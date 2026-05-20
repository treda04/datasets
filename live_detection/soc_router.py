"""
SOC Router — Service de detection live ML <-> ELK
===================================================

Architecture du flux :

    Windows machines (Sysmon + WEF)
            |
            v
    Winlogbeat / Filebeat
            |
            v
    Kafka topic: raw_events
            |
            v   <----- CE SCRIPT
    soc_router.py
      |- buffer par (hostname, fenetre 1 min)
      |- extraction features Windows (cnt_EID + scores composites)
      |- routing par source
      |- appel a SOCOrchestrator.predict() (4 modeles)
      |- correlation multi-modeles toutes les 60s
            |
            +---> Kafka topic: alerts          (alertes individuelles)
            +---> Kafka topic: critical_alerts (correlations multi-modeles)
                        |
                        v
                  Logstash -> Elasticsearch -> Kibana SOC Dashboard

Usage :
    python live_detection/soc_router.py

Variables d'environnement (toutes optionnelles) :
    KAFKA_BROKER       (default: localhost:9092)
    KAFKA_TOPIC_IN     (default: raw_events)
    KAFKA_TOPIC_OUT    (default: alerts)
    KAFKA_TOPIC_CRIT   (default: critical_alerts)
    MODELS_DIR         (default: models)
    WINDOW_MINUTES     (default: 1)
    CORRELATION_SECONDS(default: 300)
    LOG_LEVEL          (default: INFO)
"""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from math import log2
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

# Ajouter racine projet au sys.path pour importer src.orchestrator
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.orchestrator.soc_orchestrator import SOCOrchestrator  # noqa: E402

# kafka-python
try:
    from kafka import KafkaConsumer, KafkaProducer
    from kafka.errors import NoBrokersAvailable, KafkaError
except ImportError:
    print("[!] kafka-python n'est pas installe. Run: pip install kafka-python")
    sys.exit(1)


# ======================================================================
# CONFIGURATION (override via variables d'environnement)
# ======================================================================
KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC_IN = os.environ.get("KAFKA_TOPIC_IN", "raw_events")
KAFKA_TOPIC_OUT = os.environ.get("KAFKA_TOPIC_OUT", "alerts")
KAFKA_TOPIC_CRIT = os.environ.get("KAFKA_TOPIC_CRIT", "critical_alerts")
KAFKA_GROUP_ID = os.environ.get("KAFKA_GROUP_ID", "soc-router")

MODELS_DIR = os.environ.get("MODELS_DIR", str(PROJECT_ROOT / "models"))
WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "1"))
CORRELATION_SECONDS = int(os.environ.get("CORRELATION_SECONDS", "300"))
FLUSH_INTERVAL = int(os.environ.get("FLUSH_INTERVAL", "60"))  # secondes
RECONNECT_DELAY = int(os.environ.get("RECONNECT_DELAY", "5"))

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

# ======================================================================
# LOGGING
# ======================================================================
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=LOG_LEVEL,
)
LOG = logging.getLogger("soc_router")


# ======================================================================
# FEATURE EXTRACTION (alignee sur siem_windows/pipeline/io_utils.py)
# ======================================================================
TARGET_EIDS = [
    "1", "3", "7", "8", "10", "11", "12", "13", "22",
    "4103", "4104",
    "4624", "4625", "4648", "4672", "4688",
    "4697", "4698", "4702",
    "4768", "4769", "4771", "4776",
]

RX_PS_ENC = re.compile(r"\s-e(?:nc|c|ncoded\w*)?\s")
RX_PS_DL = re.compile(r"downloadstring|iex\s*\(|invoke-expression|downloadfile")
RX_REG_RUN = re.compile(r"\\(?:run|runonce)\\")
SYSTEM32_PREFIXES = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")


def _entropy(counts: np.ndarray) -> float:
    total = counts.sum()
    if total <= 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())


def compute_window_features(events: list[dict]) -> dict:
    """Calcul des 33 features pour une fenetre de N events Windows.

    Input : liste de dicts events (sous forme deja parsee)
    Output : dict {feature_name: value} pret a etre vectorise par
             l'orchestrateur (model siem_windows v3).
    """
    eids = [str(e.get("EventID", "")) for e in events]
    counts = pd.Series(eids).value_counts()
    total = len(events)

    feat = {
        "total_events": float(total),
        "events_per_minute": float(total),  # window = 1 min
        "distinct_eventids": float(counts.shape[0]),
        "entropy_eventids": _entropy(counts.values),
    }
    for eid in TARGET_EIDS:
        feat[f"cnt_{eid}"] = float(counts.get(eid, 0))

    # Scores composites
    feat["brute_force_score"] = (
        feat["cnt_4625"] + feat.get("cnt_4771", 0) + feat.get("cnt_4776", 0)
    )
    feat["lateral_move_score"] = (
        feat["cnt_4648"] + feat["cnt_4624"] + feat["cnt_4672"]
    )
    feat["persistence_score"] = (
        feat["cnt_4697"] + feat["cnt_4698"] + feat["cnt_4702"]
    )
    feat["execution_score"] = (
        feat["cnt_4688"] + feat["cnt_1"] + feat["cnt_4104"]
    )
    feat["kerberos_score"] = (
        feat["cnt_4768"] + feat["cnt_4769"] + feat["cnt_4771"]
    )
    tot_logon = max(1.0, feat["cnt_4624"] + feat["cnt_4625"])
    feat["logon_failure_ratio"] = feat["cnt_4625"] / tot_logon

    return feat


# ======================================================================
# WINDOW BUFFER (par hostname, glissant par minute)
# ======================================================================
class WindowBuffer:
    """Buffer d'events par hostname, decoupe en fenetres temporelles.

    A chaque flush() retourne la liste des fenetres COMPLETES (celles dont
    la minute est derriere maintenant - WINDOW_MINUTES).
    """

    def __init__(self, window_minutes: int = 1):
        self.window_minutes = window_minutes
        # {hostname: {minute_key: [event, event, ...]}}
        self.buffers: dict[str, dict[str, list]] = defaultdict(
            lambda: defaultdict(list)
        )

    @staticmethod
    def _minute_key(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y%m%d%H%M")

    def add(self, event: dict):
        host = event.get("hostname") or event.get("Hostname") or "UNKNOWN"
        host = str(host).split(".")[0].upper()
        ts = event.get("timestamp")
        if ts is None:
            return
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except Exception:
                return
        key = self._minute_key(ts)
        self.buffers[host][key].append({**event, "_ts": ts})

    def flush_complete_windows(self) -> list[tuple[str, str, list]]:
        """Retourne et purge les fenetres dont la minute est completement passee."""
        now = time.time()
        cutoff_key = self._minute_key(now - self.window_minutes * 60)
        complete = []
        for host, by_minute in list(self.buffers.items()):
            for minute_key in sorted(list(by_minute.keys())):
                if minute_key <= cutoff_key:
                    events = by_minute.pop(minute_key)
                    if len(events) >= 5:  # min 5 events pour eviter le bruit
                        complete.append((host, minute_key, events))
            if not by_minute:
                self.buffers.pop(host, None)
        return complete


# ======================================================================
# CORRELATION BUFFER
# ======================================================================
class CorrelationBuffer:
    """Buffer d'alertes individuelles pour correlation multi-modeles."""

    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self.alerts: deque[dict] = deque()

    def add(self, alert: dict):
        self.alerts.append(alert)
        self._purge()

    def _purge(self):
        now = time.time()
        while self.alerts and (now - self.alerts[0].get("timestamp", now)) > self.window:
            self.alerts.popleft()

    def snapshot(self) -> list[dict]:
        self._purge()
        return list(self.alerts)


# ======================================================================
# KAFKA CONSUMER / PRODUCER
# ======================================================================
def make_consumer() -> KafkaConsumer:
    """Cree un consumer Kafka avec reconnexion automatique."""
    while True:
        try:
            consumer = KafkaConsumer(
                KAFKA_TOPIC_IN,
                bootstrap_servers=[KAFKA_BROKER],
                group_id=KAFKA_GROUP_ID,
                auto_offset_reset="latest",
                enable_auto_commit=True,
                value_deserializer=lambda v: json.loads(v.decode("utf-8")),
                consumer_timeout_ms=1000,
            )
            LOG.info("Kafka consumer connecte : %s topic=%s",
                     KAFKA_BROKER, KAFKA_TOPIC_IN)
            return consumer
        except NoBrokersAvailable:
            LOG.warning("Kafka broker indisponible (%s). Retry dans %ds...",
                        KAFKA_BROKER, RECONNECT_DELAY)
            time.sleep(RECONNECT_DELAY)


def make_producer() -> KafkaProducer:
    """Cree un producer Kafka."""
    while True:
        try:
            producer = KafkaProducer(
                bootstrap_servers=[KAFKA_BROKER],
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                acks=1,
                retries=3,
            )
            LOG.info("Kafka producer connecte : %s", KAFKA_BROKER)
            return producer
        except NoBrokersAvailable:
            LOG.warning("Kafka broker indisponible. Retry dans %ds...", RECONNECT_DELAY)
            time.sleep(RECONNECT_DELAY)


# ======================================================================
# EVENT NORMALIZATION
# ======================================================================
def normalize_winlogbeat_event(raw: dict) -> dict | None:
    """Convertit un event Winlogbeat -> format interne.

    Winlogbeat envoie typiquement :
      {
        "@timestamp": "2026-05-20T...",
        "winlog": { "event_id": 4624, "channel": "Security",
                    "computer_name": "DC01", "event_data": {...} },
        "message": "..."
      }
    """
    try:
        winlog = raw.get("winlog", {})
        event_id = winlog.get("event_id") or raw.get("EventID")
        if event_id is None:
            return None

        ts_iso = raw.get("@timestamp")
        if ts_iso:
            ts = datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).timestamp()
        else:
            ts = time.time()

        hostname = (winlog.get("computer_name") or
                    raw.get("Hostname") or
                    raw.get("host", {}).get("hostname") or
                    "UNKNOWN")
        hostname = str(hostname).split(".")[0].upper()

        channel = winlog.get("channel") or raw.get("Channel") or ""

        # Champs utiles pour les features et le labelling
        event_data = winlog.get("event_data", {}) or {}
        return {
            "EventID": str(event_id),
            "Channel": str(channel).casefold(),
            "hostname": hostname,
            "timestamp": ts,
            "CommandLine": event_data.get("CommandLine") or raw.get("CommandLine") or "",
            "ScriptBlockText": event_data.get("ScriptBlockText")
                or raw.get("ScriptBlockText") or "",
            "TargetImage": event_data.get("TargetImage")
                or raw.get("TargetImage") or "",
            "TargetObject": event_data.get("TargetObject")
                or raw.get("TargetObject") or "",
            "SourceImage": event_data.get("SourceImage")
                or raw.get("SourceImage") or "",
            "LogonType": event_data.get("LogonType") or raw.get("LogonType"),
        }
    except Exception as e:
        LOG.debug("Event Winlogbeat invalide : %s", e)
        return None


# ======================================================================
# MAIN ROUTER
# ======================================================================
class SOCRouterService:

    def __init__(self):
        LOG.info("=== SOC Router Service - demarrage ===")
        LOG.info("Kafka broker        : %s", KAFKA_BROKER)
        LOG.info("Kafka topic IN      : %s", KAFKA_TOPIC_IN)
        LOG.info("Kafka topic OUT     : %s", KAFKA_TOPIC_OUT)
        LOG.info("Kafka topic CRIT    : %s", KAFKA_TOPIC_CRIT)
        LOG.info("Models dir          : %s", MODELS_DIR)
        LOG.info("Window minutes      : %d", WINDOW_MINUTES)
        LOG.info("Correlation seconds : %d", CORRELATION_SECONDS)

        # Charger les modeles
        if not Path(MODELS_DIR).exists():
            LOG.error("MODELS_DIR introuvable : %s", MODELS_DIR)
            LOG.error("Lance d'abord : python scripts/setup_models_dir.py")
            sys.exit(1)

        self.orch = SOCOrchestrator(models_dir=MODELS_DIR)
        LOG.info("Modeles charges : %s", sorted(self.orch.bundles.keys()))

        # Kafka
        self.consumer = make_consumer()
        self.producer = make_producer()

        # Buffers
        self.window_buf = WindowBuffer(window_minutes=WINDOW_MINUTES)
        self.corr_buf = CorrelationBuffer(window_seconds=CORRELATION_SECONDS)

        # Stats
        self.stats = {
            "events_in": 0,
            "events_normalized": 0,
            "windows_evaluated": 0,
            "alerts_emitted": 0,
            "critical_emitted": 0,
            "last_flush": time.time(),
            "start_time": time.time(),
        }

        self.running = True
        signal.signal(signal.SIGINT, self._stop)
        signal.signal(signal.SIGTERM, self._stop)

    def _stop(self, *_):
        LOG.info("Signal recu, arret du service...")
        self.running = False

    # ------------------------------------------------------------------
    # Coeur de la boucle
    # ------------------------------------------------------------------
    def run(self):
        LOG.info("Service pret. En attente d'events sur %s...", KAFKA_TOPIC_IN)
        while self.running:
            try:
                self._consume_loop_once()
                self._maybe_flush()
            except KafkaError as e:
                LOG.error("Erreur Kafka : %s. Reconnexion dans %ds...", e, RECONNECT_DELAY)
                time.sleep(RECONNECT_DELAY)
                self.consumer = make_consumer()
                self.producer = make_producer()
            except Exception as e:
                LOG.exception("Erreur inattendue : %s", e)
                time.sleep(1)

        self._flush_force()
        self._log_stats()
        self.consumer.close()
        self.producer.flush()
        self.producer.close()
        LOG.info("Service arrete proprement.")

    def _consume_loop_once(self):
        """Consomme les messages disponibles puis sort (timeout 1s consumer)."""
        for msg in self.consumer:
            self.stats["events_in"] += 1
            raw = msg.value
            normalized = normalize_winlogbeat_event(raw)
            if normalized is None:
                continue
            self.stats["events_normalized"] += 1
            self.window_buf.add(normalized)

    def _maybe_flush(self):
        """Flush les fenetres completes toutes les FLUSH_INTERVAL secondes."""
        now = time.time()
        if now - self.stats["last_flush"] < FLUSH_INTERVAL:
            return
        self._flush_force()

    def _flush_force(self):
        windows = self.window_buf.flush_complete_windows()
        for host, minute_key, events in windows:
            self._evaluate_window(host, minute_key, events)

        # Apres avoir traite les fenetres, on calcule les correlations
        self._compute_correlations()
        self.stats["last_flush"] = time.time()
        self._log_stats()

    # ------------------------------------------------------------------
    # Evaluation d'une fenetre Windows -> appel modele SIEM
    # ------------------------------------------------------------------
    def _evaluate_window(self, host: str, minute_key: str, events: list[dict]):
        self.stats["windows_evaluated"] += 1
        features = compute_window_features(events)

        # Construction event au format orchestrateur
        first_ts = min(e["_ts"] for e in events)
        synth_event = {
            "event_id": f"{host}-{minute_key}",
            "source": "windows_event",
            "host": host,
            "timestamp": first_ts,
            "features": features,
        }
        try:
            pred = self.orch.predict(synth_event)
        except Exception as e:
            LOG.exception("predict() a echoue sur fenetre %s/%s : %s",
                          host, minute_key, e)
            return

        # On envoie TOUTES les predictions (pas seulement attaques) vers Kibana
        # pour avoir la timeline complete d'activite
        full_alert = {
            **pred,
            "n_events": len(events),
            "minute_key": minute_key,
            "alert_time_utc": datetime.now(timezone.utc).isoformat(),
        }
        if pred.get("is_attack"):
            self.stats["alerts_emitted"] += 1
            full_alert["severity"] = "WARNING"
            LOG.info("ALERTE host=%s model=%s score=%.3f mitre=%s",
                     host, pred.get("model"), pred.get("score") or 0,
                     pred.get("mitre_technique"))
            self.corr_buf.add(pred)
        else:
            full_alert["severity"] = "INFO"

        self.producer.send(KAFKA_TOPIC_OUT, full_alert)

    # ------------------------------------------------------------------
    # Correlations multi-modeles
    # ------------------------------------------------------------------
    def _compute_correlations(self):
        snapshot = self.corr_buf.snapshot()
        if len(snapshot) < 2:
            return
        criticals = self.orch.correlate(snapshot, window_seconds=CORRELATION_SECONDS)
        for c in criticals:
            self.stats["critical_emitted"] += 1
            c["detected_at_utc"] = datetime.now(timezone.utc).isoformat()
            LOG.warning("CRITICAL host=%s models=%s mitre=%s",
                        c.get("host"), c.get("models_triggered"),
                        c.get("mitre_techniques"))
            self.producer.send(KAFKA_TOPIC_CRIT, c)

    # ------------------------------------------------------------------
    def _log_stats(self):
        uptime = int(time.time() - self.stats["start_time"])
        LOG.info("STATS uptime=%ds in=%d norm=%d windows=%d alerts=%d crit=%d",
                 uptime, self.stats["events_in"], self.stats["events_normalized"],
                 self.stats["windows_evaluated"], self.stats["alerts_emitted"],
                 self.stats["critical_emitted"])


# ======================================================================
# ENTRY POINT
# ======================================================================
def main():
    service = SOCRouterService()
    service.run()


if __name__ == "__main__":
    main()
