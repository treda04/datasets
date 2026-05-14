"""
Live Detection Service — Kafka Consumer + ML Inference
=======================================================
Consomme windows-raw-logs, applique 4 modèles ML,
publie les alertes vers ml-alerts.
Latence cible : < 100ms par événement.
"""

import json
import time
import logging
import os
import traceback
from collections import deque, defaultdict
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable
from pythonjsonlogger import jsonlogger

# ══════════════════════════════════════════════════════════════
# CONFIGURATION — Modifier selon l'environnement
# ══════════════════════════════════════════════════════════════
KAFKA_BROKER    = "192.168.94.132:9092"
TOPIC_INPUT     = "windows-raw-logs"
TOPIC_ALERTS    = "ml-alerts"
GROUP_ID        = "ml-detection-service"
ALERT_THRESHOLD = 0.65      # Score ML minimum pour générer une alerte
BATCH_SIZE      = 50        # Événements traités par batch
WINDOW_SIZE     = 500       # Taille fenêtre glissante par host (en nb d'events)
WINDOW_MIN      = 5         # Fenêtre temporelle en minutes pour les features
RECONNECT_DELAY = 5         # Secondes avant reconnexion en cas d'échec

# Seuils par modèle pour le score composite
MODEL_WEIGHTS = {
    'siem_windows':    0.50,   # Prioritaire — aligné sur l'infra
    'lateral_movement':0.25,
    'cicids':          0.15,
    'adfa_ld':         0.10,
}

# Mapping MITRE ATT&CK basé sur le modèle dominant
MITRE_MAP = {
    'siem_windows':    ('Credential Access',  'T1003'),
    'lateral_movement':('Lateral Movement',   'T1021'),
    'cicids':          ('Discovery',          'T1046'),
    'adfa_ld':         ('Execution',          'T1059'),
}

# ══════════════════════════════════════════════════════════════
# LOGGING STRUCTURÉ JSON
# ══════════════════════════════════════════════════════════════
logger = logging.getLogger('live_detection')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# ══════════════════════════════════════════════════════════════
# CHARGEMENT DES MODÈLES
# ══════════════════════════════════════════════════════════════

def load_models():
    """Charge les 4 modèles ML et leurs artéfacts."""
    models = {}
    configs = [
        ('siem_windows',     'siem_windows/saved_models/rf_siem_model.pkl',
                             'siem_windows/saved_models/siem_scaler.pkl',
                             'siem_windows/saved_models/siem_threshold.json',
                             'siem_windows/data/feature_columns.json'),
        ('lateral_movement', 'lateral_movement/saved_models/rf_lateral_model.pkl',
                             'lateral_movement/saved_models/lateral_scaler.pkl',
                             'lateral_movement/saved_models/lateral_threshold.json',
                             'lateral_movement/data/feature_columns.json'),
        ('cicids',           'cicids2017/models/xgb_model.pkl',
                             None, None, None),
        ('adfa_ld',          'adfa_ld/models/rf_adfa_model.pkl',
                             None, None, None),
    ]

    for name, model_path, scaler_path, threshold_path, features_path in configs:
        if not os.path.exists(model_path):
            logger.warning(f"Modèle {name} introuvable : {model_path}")
            continue
        entry = {'model': joblib.load(model_path), 'threshold': 0.5,
                 'scaler': None, 'features': None}
        if scaler_path and os.path.exists(scaler_path):
            entry['scaler'] = joblib.load(scaler_path)
        if threshold_path and os.path.exists(threshold_path):
            with open(threshold_path) as f:
                thr_data = json.load(f)
            entry['threshold'] = thr_data.get('threshold', 0.5)
        if features_path and os.path.exists(features_path):
            with open(features_path) as f:
                entry['features'] = json.load(f)
        models[name] = entry
        logger.info(f"Modèle chargé : {name} (seuil={entry['threshold']:.3f})")

    return models

# ══════════════════════════════════════════════════════════════
# EXTRACTION DE FEATURES DEPUIS UN ÉVÉNEMENT WINDOWS
# ══════════════════════════════════════════════════════════════

ATTACK_EVENTIDS = {
    'brute_force':    [4625, 4771, 4776],
    'lateral_move':   [4648, 4624, 4672],
    'persistence':    [4697, 4698, 4702, 4720, 4726],
    'priv_escalation':[4728, 4732, 4756, 4738, 4672],
    'recon':          [4798, 4799, 4661],
    'execution':      [4688, 4696],
    'kerberos':       [4768, 4769, 4770, 4771, 4773],
}
ALL_MONITORED = list(set(eid for ids in ATTACK_EVENTIDS.values() for eid in ids))


class HostWindow:
    """Fenêtre glissante d'événements par host."""
    def __init__(self, maxlen=WINDOW_SIZE):
        self.events = deque(maxlen=maxlen)

    def add(self, event_id: int, timestamp: float):
        self.events.append({'event_id': event_id, 'ts': timestamp})

    def get_recent(self, minutes=WINDOW_MIN):
        cutoff = time.time() - minutes * 60
        return [e for e in self.events if e['ts'] >= cutoff]


def extract_siem_features(host_window: HostWindow, feature_cols: list) -> np.ndarray:
    """Extrait les features SIEM Windows depuis la fenêtre glissante."""
    recent = host_window.get_recent(WINDOW_MIN)
    if not recent:
        return np.zeros((1, len(feature_cols)))

    event_ids = [e['event_id'] for e in recent]
    from collections import Counter
    cnt = Counter(event_ids)
    total = len(event_ids)

    row = {'total_events': total, 'events_per_minute': total / WINDOW_MIN}

    # Comptage par EventID
    for eid in ALL_MONITORED:
        row[f'cnt_{eid}'] = cnt.get(eid, 0)

    # Scores comportementaux
    for cat, eids in ATTACK_EVENTIDS.items():
        row[f'{cat}_score'] = sum(cnt.get(e, 0) for e in eids)

    # Ratio logon failure
    successes = cnt.get(4624, 0)
    failures  = cnt.get(4625, 0) + cnt.get(4771, 0)
    row['logon_failure_ratio'] = failures / (successes + failures) if (successes + failures) > 0 else 0

    # Entropie EventIDs
    unique_cnt = len(set(event_ids))
    if unique_cnt > 1:
        from collections import Counter
        probs = np.array(list(Counter(event_ids).values())) / total
        row['entropy_eventids'] = float(-np.sum(probs * np.log2(probs + 1e-10)))
    else:
        row['entropy_eventids'] = 0.0

    row['distinct_eventids'] = unique_cnt

    # Construire le vecteur dans le bon ordre
    vec = np.array([[row.get(col, 0.0) for col in feature_cols]])
    return vec


def parse_event(raw_msg: bytes) -> dict:
    """Parse un message Kafka (JSON Winlogbeat)."""
    try:
        return json.loads(raw_msg.decode('utf-8'))
    except Exception:
        return {}


def extract_event_id(event: dict) -> int:
    """Extrait l'EventID depuis un event Winlogbeat."""
    for path in ['winlog.event_id', 'event.code', 'EventID', 'event_id']:
        parts = path.split('.')
        val = event
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                val = None
                break
        if val is not None:
            try:
                return int(val)
            except (ValueError, TypeError):
                pass
    return 0


def extract_host(event: dict) -> str:
    for key in ['host.name', 'winlog.computer_name', 'hostname', 'host']:
        parts = key.split('.')
        val = event
        for p in parts:
            if isinstance(val, dict):
                val = val.get(p)
            else:
                val = None
                break
        if val and isinstance(val, str):
            return val
    return 'UNKNOWN'


# ══════════════════════════════════════════════════════════════
# INFÉRENCE ML
# ══════════════════════════════════════════════════════════════

def run_inference(event: dict, host_window: HostWindow, models: dict) -> dict:
    """Applique les modèles disponibles et retourne les scores."""
    scores = {}

    # Modèle SIEM Windows (prioritaire)
    if 'siem_windows' in models:
        m = models['siem_windows']
        feat_cols = m['features'] or []
        if feat_cols:
            X = extract_siem_features(host_window, feat_cols)
            if m['scaler']:
                X = m['scaler'].transform(X)
            score = float(m['model'].predict_proba(X)[0, 1])
            scores['siem_windows'] = score

    # Modèles ADFA-LD et CIC-IDS : pas de features extractibles depuis
    # un event Windows brut → score neutre 0.0 (ils s'activent via leur propre pipeline)
    for name in ['adfa_ld', 'cicids']:
        if name in models:
            scores[name] = 0.0

    # Lateral Movement : features identité/auth extraites de la fenêtre Windows
    if 'lateral_movement' in models:
        m = models['lateral_movement']
        feat_cols = m['features'] or []
        if feat_cols:
            X = extract_lateral_features(host_window, feat_cols)
            if m['scaler']:
                X = m['scaler'].transform(X)
            score = float(m['model'].predict_proba(X)[0, 1])
            scores['lateral_movement'] = score
        else:
            scores['lateral_movement'] = 0.0

    return scores


def extract_lateral_features(host_window: 'HostWindow', feature_cols: list) -> np.ndarray:
    """
    Extrait les features Lateral Movement depuis la fenêtre glissante.
    Le modèle attend les mêmes EventIDs + features identité que
    lateral_movement/preprocessing/preprocess_lateral.py.

    Note : la fenêtre live ne tracke que event_id et ts (pas user/IP/logon_type),
    donc les features identité (distinct_users, network_logon_ratio, etc.)
    seront à 0. C'est dégradé mais fonctionnel — les features de comptage
    d'EventIDs restent informatives. Pour une précision maximale, étendre
    HostWindow.add() pour stocker ces champs.
    """
    from collections import Counter
    LM_EVENTIDS = {
        "logon_success":  [4624],
        "logon_failure":  [4625, 4771],
        "explicit_creds": [4648],
        "special_privs":  [4672],
        "service_create": [4697, 4698, 4702],
        "wmi":            [4104, 4103],
        "kerberos_tgs":   [4769],
        "kerberos_tgt":   [4768],
        "process_create": [4688, 1],
        "network_conn":   [3, 22],
        "remote_thread":  [8],
        "image_load":     [7],
        "registry":       [12, 13],
    }
    ALL_LM = sorted({eid for ids in LM_EVENTIDS.values() for eid in ids})

    recent = host_window.get_recent(WINDOW_MIN)
    if not recent:
        return np.zeros((1, len(feature_cols)))

    eids = [e['event_id'] for e in recent]
    cnt = Counter(eids)
    total = len(eids)

    row = {
        'total_events': total,
        'events_per_minute': total / WINDOW_MIN,
    }
    for eid in ALL_LM:
        row[f'cnt_{eid}'] = cnt.get(eid, 0)
    for cat, cat_eids in LM_EVENTIDS.items():
        row[f'{cat}_score'] = sum(cnt.get(e, 0) for e in cat_eids)

    # Features identité non disponibles en live → 0 (HostWindow ne stocke
    # actuellement pas ces champs ; à enrichir si besoin de précision max).
    row['distinct_target_users'] = 0
    row['distinct_src_users'] = 0
    row['distinct_src_ips'] = 0
    row['distinct_logon_types'] = 0
    row['network_logon_ratio'] = 0.0
    row['rdp_logon_ratio'] = 0.0

    fail = cnt.get(4625, 0) + cnt.get(4771, 0)
    succ = cnt.get(4624, 0)
    row['logon_failure_ratio'] = fail / (fail + succ) if (fail + succ) > 0 else 0

    if len(set(eids)) > 1:
        probs = np.array(list(cnt.values())) / total
        row['entropy_eventids'] = float(-np.sum(probs * np.log2(probs + 1e-10)))
    else:
        row['entropy_eventids'] = 0.0
    row['distinct_eventids'] = len(set(eids))

    return np.array([[row.get(c, 0.0) for c in feature_cols]])


def compute_composite_score(scores: dict) -> float:
    """Score composite pondéré par MODEL_WEIGHTS."""
    total_weight = sum(MODEL_WEIGHTS[k] for k in scores if k in MODEL_WEIGHTS)
    if total_weight == 0:
        return 0.0
    weighted = sum(
        scores[k] * MODEL_WEIGHTS[k]
        for k in scores if k in MODEL_WEIGHTS
    )
    return weighted / total_weight


def dominant_model(scores: dict) -> str:
    if not scores:
        return 'siem_windows'
    return max(scores, key=lambda k: scores[k] * MODEL_WEIGHTS.get(k, 1))


def build_alert(host: str, event_id: int, scores: dict, composite: float,
                host_window: HostWindow) -> dict:
    """Construit le message d'alerte JSON."""
    dom = dominant_model(scores)
    tactic, technique = MITRE_MAP.get(dom, ('Unknown', 'T0000'))
    recent = host_window.get_recent(WINDOW_MIN)
    event_ids_seen = list(set(e['event_id'] for e in recent))

    level = 'CRITICAL' if composite >= 0.85 else 'HIGH' if composite >= 0.70 else 'MEDIUM'

    return {
        'timestamp':       datetime.now(timezone.utc).isoformat(),
        'host':            host,
        'trigger_event_id': event_id,
        'ml_score':        round(composite, 4),
        'alert_level':     level,
        'model_scores':    {k: round(v, 4) for k, v in scores.items()},
        'dominant_model':  dom,
        'mitre_tactic':    tactic,
        'mitre_technique': technique,
        'event_ids_in_window': event_ids_seen,
        'window_event_count':  len(recent),
        'service':         'live-detection-v1',
    }


# ══════════════════════════════════════════════════════════════
# KAFKA — CONNEXION AVEC RETRY
# ══════════════════════════════════════════════════════════════

def create_consumer():
    """Crée le consommateur Kafka avec retry."""
    while True:
        try:
            consumer = KafkaConsumer(
                TOPIC_INPUT,
                bootstrap_servers=KAFKA_BROKER,
                group_id=GROUP_ID,
                auto_offset_reset='latest',
                enable_auto_commit=True,
                value_deserializer=lambda x: x,
                max_poll_records=BATCH_SIZE,
                consumer_timeout_ms=5000,
            )
            logger.info(f"Kafka consumer connecté : {KAFKA_BROKER} → {TOPIC_INPUT}")
            return consumer
        except NoBrokersAvailable:
            logger.warning(f"Kafka indisponible, retry dans {RECONNECT_DELAY}s...")
            time.sleep(RECONNECT_DELAY)


def create_producer():
    """Crée le producteur Kafka pour les alertes."""
    while True:
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BROKER,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                acks='all',
                retries=3,
            )
            logger.info(f"Kafka producer prêt → {TOPIC_ALERTS}")
            return producer
        except NoBrokersAvailable:
            logger.warning(f"Kafka producer indisponible, retry dans {RECONNECT_DELAY}s...")
            time.sleep(RECONNECT_DELAY)


# ══════════════════════════════════════════════════════════════
# BOUCLE PRINCIPALE
# ══════════════════════════════════════════════════════════════

def main():
    logger.info("=== LIVE DETECTION SERVICE DÉMARRÉ ===")
    logger.info(f"Seuil alerte : {ALERT_THRESHOLD} | Batch : {BATCH_SIZE} | Broker : {KAFKA_BROKER}")

    # Chargement des modèles
    models = load_models()
    if not models:
        logger.error("Aucun modèle chargé. Entraîner les modèles d'abord.")
        return

    # Fenêtres glissantes par host
    host_windows: dict = defaultdict(HostWindow)

    # Compteurs de performance
    stats = {'processed': 0, 'alerts': 0, 'errors': 0, 'start_time': time.time()}

    consumer = create_consumer()
    producer = create_producer()

    logger.info("En attente d'événements Kafka...")

    while True:
        try:
            batch = consumer.poll(timeout_ms=1000, max_records=BATCH_SIZE)
            if not batch:
                # Log stats toutes les 60s
                elapsed = time.time() - stats['start_time']
                if int(elapsed) % 60 < 2:
                    logger.info("stats", extra={
                        'processed':  stats['processed'],
                        'alerts':     stats['alerts'],
                        'errors':     stats['errors'],
                        'uptime_s':   int(elapsed),
                        'models_loaded': list(models.keys()),
                    })
                continue

            for tp, messages in batch.items():
                for msg in messages:
                    t_start = time.perf_counter()

                    try:
                        event = parse_event(msg.value)
                        if not event:
                            continue

                        event_id = extract_event_id(event)
                        host     = extract_host(event)
                        ts_now   = time.time()

                        # Mise à jour fenêtre glissante
                        host_windows[host].add(event_id, ts_now)

                        # Inférence ML
                        scores    = run_inference(event, host_windows[host], models)
                        composite = compute_composite_score(scores)

                        stats['processed'] += 1

                        # Génération d'alerte si seuil dépassé
                        if composite >= ALERT_THRESHOLD:
                            alert = build_alert(host, event_id, scores, composite,
                                                host_windows[host])
                            producer.send(TOPIC_ALERTS, value=alert)
                            stats['alerts'] += 1
                            logger.warning("ALERTE ML générée", extra={
                                'host':      host,
                                'score':     composite,
                                'level':     alert['alert_level'],
                                'technique': alert['mitre_technique'],
                            })

                        # Mesure latence
                        latency_ms = (time.perf_counter() - t_start) * 1000
                        if latency_ms > 100:
                            logger.warning(f"Latence élevée : {latency_ms:.1f}ms (host={host})")

                    except Exception as e:
                        stats['errors'] += 1
                        logger.error(f"Erreur traitement event : {e}")

            producer.flush()

        except KeyboardInterrupt:
            logger.info("Arrêt du service...")
            break
        except Exception as e:
            logger.error(f"Erreur critique : {e}\n{traceback.format_exc()}")
            logger.info(f"Reconnexion dans {RECONNECT_DELAY}s...")
            time.sleep(RECONNECT_DELAY)
            try:
                consumer.close()
            except Exception:
                pass
            consumer = create_consumer()

    consumer.close()
    producer.close()
    logger.info(f"Service arrêté. Stats finales : {stats}")


if __name__ == '__main__':
    main()
