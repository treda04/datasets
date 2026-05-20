"""
SOC Orchestrator — orchestre les 4 modèles supervisés en un seul système.

Contrat des événements en entrée (dict) :
    {
        "event_id"  : str,
        "source"    : "netflow" | "linux_syscall" | "windows_event" | "identity_event",
        "host"      : str,
        "timestamp" : float (unix epoch),
        "features"  : {nom_feature: valeur, ...}     # déjà extraits par le collector
    }

Sortie de predict() :
    {
        "event_id", "host", "timestamp", "model",
        "score", "is_attack", "mitre_technique" (str | None)
    }

Sortie de correlate() :
    Liste d'alertes corrélées (>=2 modèles distincts sur le même host
    dans une fenêtre temporelle), niveau "CRITICAL".

Contraintes (PFE) :
  - Tous les modèles supervisés (RF + Calibrated, XGBoost).
  - random_state=42 fixé en amont à l'entraînement, non modifié ici.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

import joblib
import numpy as np

from .mitre_mapping import event_id_to_technique, techniques_from_features

LOG = logging.getLogger("soc_orchestrator")

# Routing source -> clé modèle interne
# NB : 3 modèles supervisés retenus pour le PFE (lateral_movement écarté
# pour cause de dataset insuffisant — voir RAPPORT_ENCADRANT_V2.md)
SOURCE_TO_MODEL = {
    "netflow":        "cicids",
    "linux_syscall":  "adfa",
    "windows_event":  "siem",
}

# Seuils par défaut si threshold.json absent
DEFAULT_THRESHOLDS = {
    "cicids":  0.50,
    "adfa":    0.507,
    "siem":    0.507,
}


@dataclass
class ModelBundle:
    """Modèle + métadonnées chargés depuis disque."""
    key: str
    model: Any
    feature_columns: list[str] | None = None
    scaler: Any | None = None
    vectorizer: Any | None = None
    label_encoder: Any | None = None  # pour les modèles multi-classes
    threshold: float = 0.5
    is_multiclass: bool = False
    classes: list[Any] = field(default_factory=list)  # peut être int ou str
    class_names: list[str] = field(default_factory=list)  # str (lisible)


def _load_model_bundle(key: str, model_dir: Path) -> ModelBundle | None:
    """Charge un bundle depuis model_dir/key/, ou None si répertoire absent."""
    sub = model_dir / key
    if not sub.exists():
        LOG.warning("Répertoire absent : %s", sub)
        return None

    # Le modèle : on accepte plusieurs noms (compatibilité historique)
    candidates = ["model.joblib", "model.pkl",
                  f"rf_{key}_model.pkl", f"xgb_model_v2.pkl",
                  f"rf_{key}_model_v2.pkl", f"xgb_model.pkl"]
    model_path = next((sub / c for c in candidates if (sub / c).exists()), None)
    if model_path is None:
        LOG.warning("Aucun modèle trouvé dans %s", sub)
        return None
    model = joblib.load(model_path)

    # Scaler optionnel
    scaler = None
    for c in ["scaler.joblib", "scaler.pkl",
              f"{key}_scaler.pkl", "cicids_scaler.pkl"]:
        if (sub / c).exists():
            scaler = joblib.load(sub / c)
            break

    # Vectorizer optionnel (ADFA)
    vectorizer = None
    for c in ["vectorizer.joblib", "vectorizer.pkl",
              f"{key}_vectorizer.pkl"]:
        if (sub / c).exists():
            vectorizer = joblib.load(sub / c)
            break

    # Feature columns
    feature_columns = None
    for c in ["features.json", "feature_columns.json"]:
        if (sub / c).exists():
            feature_columns = json.load(open(sub / c, encoding="utf-8"))
            break

    # Threshold
    threshold = DEFAULT_THRESHOLDS.get(key, 0.5)
    for c in ["threshold.json", f"{key}_threshold.json", "adfa_threshold.json"]:
        if (sub / c).exists():
            data = json.load(open(sub / c, encoding="utf-8"))
            threshold = float(data.get("threshold", threshold))
            break

    # Label encoder optionnel (mapping int -> nom de classe pour multi-classes)
    label_encoder = None
    for c in ["label_encoder.pkl", "label_encoder.joblib",
              f"{key}_label_encoder.pkl"]:
        if (sub / c).exists():
            label_encoder = joblib.load(sub / c)
            break

    # Classes (multi-classe)
    is_multiclass = False
    classes = []
    class_names = []
    if hasattr(model, "classes_"):
        try:
            n_classes = len(model.classes_)
            if n_classes > 2:
                is_multiclass = True
                classes = list(model.classes_)
                if label_encoder is not None:
                    class_names = [str(label_encoder.classes_[int(c)])
                                   for c in classes]
                else:
                    class_names = [str(c) for c in classes]
        except Exception:
            pass

    return ModelBundle(
        key=key, model=model, feature_columns=feature_columns,
        scaler=scaler, vectorizer=vectorizer, label_encoder=label_encoder,
        threshold=threshold, is_multiclass=is_multiclass,
        classes=classes, class_names=class_names,
    )


# ─────────────────────────────────────────────────────────────────────────
# Orchestrateur principal
# ─────────────────────────────────────────────────────────────────────────
class SOCOrchestrator:
    """Orchestre 4 modèles supervisés : route, prédit, corrèle."""

    def __init__(self, models_dir: str | Path):
        self.models_dir = Path(models_dir)
        if not self.models_dir.exists():
            raise FileNotFoundError(f"models_dir introuvable : {models_dir}")

        self.bundles: dict[str, ModelBundle] = {}
        for key in ["cicids", "adfa", "siem"]:
            b = _load_model_bundle(key, self.models_dir)
            if b is not None:
                self.bundles[key] = b
                LOG.info("Modèle chargé : %s (threshold=%.3f)", key, b.threshold)
            else:
                LOG.warning("Modèle %s manquant — predict() le signalera", key)

        if not self.bundles:
            raise RuntimeError("Aucun modèle chargé.")

    # ───────── Routing ─────────
    def route(self, event: dict) -> str:
        """Source -> clé modèle. Lève ValueError si source inconnue."""
        source = event.get("source")
        if source not in SOURCE_TO_MODEL:
            raise ValueError(f"Source inconnue : {source!r}. "
                             f"Attendu : {list(SOURCE_TO_MODEL)}")
        return SOURCE_TO_MODEL[source]

    # ───────── Préparation des features ─────────
    def _vectorize(self, bundle: ModelBundle, event: dict) -> np.ndarray:
        """Transforme features dict -> ndarray (1, n_features)."""
        features = event.get("features", {})
        if bundle.feature_columns:
            # Ordre exact attendu par le modèle
            vec = np.array(
                [[float(features.get(c, 0.0)) for c in bundle.feature_columns]],
                dtype=np.float32,
            )
        elif bundle.vectorizer is not None:
            # ADFA : la "feature" est une séquence de syscalls
            seq = event.get("syscall_sequence", "")
            vec = bundle.vectorizer.transform([seq]).toarray().astype(np.float32)
        else:
            # Fallback : prend les valeurs telles quelles
            vec = np.array([list(features.values())], dtype=np.float32)

        if bundle.scaler is not None:
            vec = bundle.scaler.transform(vec)
        return vec

    def _attack_score(self, bundle: ModelBundle, X: np.ndarray) -> tuple[float, str | None, bool]:
        """Retourne (score, top_class, is_attack_multiclass).
        Pour le multi-classe : is_attack = (classe top != normale) — la décision
        ne dépend pas du threshold (qui ne s'applique qu'au binaire)."""
        proba = bundle.model.predict_proba(X)[0]
        if bundle.is_multiclass:
            names = bundle.class_names or [str(c) for c in bundle.classes]
            idx_normal = None
            for i, n in enumerate(names):
                if "normal" in n.lower():
                    idx_normal = i
                    break
            top_idx = int(np.argmax(proba))
            top_class = names[top_idx]
            score = float(proba[top_idx])
            is_attack_mc = (idx_normal is not None and top_idx != idx_normal)
            return score, top_class, is_attack_mc
        # Binaire : proba classe 1
        return float(proba[-1]), None, None

    # ───────── Prediction ─────────
    def predict(self, event: dict) -> dict:
        """Route, preprocess, predict_proba. Retourne dict standardisé."""
        key = self.route(event)
        bundle = self.bundles.get(key)
        if bundle is None:
            return {
                "event_id": event.get("event_id"),
                "host": event.get("host"),
                "timestamp": event.get("timestamp"),
                "model": key,
                "score": None,
                "is_attack": False,
                "mitre_technique": None,
                "error": f"model_not_loaded:{key}",
            }

        X = self._vectorize(bundle, event)
        score, top_class, is_attack_mc = self._attack_score(bundle, X)
        if is_attack_mc is not None:
            # Multi-classe : décision par argmax (pas de threshold binaire)
            is_attack = bool(is_attack_mc)
        else:
            # Binaire : seuil calibré
            is_attack = bool(score >= bundle.threshold)

        # Technique MITRE
        mitre = None
        # Si l'event porte un EventID explicite (Windows raw)
        eid = event.get("event_id_windows") or (event.get("features", {}).get("event_id"))
        if eid is not None:
            tech = event_id_to_technique(eid)
            if tech is not None:
                mitre = tech[0]
        # Sinon : déduit depuis features cnt_*
        if mitre is None:
            techs = techniques_from_features(event.get("features", {}))
            if techs:
                mitre = techs[0]
        # Sinon : classe multi-classe -> technique connue
        if mitre is None and top_class:
            mapping = {
                "Brute Force": "T1110", "Port Scanning": "T1046",
                "Web Attacks": "T1190", "DoS": "T1499",
            }
            mitre = mapping.get(top_class)

        return {
            "event_id": event.get("event_id"),
            "host": event.get("host"),
            "timestamp": event.get("timestamp"),
            "model": key,
            "score": round(score, 4),
            "is_attack": is_attack,
            "mitre_technique": mitre,
            "top_class": top_class,
        }

    # ───────── Corrélation multi-modèles ─────────
    def correlate(self, alerts: list[dict], window_seconds: float = 300) -> list[dict]:
        """Escalade en CRITICAL si >= 2 modèles distincts sur le MÊME host
        dans une fenêtre glissante de window_seconds."""
        # Conserver uniquement les alertes is_attack=True avec timestamp valide
        valid = [a for a in alerts
                 if a.get("is_attack") and a.get("timestamp") is not None
                 and a.get("host") is not None]
        if not valid:
            return []

        # Indexer par host
        by_host: dict[str, list[dict]] = defaultdict(list)
        for a in valid:
            by_host[a["host"]].append(a)

        critical_alerts = []
        for host, host_alerts in by_host.items():
            host_alerts.sort(key=lambda a: a["timestamp"])
            buffer: deque[dict] = deque()
            for a in host_alerts:
                # Purge les anciennes alertes hors fenêtre
                while buffer and a["timestamp"] - buffer[0]["timestamp"] > window_seconds:
                    buffer.popleft()
                buffer.append(a)
                models_in_window = {x["model"] for x in buffer}
                if len(models_in_window) >= 2:
                    mitre_set = sorted({x["mitre_technique"] for x in buffer
                                         if x.get("mitre_technique")})
                    critical_alerts.append({
                        "host": host,
                        "window_start": buffer[0]["timestamp"],
                        "window_end": a["timestamp"],
                        "models_triggered": sorted(models_in_window),
                        "mitre_techniques": mitre_set,
                        "severity": "CRITICAL",
                        "n_alerts": len(buffer),
                        "max_score": max(x["score"] or 0 for x in buffer),
                    })
        return critical_alerts

    # ───────── Stream ─────────
    def run_stream(
        self,
        event_stream: Iterable[dict],
        output_path: str | Path,
        correlation_window_seconds: float = 300,
    ) -> dict:
        """Itère sur le stream, prédit, sort un log JSONL.
        Retourne un résumé (compte d'alertes, corrélations détectées)."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        all_preds = []
        with output_path.open("w", encoding="utf-8") as fh:
            for ev in event_stream:
                try:
                    pred = self.predict(ev)
                except Exception as e:
                    LOG.exception("predict failed : %s", e)
                    continue
                fh.write(json.dumps(pred, ensure_ascii=False) + "\n")
                all_preds.append(pred)

        criticals = self.correlate(all_preds, window_seconds=correlation_window_seconds)
        # Append des corrélations à la fin du log
        with output_path.open("a", encoding="utf-8") as fh:
            for c in criticals:
                fh.write(json.dumps({"type": "correlated", **c},
                                      ensure_ascii=False) + "\n")

        return {
            "n_events": len(all_preds),
            "n_attacks": sum(1 for p in all_preds if p["is_attack"]),
            "n_critical_correlations": len(criticals),
            "output_file": str(output_path),
        }
