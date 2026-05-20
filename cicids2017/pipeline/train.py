"""Étape 2/3 du pipeline CIC-IDS-2017 — Entraînement.

Charge les données prétraitées, fait une CV 5-fold stratifiée pour diagnostic,
puis entraîne le RandomForest final sur tout le train. Sauvegarde le modèle
+ les métriques CV.

Usage :
    python pipeline/train.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (  # noqa: E402
    CV_FOLDS, MODELS_DIR, PROCESSED_DIR, RANDOM_STATE,
    RF_CLASS_WEIGHT, RF_MAX_DEPTH, RF_MIN_SAMPLES_LEAF, RF_N_ESTIMATORS,
)


def build_rf() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_depth=RF_MAX_DEPTH,
        min_samples_leaf=RF_MIN_SAMPLES_LEAF,
        class_weight=RF_CLASS_WEIGHT,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )


def main() -> None:
    print("=" * 60)
    print("ÉTAPE 2/3 — Training CIC-IDS-2017")
    print("=" * 60)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Charger les données prétraitées ---
    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    y_train = np.load(PROCESSED_DIR / "y_train.npy", allow_pickle=True)
    print(f"[load] X_train={X_train.shape}")
    print(f"[load] classes={dict(zip(*np.unique(y_train, return_counts=True)))}")

    # --- 2. CV 5-fold stratifiée ---
    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    rf_diag = build_rf()
    cv_f1_macro = cross_val_score(rf_diag, X_train, y_train, cv=skf,
                                  scoring="f1_macro", n_jobs=-1)
    print(f"[cv] F1 macro : mean={cv_f1_macro.mean():.4f}  std={cv_f1_macro.std():.4f}")
    print(f"[cv] folds : {[round(x, 4) for x in cv_f1_macro]}")

    # --- 3. Entraînement final ---
    model = build_rf()
    model.fit(X_train, y_train)
    print("[fit] modèle final entraîné")

    # --- 4. Sauvegarde ---
    joblib.dump(model, MODELS_DIR / "model.pkl")

    manifest = {
        "model_version": "v1_final",
        "random_state": RANDOM_STATE,
        "rf_params": {
            "n_estimators": RF_N_ESTIMATORS,
            "max_depth": RF_MAX_DEPTH,
            "min_samples_leaf": RF_MIN_SAMPLES_LEAF,
            "class_weight": RF_CLASS_WEIGHT,
        },
        "cv_metrics": {
            "f1_macro_mean": float(cv_f1_macro.mean()),
            "f1_macro_std": float(cv_f1_macro.std()),
            "f1_macro_folds": [float(x) for x in cv_f1_macro],
        },
        "n_train_samples": int(len(X_train)),
        "classes": sorted(np.unique(y_train).tolist()),
    }
    (MODELS_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\nArtefacts dans {MODELS_DIR}/ :")
    for f in sorted(MODELS_DIR.iterdir()):
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
