"""Étape 2/3 du pipeline ADFA-LD — Entraînement.

Charge les données prétraitées (data/processed/), entraîne un Random Forest
calibré, calcule le seuil de décision optimal (max F2 sur CV GroupKFold du
train, sans toucher au test), et sauvegarde le tout dans saved_models/v2_final/.

Usage :
    python pipeline/train.py

Pré-requis :
    avoir exécuté preprocess.py au préalable.

Sorties :
    saved_models/v2_final/model.pkl              CalibratedClassifierCV fitté
    saved_models/v2_final/manifest.json          hyperparams + seuil + métriques CV
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, fbeta_score, precision_score, recall_score
from sklearn.model_selection import GroupKFold, cross_val_predict, cross_val_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (  # noqa: E402
    CALIB_CV, CALIB_METHOD, CV_FOLDS, MODELS_DIR, PROCESSED_DIR, RANDOM_STATE,
    RF_MAX_DEPTH, RF_MIN_SAMPLES_LEAF, RF_N_ESTIMATORS,
)


def build_rf() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_depth=RF_MAX_DEPTH,
        min_samples_leaf=RF_MIN_SAMPLES_LEAF,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )


def build_calibrated(rf: RandomForestClassifier) -> CalibratedClassifierCV:
    return CalibratedClassifierCV(rf, method=CALIB_METHOD, cv=CALIB_CV)


def main() -> None:
    print("=" * 60)
    print("ÉTAPE 2/3 — Training")
    print("=" * 60)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Charger les données prétraitées ---
    X_train = sp.load_npz(PROCESSED_DIR / "X_train.npz")
    y_train_df = pd.read_csv(PROCESSED_DIR / "y_train.csv")
    y_train = y_train_df["label"].values
    groups_train = y_train_df["scenario"].values
    print(f"[load] X_train={X_train.shape}, attaques={int(y_train.sum())}")

    # --- 2. CV pour diagnostic d'overfitting ---
    gkf = GroupKFold(n_splits=CV_FOLDS)
    rf_diagnostic = build_rf()
    cv_f1 = cross_val_score(rf_diagnostic, X_train, y_train,
                            groups=groups_train, cv=gkf,
                            scoring="f1", n_jobs=-1)
    cv_auc = cross_val_score(rf_diagnostic, X_train, y_train,
                             groups=groups_train, cv=gkf,
                             scoring="roc_auc", n_jobs=-1)
    print(f"[cv] F1  : mean={cv_f1.mean():.4f}  std={cv_f1.std():.4f}")
    print(f"[cv] AUC : mean={cv_auc.mean():.4f}  std={cv_auc.std():.4f}")

    # --- 3. Tuning du seuil sur cross_val_predict (zéro leakage du test) ---
    model_for_cv = build_calibrated(build_rf())
    y_train_proba_cv = cross_val_predict(
        model_for_cv, X_train, y_train,
        groups=groups_train, cv=gkf,
        method="predict_proba", n_jobs=-1,
    )[:, 1]

    thresholds = np.arange(0.05, 0.95, 0.01)
    scores = []
    for thr in thresholds:
        y_pred = (y_train_proba_cv >= thr).astype(int)
        scores.append({
            "threshold": float(thr),
            "precision": precision_score(y_train, y_pred, zero_division=0),
            "recall": recall_score(y_train, y_pred, zero_division=0),
            "f1": f1_score(y_train, y_pred, zero_division=0),
            "f2": fbeta_score(y_train, y_pred, beta=2, zero_division=0),
        })

    scores_df = pd.DataFrame(scores)
    best = scores_df.loc[scores_df["f2"].idxmax()]
    best_threshold = float(best["threshold"])
    print(f"[threshold] seuil optimal (max F2 CV) = {best_threshold:.2f}")
    print(f"[threshold] precision CV={best['precision']:.4f} "
          f"recall CV={best['recall']:.4f} F2 CV={best['f2']:.4f}")

    # --- 4. Entraînement final sur tout le train ---
    model = build_calibrated(build_rf())
    model.fit(X_train, y_train)
    print("[fit] modèle final entraîné")

    # --- 5. Sauvegarde ---
    joblib.dump(model, MODELS_DIR / "model.pkl")

    manifest = {
        "model_version": "v2_final",
        "random_state": RANDOM_STATE,
        "rf_params": {
            "n_estimators": RF_N_ESTIMATORS,
            "max_depth": RF_MAX_DEPTH,
            "min_samples_leaf": RF_MIN_SAMPLES_LEAF,
            "class_weight": "balanced",
        },
        "calibration": {"method": CALIB_METHOD, "cv": CALIB_CV},
        "cv_metrics": {
            "f1_mean": float(cv_f1.mean()), "f1_std": float(cv_f1.std()),
            "f1_folds": [float(x) for x in cv_f1],
            "auc_mean": float(cv_auc.mean()), "auc_std": float(cv_auc.std()),
        },
        "decision_threshold": best_threshold,
        "threshold_choice_rule":
            "argmax F2 sur cross_val_predict probas du train (GroupKFold cv=5)",
    }
    (MODELS_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8",
    )
    scores_df.to_csv(MODELS_DIR / "threshold_scan.csv", index=False)

    print(f"\nArtefacts écrits dans {MODELS_DIR}/ :")
    for f in sorted(MODELS_DIR.iterdir()):
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
