"""Étape 2/3 du pipeline : load -> CV -> fit RF -> tuning seuil -> save model + manifest.

Usage :
    python pipeline/train.py

Produit :
    saved_models/v1_final/model.pkl
    saved_models/v1_final/scaler.pkl (copie depuis data/processed)
    saved_models/v1_final/feature_names.json
    saved_models/v1_final/manifest.json
    saved_models/v1_final/threshold_scan.csv
"""
from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (
    StratifiedKFold, cross_val_predict, cross_val_score,
)
from sklearn.metrics import (
    f1_score, fbeta_score, precision_score, recall_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (  # noqa: E402
    CV_FOLDS, DECISION_THRESHOLD_DEFAULT, MODELS_DIR, PROCESSED_DIR,
    RANDOM_STATE, RF_PARAMS,
)


def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    t0 = datetime.now(timezone.utc)
    print(f"[train] start utc={t0.isoformat()}")

    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    y_train = np.load(PROCESSED_DIR / "y_train.npy")
    feature_names = json.loads((PROCESSED_DIR / "feature_names.json").read_text())
    print(f"[train] loaded X_train={X_train.shape} | positives={int(y_train.sum())}")

    rf = RandomForestClassifier(**RF_PARAMS)
    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)

    print(f"[train] CV {CV_FOLDS}-fold stratifiée ...")
    cv_f1 = cross_val_score(rf, X_train, y_train, cv=skf, scoring="f1", n_jobs=-1)
    cv_auc = cross_val_score(rf, X_train, y_train, cv=skf, scoring="roc_auc", n_jobs=-1)
    print(f"[train] CV F1  mean={cv_f1.mean():.4f}  std={cv_f1.std():.4f}")
    print(f"[train] CV AUC mean={cv_auc.mean():.4f}  std={cv_auc.std():.4f}")

    print("[train] tuning seuil sur CV-train (max F2) ...")
    y_train_proba = cross_val_predict(
        rf, X_train, y_train, cv=skf, method="predict_proba", n_jobs=-1
    )[:, 1]
    thresholds = np.linspace(0.05, 0.95, 19)
    rows = []
    best_t, best_f2 = DECISION_THRESHOLD_DEFAULT, -1.0
    for t in thresholds:
        yp = (y_train_proba >= t).astype(int)
        f2t = fbeta_score(y_train, yp, beta=2, zero_division=0)
        rows.append({
            "threshold": float(t),
            "f1": float(f1_score(y_train, yp, zero_division=0)),
            "f2": float(f2t),
            "precision": float(precision_score(y_train, yp, zero_division=0)),
            "recall": float(recall_score(y_train, yp, zero_division=0)),
        })
        if f2t > best_f2:
            best_f2, best_t = f2t, float(t)
    pd.DataFrame(rows).to_csv(MODELS_DIR / "threshold_scan.csv", index=False)
    print(f"[train] seuil retenu = {best_t:.2f} (F2_train_cv = {best_f2:.4f})")

    print("[train] fit final RF sur tout le train ...")
    rf.fit(X_train, y_train)

    joblib.dump(rf, MODELS_DIR / "model.pkl")
    shutil.copy2(PROCESSED_DIR / "scaler.pkl", MODELS_DIR / "scaler.pkl")
    (MODELS_DIR / "feature_names.json").write_text(
        json.dumps(feature_names), encoding="utf-8"
    )

    t1 = datetime.now(timezone.utc)
    manifest = {
        "generated_utc": t1.isoformat(),
        "duration_s": (t1 - t0).total_seconds(),
        "rf_params": RF_PARAMS,
        "cv": {
            "folds": CV_FOLDS,
            "f1_mean": float(cv_f1.mean()),
            "f1_std": float(cv_f1.std()),
            "f1_folds": [float(x) for x in cv_f1],
            "auc_mean": float(cv_auc.mean()),
            "auc_std": float(cv_auc.std()),
            "auc_folds": [float(x) for x in cv_auc],
        },
        "decision_threshold": float(best_t),
        "n_features": len(feature_names),
        "feature_names": feature_names,
    }
    (MODELS_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"[train] OK ({(t1-t0).total_seconds():.0f}s) -> {MODELS_DIR}")


if __name__ == "__main__":
    main()
