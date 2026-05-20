"""Étape 3/3 du pipeline : load model + test set -> métriques + figures.

Usage :
    python pipeline/evaluate.py

Produit :
    results/final/metrics.json
    results/final/classification_report.txt
    results/final/confusion_matrix.png
    results/final/roc_pr_curves.png
    results/final/feature_importance.png
"""
from __future__ import annotations

import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score, fbeta_score,
    precision_score, recall_score, roc_auc_score, roc_curve,
    precision_recall_curve, average_precision_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import MODELS_DIR, PROCESSED_DIR, RESULTS_DIR  # noqa: E402


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    sns.set_theme(style="whitegrid", palette="muted")
    t0 = datetime.now(timezone.utc)
    print(f"[evaluate] start utc={t0.isoformat()}")

    # Chargements
    model = joblib.load(MODELS_DIR / "model.pkl")
    manifest_train = json.loads((MODELS_DIR / "manifest.json").read_text())
    threshold = float(manifest_train.get("decision_threshold", 0.50))
    feature_names = manifest_train["feature_names"]

    X_test = np.load(PROCESSED_DIR / "X_test.npy")
    y_test = np.load(PROCESSED_DIR / "y_test.npy")
    cv_f1_mean = manifest_train["cv"]["f1_mean"]
    print(f"[evaluate] X_test={X_test.shape} | seuil={threshold:.2f} | CV F1 mean={cv_f1_mean:.4f}")

    # Prédictions
    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= threshold).astype(int)

    # Métriques
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    f2 = float(fbeta_score(y_test, y_pred, beta=2, zero_division=0))
    pr = float(precision_score(y_test, y_pred, zero_division=0))
    rc = float(recall_score(y_test, y_pred, zero_division=0))
    try:
        auc = float(roc_auc_score(y_test, y_proba))
    except Exception:
        auc = float("nan")
    try:
        ap = float(average_precision_score(y_test, y_proba))
    except Exception:
        ap = float("nan")
    gap = abs(cv_f1_mean - f1)
    cm = confusion_matrix(y_test, y_pred)

    report_txt = classification_report(
        y_test, y_pred, target_names=["Normal(0)", "Attaque(1)"], digits=4, zero_division=0
    )
    print()
    print(f"=== TEST METRICS — seuil {threshold:.2f} ===")
    print(f"  F1={f1:.4f}  F2={f2:.4f}  AUC={auc:.4f}  Prec={pr:.4f}  Recall={rc:.4f}")
    print(f"  Gap CV-Test F1 = {gap:.4f}")
    print(report_txt)

    # Figure 1 — confusion matrix
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues", cbar=False,
        xticklabels=["Normal(0)", "Attaque(1)"],
        yticklabels=["Normal(0)", "Attaque(1)"], ax=ax,
    )
    ax.set_title(f"Matrice de Confusion — seuil {threshold:.2f}\n"
                 f"F1={f1:.3f} | Recall={rc:.3f} | Precision={pr:.3f}")
    ax.set_xlabel("Prédiction modèle")
    ax.set_ylabel("Vérité terrain")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=120, bbox_inches="tight")
    plt.close()

    # Figure 2 — ROC + PR
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    if not math.isnan(auc):
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        axes[0].plot(fpr, tpr, color="#c0392b", lw=2, label=f"AUC = {auc:.3f}")
        axes[0].plot([0, 1], [0, 1], lw=1, ls="--", color="grey")
        axes[0].set_title("Courbe ROC (test Day 2)")
        axes[0].set_xlabel("False Positive Rate")
        axes[0].set_ylabel("True Positive Rate")
        axes[0].legend(loc="lower right")
    if not math.isnan(ap):
        prec_arr, rec_arr, _ = precision_recall_curve(y_test, y_proba)
        axes[1].plot(rec_arr, prec_arr, color="#2980b9", lw=2, label=f"AP = {ap:.3f}")
        axes[1].axhline(y=float(y_test.mean()), color="grey", ls="--", lw=1,
                        label=f"Baseline = {y_test.mean():.3f}")
        axes[1].set_title("Courbe Precision-Recall")
        axes[1].set_xlabel("Recall")
        axes[1].set_ylabel("Precision")
        axes[1].legend(loc="best")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "roc_pr_curves.png", dpi=120, bbox_inches="tight")
    plt.close()

    # Figure 3 — feature importance
    importances = pd.Series(model.feature_importances_, index=feature_names).sort_values(ascending=False)
    top = importances.head(15)
    max_imp = float(importances.max())
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ["#c0392b" if v > 0.25 else "#2980b9" for v in top.values]
    ax.barh(top.index[::-1], top.values[::-1], color=colors[::-1])
    ax.set_title(f"Top 15 features — Importance Gini\nMax importance = {max_imp:.3f} (cible < 0.25)")
    ax.set_xlabel("Importance (somme = 1)")
    ax.axvline(0.25, color="red", ls="--", lw=1, alpha=0.5, label="Seuil shortcut (0.25)")
    ax.legend()
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "feature_importance.png", dpi=120, bbox_inches="tight")
    plt.close()

    # Sauvegardes
    (RESULTS_DIR / "classification_report.txt").write_text(report_txt, encoding="utf-8")

    metrics = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "decision_threshold": threshold,
        "cv_f1_mean_from_train": cv_f1_mean,
        "test": {
            "f1": f1, "f2": f2, "precision": pr, "recall": rc,
            "auc_roc": auc if not math.isnan(auc) else None,
            "avg_precision": ap if not math.isnan(ap) else None,
            "gap_cv_test_f1": gap,
            "confusion_matrix": cm.tolist(),
            "n_test": int(len(y_test)),
            "n_test_positive": int(int(y_test.sum())),
        },
        "feature_importance": {
            "max": max_imp,
            "top15": {k: float(v) for k, v in importances.head(15).items()},
        },
        "targets_check": {
            "f1_ge_0_78": bool(f1 >= 0.78),
            "f2_ge_0_80": bool(f2 >= 0.80),
            "recall_ge_0_80": bool(rc >= 0.80),
            "precision_ge_0_70": bool(pr >= 0.70),
            "auc_ge_0_85": bool((not math.isnan(auc)) and auc >= 0.85),
            "gap_lt_0_10": bool(gap < 0.10),
            "max_importance_lt_0_25": bool(max_imp < 0.25),
        },
    }
    (RESULTS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    t1 = datetime.now(timezone.utc)
    print(f"[evaluate] OK ({(t1-t0).total_seconds():.0f}s) -> {RESULTS_DIR}")
    print()
    print("Cibles :")
    for k, v in metrics["targets_check"].items():
        flag = "[OK]" if v else "[KO]"
        print(f"  {flag}  {k}")


if __name__ == "__main__":
    main()
