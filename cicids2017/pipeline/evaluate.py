"""Étape 3/3 du pipeline CIC-IDS-2017 — Évaluation.

Charge le modèle + le test set, prédit, calcule toutes les métriques,
génère les figures.

Usage :
    python pipeline/evaluate.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import MODELS_DIR, PROCESSED_DIR, RESULTS_DIR  # noqa: E402

sns.set_theme(style="whitegrid")


def main() -> None:
    print("=" * 60)
    print("ÉTAPE 3/3 — Evaluation CIC-IDS-2017")
    print("=" * 60)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Charger artefacts ---
    model = joblib.load(MODELS_DIR / "model.pkl")
    manifest = json.loads((MODELS_DIR / "manifest.json").read_text(encoding="utf-8"))
    feature_names = json.loads(
        (PROCESSED_DIR / "feature_names.json").read_text(encoding="utf-8")
    )

    X_test = np.load(PROCESSED_DIR / "X_test.npy")
    y_test = np.load(PROCESSED_DIR / "y_test.npy", allow_pickle=True)
    print(f"[load] X_test={X_test.shape}")

    # --- 2. Prédictions ---
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    # --- 3. Métriques globales ---
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")
    p_macro = precision_score(y_test, y_pred, average="macro")
    r_macro = recall_score(y_test, y_pred, average="macro")
    auc_ovr = roc_auc_score(y_test, y_proba, multi_class="ovr", average="macro")
    gap = abs(manifest["cv_metrics"]["f1_macro_mean"] - f1_macro)

    print(f"\n=== Métriques TEST ===")
    print(f"F1 macro     : {f1_macro:.4f}")
    print(f"F1 weighted  : {f1_weighted:.4f}")
    print(f"Precision M  : {p_macro:.4f}")
    print(f"Recall    M  : {r_macro:.4f}")
    print(f"AUC OVR macro: {auc_ovr:.4f}")
    print(f"Gap CV-Test  : {gap:.4f}")

    report_txt = classification_report(y_test, y_pred, digits=4)
    print("\n--- Classification report ---")
    print(report_txt)
    (RESULTS_DIR / "classification_report.txt").write_text(report_txt, encoding="utf-8")

    # --- 4. Matrice de confusion (2 versions) ---
    labels = sorted(np.unique(y_test).tolist())
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    fig, axes = plt.subplots(1, 2, figsize=(16, 5.5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=labels, yticklabels=labels, ax=axes[0])
    axes[0].set_title("Matrice de confusion (compte)")
    axes[0].set_xlabel("Prédit"); axes[0].set_ylabel("Réel")
    axes[0].tick_params(axis="x", rotation=30)

    cm_norm = cm / cm.sum(axis=1, keepdims=True)
    sns.heatmap(cm_norm, annot=True, fmt=".2f", cmap="Greens",
                xticklabels=labels, yticklabels=labels, ax=axes[1])
    axes[1].set_title("Matrice de confusion (normalisée = recall par classe)")
    axes[1].set_xlabel("Prédit"); axes[1].set_ylabel("Réel")
    axes[1].tick_params(axis="x", rotation=30)
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=110, bbox_inches="tight")
    plt.close(fig)

    # --- 5. Métriques par classe ---
    per_class = []
    for cls in labels:
        mask = (y_test == cls)
        pred_mask = (y_pred == cls)
        tp = int((mask & pred_mask).sum())
        fn = int((mask & ~pred_mask).sum())
        fp = int((~mask & pred_mask).sum())
        n = int(mask.sum())
        rec = tp / max(n, 1)
        prec = tp / max(tp + fp, 1)
        f1 = 2 * prec * rec / max(prec + rec, 1e-9)
        per_class.append({
            "class": cls, "n_test": n, "tp": tp, "fn": fn, "fp": fp,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        })

    pc_df = pd.DataFrame(per_class).sort_values("f1", ascending=False)
    pc_df.to_csv(RESULTS_DIR / "per_class_metrics.csv", index=False)
    print("\n--- Métriques par classe ---")
    print(pc_df.to_string(index=False))

    fig, ax = plt.subplots(figsize=(10, 4.5))
    pc_melted = pc_df.melt(id_vars="class", value_vars=["precision", "recall", "f1"],
                           var_name="metric", value_name="score")
    sns.barplot(data=pc_melted, x="class", y="score", hue="metric",
                ax=ax, palette="viridis")
    ax.set_ylim(0, 1.05)
    ax.axhline(0.80, ls="--", color="red", lw=1, label="Seuil 0.80")
    ax.set_title("Métriques par classe — Test set")
    ax.tick_params(axis="x", rotation=20)
    ax.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "per_class_metrics.png", dpi=110, bbox_inches="tight")
    plt.close(fig)

    # --- 6. Feature importance ---
    fi = pd.DataFrame({
        "feature": feature_names,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False).reset_index(drop=True)
    fi.to_csv(RESULTS_DIR / "feature_importance.csv", index=False)

    top30 = fi.head(30)
    fig, ax = plt.subplots(figsize=(10, 9))
    sns.barplot(data=top30, y="feature", x="importance", hue="feature",
                palette="rocket", legend=False, ax=ax)
    ax.set_title("Top 30 features — Random Forest feature importance")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "feature_importance.png", dpi=110, bbox_inches="tight")
    plt.close(fig)

    # --- 7. Métriques consolidées ---
    metrics = {
        "test": {
            "f1_macro": float(f1_macro),
            "f1_weighted": float(f1_weighted),
            "precision_macro": float(p_macro),
            "recall_macro": float(r_macro),
            "auc_ovr_macro": float(auc_ovr),
        },
        "cv_train": manifest["cv_metrics"],
        "gap_cv_test_f1_macro": float(gap),
        "max_feature_importance": float(fi["importance"].max()),
        "min_class_f1": float(pc_df["f1"].min()),
        "min_class_recall": float(pc_df["recall"].min()),
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "labels": labels,
    }
    (RESULTS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"\nArtefacts dans {RESULTS_DIR}/ :")
    for f in sorted(RESULTS_DIR.iterdir()):
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
