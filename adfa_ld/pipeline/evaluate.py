"""Étape 3/3 du pipeline ADFA-LD — Évaluation.

Charge le modèle entraîné + le test set, applique le seuil de décision figé
dans le manifest, calcule toutes les métriques et génère les figures finales.

Usage :
    python pipeline/evaluate.py

Pré-requis :
    avoir exécuté preprocess.py puis train.py.

Sorties (dans results/final/) :
    metrics.json                     toutes les métriques
    classification_report.txt        rapport sklearn formaté
    confusion_matrix.png             matrice de confusion
    roc_pr_curves.png                ROC + Precision-Recall
    per_attack_family.{csv,png}      recall par famille
    feature_importance.{csv,png}     top 30 features
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy.sparse as sp
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score, fbeta_score,
    precision_recall_curve, precision_score, recall_score, roc_auc_score,
    roc_curve,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import MODELS_DIR, PROCESSED_DIR, RESULTS_DIR  # noqa: E402

sns.set_theme(style="whitegrid")


def main() -> None:
    print("=" * 60)
    print("ÉTAPE 3/3 — Evaluation")
    print("=" * 60)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Charger artefacts ---
    model = joblib.load(MODELS_DIR / "model.pkl")
    vectorizer = joblib.load(PROCESSED_DIR / "vectorizer.pkl")
    manifest = json.loads((MODELS_DIR / "manifest.json").read_text(encoding="utf-8"))
    threshold = float(manifest["decision_threshold"])

    X_test = sp.load_npz(PROCESSED_DIR / "X_test.npz")
    y_test_df = pd.read_csv(PROCESSED_DIR / "y_test.csv")
    y_test = y_test_df["label"].values

    print(f"[load] X_test={X_test.shape}, attaques={int(y_test.sum())}")
    print(f"[load] seuil de décision = {threshold:.2f}")

    # --- 2. Prédictions ---
    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= threshold).astype(int)

    # --- 3. Métriques principales ---
    f1 = f1_score(y_test, y_pred)
    f2 = fbeta_score(y_test, y_pred, beta=2)
    auc = roc_auc_score(y_test, y_proba)
    p = precision_score(y_test, y_pred)
    r = recall_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    gap = abs(manifest["cv_metrics"]["f1_mean"] - f1)

    print(f"\n=== Métriques TEST (seuil={threshold:.2f}) ===")
    print(f"F1        : {f1:.4f}")
    print(f"F2        : {f2:.4f}")
    print(f"AUC       : {auc:.4f}")
    print(f"Precision : {p:.4f}")
    print(f"Recall    : {r:.4f}")
    print(f"Gap CV-Test F1 : {gap:.4f}")

    report_txt = classification_report(
        y_test, y_pred, target_names=["Normal", "Attaque"], digits=4,
    )
    (RESULTS_DIR / "classification_report.txt").write_text(report_txt, encoding="utf-8")

    # --- 4. Matrice de confusion ---
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Normal", "Attaque"],
                yticklabels=["Normal", "Attaque"], ax=ax)
    ax.set_xlabel("Prédit"); ax.set_ylabel("Réel")
    ax.set_title(f"Matrice de confusion — seuil={threshold:.2f}")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=110, bbox_inches="tight")
    plt.close(fig)

    # --- 5. Courbes ROC + PR ---
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    prec_curve, rec_curve, _ = precision_recall_curve(y_test, y_proba)

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    axes[0].plot(fpr, tpr, lw=2, label=f"AUC = {auc:.4f}")
    axes[0].plot([0, 1], [0, 1], "--", color="gray")
    axes[0].set_xlabel("FPR"); axes[0].set_ylabel("TPR")
    axes[0].set_title("ROC curve"); axes[0].legend()

    axes[1].plot(rec_curve, prec_curve, lw=2, color="crimson")
    axes[1].set_xlabel("Recall"); axes[1].set_ylabel("Precision")
    axes[1].set_title("Precision-Recall curve")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "roc_pr_curves.png", dpi=110, bbox_inches="tight")
    plt.close(fig)

    # --- 6. Recall par famille d'attaque ---
    df_eval = y_test_df.copy()
    df_eval["y_pred"] = y_pred
    df_eval["y_proba"] = y_proba

    per_family = []
    for family in sorted(df_eval[df_eval.label == 1]["family"].unique()):
        mask = df_eval["family"] == family
        n = int(mask.sum())
        detected = int(df_eval.loc[mask, "y_pred"].sum())
        per_family.append({
            "family": family, "n_test": n, "detected": detected,
            "recall": round(detected / n if n else 0.0, 4),
        })

    per_family_df = pd.DataFrame(per_family).sort_values("recall", ascending=False)
    per_family_df.to_csv(RESULTS_DIR / "per_attack_family.csv", index=False)

    fig, ax = plt.subplots(figsize=(8, 4))
    sns.barplot(data=per_family_df, x="family", y="recall", hue="family",
                palette="viridis", legend=False, ax=ax)
    ax.set_title(f"Recall par famille (seuil={threshold:.2f})")
    ax.set_ylim(0, 1.05)
    ax.axhline(0.80, ls="--", color="red", lw=1, label="Cible 0.80")
    ax.tick_params(axis="x", rotation=20)
    ax.legend()
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "per_attack_family.png", dpi=110, bbox_inches="tight")
    plt.close(fig)

    print("\n--- Recall par famille ---")
    print(per_family_df.to_string(index=False))

    # --- 7. Feature importance (moyenne sur les 5 RF calibrés) ---
    feature_names = vectorizer.get_feature_names_out()
    importances = np.mean(
        [cc.estimator.feature_importances_ for cc in model.calibrated_classifiers_],
        axis=0,
    )
    fi_df = (
        pd.DataFrame({
            "feature": feature_names, "importance": importances,
            "type": [{1: "unigramme", 2: "bigramme", 3: "trigramme"}[len(f.split())]
                     for f in feature_names],
        })
        .sort_values("importance", ascending=False)
        .reset_index(drop=True)
    )
    fi_df.to_csv(RESULTS_DIR / "feature_importance.csv", index=False)

    top30 = fi_df.head(30)
    fig, ax = plt.subplots(figsize=(9, 8))
    sns.barplot(data=top30, y="feature", x="importance", hue="feature",
                palette="rocket", legend=False, ax=ax)
    ax.set_title("Top 30 features — feature importance")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "feature_importance.png", dpi=110, bbox_inches="tight")
    plt.close(fig)

    # --- 8. Métriques consolidées ---
    metrics = {
        "decision_threshold": threshold,
        "test": {
            "f1": float(f1), "f2": float(f2), "auc": float(auc),
            "precision": float(p), "recall": float(r),
        },
        "cv_train": manifest["cv_metrics"],
        "gap_cv_test_f1": float(gap),
        "max_feature_importance": float(fi_df["importance"].max()),
        "min_family_recall": float(per_family_df["recall"].min()),
        "per_family": per_family,
        "confusion_matrix": cm.tolist(),
    }
    (RESULTS_DIR / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8",
    )

    print(f"\nArtefacts écrits dans {RESULTS_DIR}/ :")
    for f in sorted(RESULTS_DIR.iterdir()):
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
