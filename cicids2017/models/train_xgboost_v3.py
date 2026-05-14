"""
═══════════════════════════════════════════════════════════════════════
CIC-IDS-2017 Training v3 — XGBoost sur dataset stratifié 7 classes
═══════════════════════════════════════════════════════════════════════
Améliorations vs v2 :
  - Entraînement sur les 7 classes (vs 4 dans v2)
  - Cross-validation 5-fold sur données équilibrées
  - Métriques détaillées par classe (precision, recall, F1)
  - Détection automatique de leakage via feature importance
  - Visualisations : matrice de confusion + ROC + PR + feature importance
═══════════════════════════════════════════════════════════════════════
"""

import json
import time
import warnings
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import xgboost as xgb
import seaborn as sns
from sklearn.metrics import (
    PrecisionRecallDisplay,
    RocCurveDisplay,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import label_binarize

warnings.filterwarnings("ignore")

# ═══════════════════════════════════════════════════════════════════
DATA_DIR = Path("cicids2017/data/processed_v3")
ARTIFACTS_DIR = Path("cicids2017/saved_models")
RESULTS_DIR = Path("cicids2017/results_v3")
FEATURE_IMPORTANCE_LEAKAGE_THRESHOLD = 0.4


def main():
    print("=" * 70)
    print("🚀 TRAINING CIC-IDS-2017 v3")
    print("   XGBoost multi-classes sur dataset stratifié")
    print("=" * 70)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # ─── 1. Chargement ───
    print("\n[1/6] Chargement des données processed_v3...")
    X_train = pd.read_csv(DATA_DIR / "X_train.csv")
    X_test = pd.read_csv(DATA_DIR / "X_test.csv")
    y_train = pd.read_csv(DATA_DIR / "y_train.csv").values.ravel()
    y_test = pd.read_csv(DATA_DIR / "y_test.csv").values.ravel()

    encoder = joblib.load(ARTIFACTS_DIR / "cicids_label_encoder_v3.pkl")
    classes = list(encoder.classes_)
    n_classes = len(classes)
    print(f"      Train : {X_train.shape}  |  Test : {X_test.shape}")
    print(f"      Classes ({n_classes}) : {classes}")

    # ─── 2. Cross-validation k=5 ───
    print("\n[2/6] Cross-validation stratifiée k=5...")
    cv_scores = []
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for fold, (tr, va) in enumerate(skf.split(X_train, y_train), 1):
        m = xgb.XGBClassifier(
            n_estimators=100, max_depth=6, learning_rate=0.1,
            tree_method="hist", n_jobs=-1, random_state=42,
            objective="multi:softprob", num_class=n_classes,
        )
        m.fit(X_train.iloc[tr], y_train[tr])
        f1 = f1_score(y_train[va], m.predict(X_train.iloc[va]), average="macro")
        cv_scores.append(f1)
        print(f"      Fold {fold} F1-macro = {f1:.4f}")
    print(f"\n      ✅ F1-macro CV = {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")

    # ─── 3. Entraînement final ───
    print("\n[3/6] Entraînement final XGBoost...")
    t0 = time.time()
    model = xgb.XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        tree_method="hist", n_jobs=-1, random_state=42,
        objective="multi:softprob", num_class=n_classes,
    )
    model.fit(X_train, y_train)
    print(f"      ✅ Terminé en {time.time()-t0:.1f}s")

    # ─── 4. Évaluation sur test (RÉEL, non équilibré) ───
    print("\n[4/6] Évaluation sur test set (distribution réelle)...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")
    print(f"      F1-macro    = {f1_macro:.4f}")
    print(f"      F1-weighted = {f1_weighted:.4f}")

    report = classification_report(y_test, y_pred, target_names=classes, zero_division=0)
    print("\n" + report)
    with open(RESULTS_DIR / "classification_report.txt", "w") as f:
        f.write(f"F1-macro CV    = {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}\n")
        f.write(f"F1-macro TEST  = {f1_macro:.4f}\n")
        f.write(f"F1-weighted TEST = {f1_weighted:.4f}\n\n")
        f.write(report)

    # ─── 5. Feature importance + détection leakage ───
    print("[5/6] Feature importance + détection leakage...")
    fi = pd.DataFrame({
        "feature": X_train.columns,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False)
    fi.to_csv(RESULTS_DIR / "feature_importance.csv", index=False)

    top_imp = float(fi["importance"].iloc[0])
    top_feat = fi["feature"].iloc[0]
    print(f"      Top feature : {top_feat} ({top_imp:.3f})")
    if top_imp > FEATURE_IMPORTANCE_LEAKAGE_THRESHOLD:
        print(f"      🚩 [WARNING] Feature dominante ({top_imp:.3f}) → LEAKAGE possible !")
    else:
        print(f"      ✅ [OK] Pas de feature dominante (max = {top_imp:.3f}).")

    fig, ax = plt.subplots(figsize=(10, 7))
    top_20 = fi.head(20)
    ax.barh(range(len(top_20)), top_20["importance"].values, color='steelblue', edgecolor='black')
    ax.set_yticks(range(len(top_20)))
    ax.set_yticklabels(top_20["feature"].values, fontsize=10)
    ax.invert_yaxis()
    ax.set_title(f"CIC-IDS-2017 v3 — Top 20 Features (Gini)\nTop feature: {top_feat} ({top_imp:.3f})",
                 fontsize=12, fontweight='bold')
    ax.set_xlabel("Importance")
    ax.axvline(FEATURE_IMPORTANCE_LEAKAGE_THRESHOLD, color='red', linestyle='--',
               alpha=0.5, label=f'Seuil leakage ({FEATURE_IMPORTANCE_LEAKAGE_THRESHOLD})')
    ax.legend()
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "feature_importance.png", dpi=150, bbox_inches='tight')
    plt.close()

    # ─── 6. Matrice de confusion + ROC + PR ───
    print("\n[6/6] Génération des graphiques...")

    # Matrice de confusion
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                xticklabels=classes, yticklabels=classes, cbar=True)
    ax.set_xlabel('Prédit', fontsize=12, fontweight='bold')
    ax.set_ylabel('Réel', fontsize=12, fontweight='bold')
    ax.set_title(f"Matrice de confusion CIC-IDS-2017 v3\nF1-macro = {f1_macro:.4f} (test) | "
                 f"F1-macro CV = {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}",
                 fontsize=12, fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=150, bbox_inches='tight')
    plt.close()

    # ROC + PR par classe (One-vs-Rest)
    if n_classes > 1:
        y_test_bin = label_binarize(y_test, classes=range(n_classes))
        fig_roc, ax_roc = plt.subplots(figsize=(10, 7))
        fig_pr, ax_pr = plt.subplots(figsize=(10, 7))
        for i, cname in enumerate(classes):
            if y_test_bin.shape[1] == 1:
                yb = y_test
                proba_i = y_proba[:, 1] if y_proba.shape[1] > 1 else y_proba.ravel()
            else:
                yb = y_test_bin[:, i]
                proba_i = y_proba[:, i]
            try:
                RocCurveDisplay.from_predictions(yb, proba_i, name=cname, ax=ax_roc)
                PrecisionRecallDisplay.from_predictions(yb, proba_i, name=cname, ax=ax_pr)
            except Exception as e:
                print(f"      ⚠️ ROC/PR pour {cname} : {e}")
        ax_roc.set_title("Courbes ROC par classe — CIC-IDS-2017 v3", fontsize=12, fontweight='bold')
        ax_pr.set_title("Courbes Précision-Recall par classe — CIC-IDS-2017 v3", fontsize=12, fontweight='bold')
        fig_roc.tight_layout()
        fig_pr.tight_layout()
        fig_roc.savefig(RESULTS_DIR / "roc_curves.png", dpi=150, bbox_inches='tight')
        fig_pr.savefig(RESULTS_DIR / "pr_curves.png", dpi=150, bbox_inches='tight')
        plt.close(fig_roc)
        plt.close(fig_pr)

    # ─── 7. Sauvegarde modèle + métriques ───
    joblib.dump(model, ARTIFACTS_DIR / "xgb_model_v3.pkl")
    metrics = {
        "version": 3,
        "f1_macro_test": float(f1_macro),
        "f1_weighted_test": float(f1_weighted),
        "f1_cv_mean": float(np.mean(cv_scores)),
        "f1_cv_std": float(np.std(cv_scores)),
        "n_classes": n_classes,
        "classes": classes,
        "top_feature": top_feat,
        "top_feature_importance": top_imp,
        "leakage_warning": top_imp > FEATURE_IMPORTANCE_LEAKAGE_THRESHOLD,
    }
    with open(RESULTS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n      Modèle      → {ARTIFACTS_DIR / 'xgb_model_v3.pkl'}")
    print(f"      Résultats   → {RESULTS_DIR}/")

    print("\n" + "=" * 70)
    print(f"[✅] F1-macro TEST = {f1_macro:.4f}")
    print(f"     F1-macro CV  = {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")
    if metrics["leakage_warning"]:
        print("[🚩] Inspection manuelle requise : une feature domine.")
    else:
        print("[✅] Aucune feature dominante détectée — modèle scientifiquement défendable.")
    print("=" * 70)


if __name__ == "__main__":
    main()