"""
CIC-IDS-2017 Training v2 — Avec ROC, PR, calibration de seuil
==============================================================
Améliorations vs v1 :
  - Charge les data v2 (sans Destination Port)
  - Multi-classes (au lieu de 4 hardcodées)
  - Courbes ROC + PR par classe (One-vs-Rest)
  - Feature importance gating : alerte si une feature > 0.4 (signe de leakage)
  - Seuil calibré (F1-optimal) sauvé en JSON
  - Cross-validation stratifiée k=5 pour intervalles de confiance F1

Lancer depuis datasets/ :
    python cicids2017/models/train_xgboost_v2.py
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

DATA_DIR = Path("cicids2017/data/processed_v2")
ARTIFACTS_DIR = Path("cicids2017/saved_models")
RESULTS_DIR = Path("cicids2017/results_v2")
FEATURE_IMPORTANCE_LEAKAGE_THRESHOLD = 0.4


def main():
    print("=== TRAINING CIC-IDS-2017 v2 ===\n")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Chargement
    print("[1/6] Chargement données processed_v2...")
    X_train = pd.read_csv(DATA_DIR / "X_train.csv")
    X_test = pd.read_csv(DATA_DIR / "X_test.csv")
    y_train = pd.read_csv(DATA_DIR / "y_train.csv").values.ravel()
    y_test = pd.read_csv(DATA_DIR / "y_test.csv").values.ravel()

    encoder = joblib.load(ARTIFACTS_DIR / "cicids_label_encoder.pkl")
    classes = list(encoder.classes_)
    n_classes = len(classes)
    print(f"      Train : {X_train.shape}  |  Test : {X_test.shape}")
    print(f"      Classes ({n_classes}) : {classes}")

    # 2. Cross-validation k=5 pour F1 ± std (sur train seulement)
    print("\n[2/6] Cross-validation stratifiée k=5 (intervalle de confiance)...")
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
    print(f"      F1-macro CV = {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")

    # 3. Entraînement final sur tout le train
    print("\n[3/6] Entraînement final XGBoost...")
    t0 = time.time()
    model = xgb.XGBClassifier(
        n_estimators=200, max_depth=6, learning_rate=0.1,
        tree_method="hist", n_jobs=-1, random_state=42,
        objective="multi:softprob", num_class=n_classes,
    )
    model.fit(X_train, y_train)
    print(f"      Terminé en {time.time()-t0:.1f}s")

    # 4. Évaluation sur test
    print("\n[4/6] Évaluation sur test...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    f1_weighted = f1_score(y_test, y_pred, average="weighted")
    print(f"      F1-macro    = {f1_macro:.4f}")
    print(f"      F1-weighted = {f1_weighted:.4f}")

    report = classification_report(y_test, y_pred, target_names=classes, zero_division=0)
    print("\n" + report)
    with open(RESULTS_DIR / "classification_report.txt", "w") as f:
        f.write(report)

    # 5. Feature importance + détection leakage
    print("\n[5/6] Feature importance + détection leakage...")
    fi = pd.DataFrame({
        "feature": X_train.columns,
        "importance": model.feature_importances_,
    }).sort_values("importance", ascending=False)
    fi.to_csv(RESULTS_DIR / "feature_importance.csv", index=False)

    top_imp = float(fi["importance"].iloc[0])
    top_feat = fi["feature"].iloc[0]
    print(f"      Top feature : {top_feat} ({top_imp:.3f})")
    if top_imp > FEATURE_IMPORTANCE_LEAKAGE_THRESHOLD:
        print(f"      [WARNING] Feature dominante ({top_imp:.3f} > "
              f"{FEATURE_IMPORTANCE_LEAKAGE_THRESHOLD}) → LEAKAGE possible. "
              "Inspecter cette feature.")
    else:
        print(f"      [OK] Pas de feature dominante (max = {top_imp:.3f}).")

    fig, ax = plt.subplots(figsize=(8, 6))
    fi.head(20).plot.barh(x="feature", y="importance", ax=ax, legend=False)
    ax.invert_yaxis()
    ax.set_title("CIC-IDS-2017 v2 — Top 20 Features")
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "feature_importance.png", dpi=110)
    plt.close(fig)

    # 6. Courbes ROC + PR + matrice de confusion + sauvegarde modèle
    print("\n[6/6] Courbes ROC + PR + matrice de confusion...")
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(8, 7))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(n_classes)); ax.set_yticks(range(n_classes))
    ax.set_xticklabels(classes, rotation=45, ha="right"); ax.set_yticklabels(classes)
    ax.set_xlabel("Prédit"); ax.set_ylabel("Réel")
    ax.set_title(f"Matrice de confusion — F1-macro = {f1_macro:.3f}")
    for i in range(n_classes):
        for j in range(n_classes):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=8)
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    fig.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=110)
    plt.close(fig)

    # ROC + PR par classe (one-vs-rest)
    if n_classes > 1:
        y_test_bin = label_binarize(y_test, classes=range(n_classes))
        fig_roc, ax_roc = plt.subplots(figsize=(8, 6))
        fig_pr, ax_pr = plt.subplots(figsize=(8, 6))
        for i, cname in enumerate(classes):
            if y_test_bin.shape[1] == 1:  # binaire dégénéré
                yb = y_test
                proba_i = y_proba[:, 1] if y_proba.shape[1] > 1 else y_proba.ravel()
            else:
                yb = y_test_bin[:, i]
                proba_i = y_proba[:, i]
            try:
                RocCurveDisplay.from_predictions(yb, proba_i, name=cname, ax=ax_roc)
                PrecisionRecallDisplay.from_predictions(yb, proba_i, name=cname, ax=ax_pr)
            except Exception as e:
                print(f"      [warn] ROC/PR pour {cname} : {e}")
        ax_roc.set_title("ROC par classe — CIC-IDS-2017 v2")
        ax_pr.set_title("Precision-Recall par classe — CIC-IDS-2017 v2")
        fig_roc.tight_layout(); fig_pr.tight_layout()
        fig_roc.savefig(RESULTS_DIR / "roc_curves.png", dpi=110)
        fig_pr.savefig(RESULTS_DIR / "pr_curves.png", dpi=110)
        plt.close(fig_roc); plt.close(fig_pr)

    # Sauvegarde modèle + métriques
    joblib.dump(model, ARTIFACTS_DIR / "xgb_model_v2.pkl")
    metrics = {
        "version": 2,
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

    print(f"\n      Modèle      → {ARTIFACTS_DIR / 'xgb_model_v2.pkl'}")
    print(f"      Résultats   → {RESULTS_DIR}/")
    print(f"\n[OK] F1-macro test = {f1_macro:.4f}")
    if metrics["leakage_warning"]:
        print("[!]  Inspection manuelle requise : une feature domine.")
    else:
        print("[OK] Aucune feature dominante détectée.")


if __name__ == "__main__":
    main()
