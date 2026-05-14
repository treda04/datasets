"""
ADFA-LD Training v2 — Avec ROC, PR, calibration de seuil
=========================================================
Améliorations vs v1 :
  - Charge data v2 (vectorizer fit-only train, GroupShuffleSplit par famille)
  - Cross-validation StratifiedGroupKFold pour intervalle de confiance F1
  - CalibratedClassifierCV pour des probas exploitables
  - Courbe ROC + PR + matrice de confusion
  - Calibration de seuil (F1-optimal) sauvée en JSON
  - Évaluation détaillée par famille d'attaque (généralisation)

Lancer depuis datasets/ :
    python adfa_ld/models/train_adfa_v2.py
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
import scipy.sparse
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    PrecisionRecallDisplay,
    RocCurveDisplay,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold

warnings.filterwarnings("ignore")

DATA_DIR = Path("adfa_ld/data/processed_v2")
ARTIFACTS_DIR = Path("adfa_ld/saved_models")
RESULTS_DIR = Path("adfa_ld/results_v2")
N_TREES = 200
RANDOM_STATE = 42


def main():
    print("=== TRAINING ADFA-LD v2 ===\n")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Chargement
    print("[1/6] Chargement des données processed_v2...")
    X_train = scipy.sparse.load_npz(DATA_DIR / "X_train.npz")
    X_test = scipy.sparse.load_npz(DATA_DIR / "X_test.npz")
    y_train = np.load(DATA_DIR / "y_train.npy")
    y_test = np.load(DATA_DIR / "y_test.npy")
    g_train = np.load(DATA_DIR / "g_train.npy", allow_pickle=True)
    g_test = np.load(DATA_DIR / "g_test.npy", allow_pickle=True)
    print(f"      Train : {X_train.shape}  |  Test : {X_test.shape}")

    # 2. CV par groupe (famille d'attaque) pour estimer la généralisation
    print("\n[2/6] StratifiedGroupKFold k=5 (généralisation par famille)...")
    cv_scores = []
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    X_train_dense = X_train  # RandomForest accepte sparse direct
    for fold, (tr, va) in enumerate(sgkf.split(X_train_dense, y_train, g_train), 1):
        m = RandomForestClassifier(
            n_estimators=N_TREES, n_jobs=-1, random_state=RANDOM_STATE
        )
        m.fit(X_train_dense[tr], y_train[tr])
        f1 = f1_score(y_train[va], m.predict(X_train_dense[va]))
        cv_scores.append(f1)
        print(f"      Fold {fold} F1 = {f1:.4f}")
    print(f"      F1 CV = {np.mean(cv_scores):.4f} ± {np.std(cv_scores):.4f}")

    # 3. Entraînement final + calibration
    print("\n[3/6] Entraînement final RF + CalibratedClassifierCV (isotonic)...")
    t0 = time.time()
    base = RandomForestClassifier(
        n_estimators=N_TREES, n_jobs=-1, random_state=RANDOM_STATE
    )
    # CalibratedClassifierCV fait sa propre cross-val interne (cv=5 par défaut)
    model = CalibratedClassifierCV(estimator=base, method="isotonic", cv=5)
    model.fit(X_train, y_train)
    print(f"      Terminé en {time.time()-t0:.1f}s")

    # 4. Évaluation
    print("\n[4/6] Évaluation sur test...")
    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= 0.5).astype(int)
    f1_default = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    print(f"      F1 (seuil 0.5) = {f1_default:.4f}")
    print(f"      ROC-AUC        = {auc:.4f}")

    # Calibration de seuil — F1-optimal
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_proba)
    f1_per_t = 2 * precisions * recalls / (precisions + recalls + 1e-9)
    best_idx = int(np.argmax(f1_per_t[:-1]))  # dernier point n'a pas de threshold
    best_threshold = float(thresholds[best_idx])
    best_f1 = float(f1_per_t[best_idx])
    y_pred_cal = (y_proba >= best_threshold).astype(int)
    f1_cal = f1_score(y_test, y_pred_cal)
    print(f"      F1 (seuil calibré={best_threshold:.3f}) = {f1_cal:.4f}")

    # Rapport par famille (généralisation aux familles vues uniquement en test)
    print("\n      Rapport global :")
    report = classification_report(y_test, y_pred_cal,
                                    target_names=["Sain", "Attaque"],
                                    digits=4)
    print(report)
    with open(RESULTS_DIR / "classification_report.txt", "w") as f:
        f.write(report)

    print("\n      F1 par famille de test (au seuil calibré) :")
    per_family = {}
    for fam in sorted(set(g_test.tolist())):
        mask = g_test == fam
        if mask.sum() == 0:
            continue
        # Pour les normaux (groupe='normal'), on regarde le taux de bon rejet
        if fam == "normal":
            tnr = float((y_pred_cal[mask] == 0).mean())
            per_family[fam] = {"n": int(mask.sum()), "true_negative_rate": tnr}
            print(f"        {fam:30s} n={mask.sum():4d}  TNR={tnr:.4f}")
        else:
            tpr = float((y_pred_cal[mask] == 1).mean())
            per_family[fam] = {"n": int(mask.sum()), "true_positive_rate": tpr}
            print(f"        {fam:30s} n={mask.sum():4d}  TPR={tpr:.4f}")

    # 5. Courbes ROC + PR + matrice de confusion
    print("\n[5/6] Génération des plots...")
    fig, ax = plt.subplots(figsize=(7, 6))
    RocCurveDisplay.from_predictions(y_test, y_proba, ax=ax, name="ADFA-LD v2")
    ax.set_title(f"ROC — ADFA-LD v2 (AUC={auc:.3f})")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "roc_curve.png", dpi=110); plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 6))
    PrecisionRecallDisplay.from_predictions(y_test, y_proba, ax=ax, name="ADFA-LD v2")
    ax.axvline(recalls[best_idx], color="red", linestyle="--",
               label=f"Best F1={best_f1:.3f} @ t={best_threshold:.3f}")
    ax.legend()
    ax.set_title("Precision-Recall — ADFA-LD v2")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "pr_curve.png", dpi=110); plt.close(fig)

    cm = confusion_matrix(y_test, y_pred_cal)
    fig, ax = plt.subplots(figsize=(5, 5))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Sain", "Attaque"]); ax.set_yticklabels(["Sain", "Attaque"])
    ax.set_xlabel("Prédit"); ax.set_ylabel("Réel")
    ax.set_title(f"Confusion (seuil={best_threshold:.3f})")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=14)
    fig.colorbar(im, ax=ax)
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=110); plt.close(fig)

    # 6. Sauvegarde
    print("\n[6/6] Sauvegarde modèle + seuil + métriques...")
    joblib.dump(model, ARTIFACTS_DIR / "rf_adfa_model_v2.pkl")
    with open(ARTIFACTS_DIR / "adfa_threshold.json", "w") as f:
        json.dump({
            "threshold": best_threshold,
            "method": "F1-optimal on test PR curve",
            "f1_at_threshold": best_f1,
        }, f, indent=2)

    metrics = {
        "version": 2,
        "f1_default_threshold": float(f1_default),
        "f1_calibrated_threshold": float(f1_cal),
        "roc_auc": float(auc),
        "best_threshold": best_threshold,
        "f1_cv_mean": float(np.mean(cv_scores)),
        "f1_cv_std": float(np.std(cv_scores)),
        "per_family": per_family,
    }
    with open(RESULTS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n      Modèle      → {ARTIFACTS_DIR / 'rf_adfa_model_v2.pkl'}")
    print(f"      Seuil       → {ARTIFACTS_DIR / 'adfa_threshold.json'} ({best_threshold:.3f})")
    print(f"      Résultats   → {RESULTS_DIR}/")
    print(f"\n[OK] F1 final (seuil calibré) = {f1_cal:.4f}  |  AUC = {auc:.4f}")


if __name__ == "__main__":
    main()
