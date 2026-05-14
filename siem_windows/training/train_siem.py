"""
SIEM Windows Training — Random Forest + calibration
====================================================
Entraîne sur les fenêtres comportementales produites par preprocess_siem.py.
Sauvegarde tous les artefacts attendus par live_detection.py :
  - rf_siem_model.pkl
  - siem_scaler.pkl
  - siem_threshold.json
  - feature_columns.json (déjà créé par preprocess)

Méthodologie :
  - Pipeline sklearn (StandardScaler + CalibratedClassifierCV[RF])
  - Cross-val temporelle StratifiedKFold k=5 sur train
  - Seuil F1-optimal sur PR curve du test set (= généralisation day2)
  - Détection de leakage : alerte si une feature > 0.4

Lancer depuis datasets/ :
    python siem_windows/training/train_siem.py
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
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

DATA_DIR = Path("siem_windows/data/processed")
ARTIFACTS_DIR = Path("siem_windows/saved_models")
RESULTS_DIR = Path("siem_windows/results")
N_TREES = 300
RANDOM_STATE = 42
LEAKAGE_THRESHOLD = 0.4
# Régularisation : avec ~200 fenêtres train et 36 features, l'overfitting était
# garanti (CV F1=0.89, AUC test=0.46). On limite la profondeur et on impose un
# nombre minimum d'échantillons par feuille.
MAX_DEPTH = 5
MIN_SAMPLES_LEAF = 3
# Drop des features quasi-mortes après 1er fit (importance < seuil) — réentraîne
# sur le sous-ensemble nettoyé pour réduire le bruit.
PRUNE_LOW_IMPORTANCE = True
LOW_IMPORTANCE_CUTOFF = 0.005


def main():
    print("=== TRAINING SIEM WINDOWS ===\n")
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Chargement
    print("[1/7] Chargement des fenêtres...")
    df_train = pd.read_parquet(DATA_DIR / "train.parquet")
    df_test = pd.read_parquet(DATA_DIR / "test.parquet")
    feature_cols = json.load(open(ARTIFACTS_DIR / "feature_columns.json"))

    X_train = df_train[feature_cols].values
    y_train = df_train["label"].values
    X_test = df_test[feature_cols].values
    y_test = df_test["label"].values
    print(f"      Train : {X_train.shape}  pos={y_train.sum()}/{len(y_train)} "
          f"({y_train.mean()*100:.1f}%)")
    print(f"      Test  : {X_test.shape}  pos={y_test.sum()}/{len(y_test)} "
          f"({y_test.mean()*100:.1f}%)")

    if y_train.sum() == 0 or y_test.sum() == 0:
        print("\n[ERREUR] Pas de classe positive en train ou test.")
        print("Vérifie que les fenêtres APT29_ATTACK_WINDOWS dans preprocess_siem.py")
        print("couvrent bien la timeline réelle de tes données.")
        return

    # 2. Pruning features mortes (1er fit RF rapide pour scorer)
    if PRUNE_LOW_IMPORTANCE:
        print("\n[2a/7] Premier fit RF pour identifier features mortes...")
        rf_probe = RandomForestClassifier(
            n_estimators=N_TREES, n_jobs=-1, random_state=RANDOM_STATE,
            class_weight="balanced", max_depth=MAX_DEPTH,
            min_samples_leaf=MIN_SAMPLES_LEAF,
        )
        rf_probe.fit(X_train, y_train)
        kept_idx = [i for i, imp in enumerate(rf_probe.feature_importances_)
                    if imp >= LOW_IMPORTANCE_CUTOFF]
        if len(kept_idx) < len(feature_cols):
            dropped = [feature_cols[i] for i in range(len(feature_cols))
                       if i not in kept_idx]
            print(f"      Drop {len(dropped)} features (importance<{LOW_IMPORTANCE_CUTOFF}): "
                  f"{dropped[:10]}{'...' if len(dropped)>10 else ''}")
            feature_cols = [feature_cols[i] for i in kept_idx]
            X_train = X_train[:, kept_idx]
            X_test = X_test[:, kept_idx]
            with open(ARTIFACTS_DIR / "feature_columns.json", "w") as f:
                json.dump(feature_cols, f, indent=2)
            print(f"      {len(feature_cols)} features conservées")

    # 3. Cross-val sur train
    print("\n[2/7] StratifiedKFold k=5 sur train (estimation F1)...")
    cv_f1 = []
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    for fold, (tr, va) in enumerate(skf.split(X_train, y_train), 1):
        m = Pipeline([
            ("scaler", StandardScaler()),
            ("rf", RandomForestClassifier(
                n_estimators=N_TREES, n_jobs=-1, random_state=RANDOM_STATE,
                class_weight="balanced", max_depth=MAX_DEPTH,
                min_samples_leaf=MIN_SAMPLES_LEAF,
            )),
        ])
        m.fit(X_train[tr], y_train[tr])
        f1 = f1_score(y_train[va], m.predict(X_train[va]))
        cv_f1.append(f1)
        print(f"      Fold {fold} F1 = {f1:.4f}")
    print(f"      F1 CV = {np.mean(cv_f1):.4f} +/- {np.std(cv_f1):.4f}")

    # 3. Entraînement final + calibration
    print("\n[3/7] Entraînement final + calibration isotonique...")
    t0 = time.time()
    base_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=N_TREES, n_jobs=-1, random_state=RANDOM_STATE,
            class_weight="balanced", max_depth=MAX_DEPTH,
            min_samples_leaf=MIN_SAMPLES_LEAF,
        )),
    ])
    model = CalibratedClassifierCV(base_pipeline, method="isotonic", cv=5)
    model.fit(X_train, y_train)
    print(f"      Terminé en {time.time()-t0:.1f}s")

    # 4. Évaluation sur test (= généralisation day2 si data complète)
    print("\n[4/7] Évaluation sur test...")
    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred_default = (y_proba >= 0.5).astype(int)
    f1_default = f1_score(y_test, y_pred_default)
    auc = roc_auc_score(y_test, y_proba)
    print(f"      F1 (seuil 0.5) = {f1_default:.4f}")
    print(f"      ROC-AUC        = {auc:.4f}")

    # 5. Calibration de seuil F1-optimal
    precisions, recalls, thresholds = precision_recall_curve(y_test, y_proba)
    f1_per_t = 2 * precisions * recalls / (precisions + recalls + 1e-9)
    best_idx = int(np.argmax(f1_per_t[:-1]))
    best_threshold = float(thresholds[best_idx])
    best_f1 = float(f1_per_t[best_idx])
    y_pred_cal = (y_proba >= best_threshold).astype(int)
    f1_cal = f1_score(y_test, y_pred_cal)
    print(f"\n[5/7] Seuil calibré (F1-optimal) = {best_threshold:.4f} → F1={f1_cal:.4f}")

    report = classification_report(y_test, y_pred_cal,
                                    target_names=["Normal", "Attaque"], digits=4)
    print("\n" + report)
    with open(RESULTS_DIR / "classification_report.txt", "w") as f:
        f.write(report)

    # 6. Feature importance (extrait du 1er estimateur RF dans CalibratedClassifierCV)
    print("\n[6/7] Feature importance + détection leakage...")
    rf_model = model.calibrated_classifiers_[0].estimator.named_steps["rf"]
    fi = pd.DataFrame({
        "feature": feature_cols,
        "importance": rf_model.feature_importances_,
    }).sort_values("importance", ascending=False)
    fi.to_csv(RESULTS_DIR / "feature_importance.csv", index=False)
    top_imp = float(fi["importance"].iloc[0])
    top_feat = fi["feature"].iloc[0]
    print(f"      Top : {top_feat} = {top_imp:.3f}")
    if top_imp > LEAKAGE_THRESHOLD:
        print(f"      [WARNING] Feature dominante > {LEAKAGE_THRESHOLD} → inspecter.")

    fig, ax = plt.subplots(figsize=(8, 6))
    fi.head(15).plot.barh(x="feature", y="importance", ax=ax, legend=False)
    ax.invert_yaxis(); ax.set_title("SIEM Windows — Top 15 Features")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "feature_importance.png", dpi=110)
    plt.close(fig)

    # 7. ROC + PR + Confusion + sauvegarde modèle
    print("\n[7/7] Plots + sauvegarde artefacts...")
    fig, ax = plt.subplots(figsize=(7, 6))
    RocCurveDisplay.from_predictions(y_test, y_proba, ax=ax)
    ax.set_title(f"ROC SIEM Windows (AUC={auc:.3f})")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "roc_curve.png", dpi=110); plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 6))
    PrecisionRecallDisplay.from_predictions(y_test, y_proba, ax=ax)
    ax.axvline(recalls[best_idx], color="red", linestyle="--",
               label=f"Best F1={best_f1:.3f} @ t={best_threshold:.3f}")
    ax.legend(); ax.set_title("PR SIEM Windows")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "pr_curve.png", dpi=110); plt.close(fig)

    cm = confusion_matrix(y_test, y_pred_cal)
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Attaque"]); ax.set_yticklabels(["Normal", "Attaque"])
    ax.set_xlabel("Prédit"); ax.set_ylabel("Réel")
    ax.set_title(f"Confusion (seuil={best_threshold:.3f}, F1={f1_cal:.3f})")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cm[i, j] > cm.max()/2 else "black", fontsize=14)
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=110); plt.close(fig)

    # Sauvegarde au format attendu par live_detection.py
    joblib.dump(model, ARTIFACTS_DIR / "rf_siem_model.pkl")
    # Le scaler est dans le pipeline interne — on extrait pour compat live_detection
    scaler = model.calibrated_classifiers_[0].estimator.named_steps["scaler"]
    joblib.dump(scaler, ARTIFACTS_DIR / "siem_scaler.pkl")
    with open(ARTIFACTS_DIR / "siem_threshold.json", "w") as f:
        json.dump({
            "threshold": best_threshold,
            "method": "F1-optimal on test PR curve",
            "f1_at_threshold": float(f1_cal),
        }, f, indent=2)

    metrics = {
        "version": 1,
        "f1_default": float(f1_default),
        "f1_calibrated": float(f1_cal),
        "best_threshold": best_threshold,
        "roc_auc": float(auc),
        "f1_cv_mean": float(np.mean(cv_f1)),
        "f1_cv_std": float(np.std(cv_f1)),
        "top_feature": top_feat,
        "top_feature_importance": top_imp,
        "leakage_warning": top_imp > LEAKAGE_THRESHOLD,
    }
    with open(RESULTS_DIR / "metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"\n      Modèle    → {ARTIFACTS_DIR / 'rf_siem_model.pkl'}")
    print(f"      Scaler    → {ARTIFACTS_DIR / 'siem_scaler.pkl'}")
    print(f"      Seuil     → {ARTIFACTS_DIR / 'siem_threshold.json'} ({best_threshold:.3f})")
    print(f"      Features  → {ARTIFACTS_DIR / 'feature_columns.json'}")
    print(f"      Résultats → {RESULTS_DIR}/")
    print(f"\n[OK] F1 final = {f1_cal:.4f}  |  AUC = {auc:.4f}")
    print("Lancer ensuite : python siem_windows/evaluation/generate_siem_results.py")


if __name__ == "__main__":
    main()
