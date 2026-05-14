"""
SIEM Windows — Leave-One-Host-Out Cross-Validation
====================================================
Boucle sur les 4 hosts du dataset APT29 : chaque host à son tour est le test set,
les 3 autres forment le train. Donne une estimation robuste de la généralisation
(au lieu de dépendre du choix d'un seul host comme NEWYORK).

Lancer depuis datasets/ :
    .venv\\Scripts\\python.exe scripts/siem_loho_cv.py
"""
import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

DATA_DIR = Path("siem_windows/data/processed")
RESULTS_DIR = Path("siem_windows/results")
RANDOM_STATE = 42
N_TREES = 300
MAX_DEPTH = 5
MIN_SAMPLES_LEAF = 3


def main():
    print("=== LEAVE-ONE-HOST-OUT CROSS-VALIDATION SIEM ===\n")
    # On recharge l'ensemble brut day1+day2 (avant le split par host)
    df_train = pd.read_parquet(DATA_DIR / "train.parquet")
    df_test = pd.read_parquet(DATA_DIR / "test.parquet")
    df_all = pd.concat([df_train, df_test], ignore_index=True)

    feature_cols = json.load(open("siem_windows/saved_models/feature_columns.json"))
    X = df_all[feature_cols].values
    y = df_all["label"].values
    hosts = df_all["host"].values
    unique_hosts = sorted(set(hosts))

    print(f"Hosts : {unique_hosts}")
    print(f"Total : {len(df_all)} fenêtres ({y.sum()} positives, "
          f"{y.mean()*100:.1f}%)\n")

    results = []
    for held_out in unique_hosts:
        tr_mask = hosts != held_out
        te_mask = hosts == held_out
        Xtr, Xte = X[tr_mask], X[te_mask]
        ytr, yte = y[tr_mask], y[te_mask]

        base = Pipeline([
            ("scaler", StandardScaler()),
            ("rf", RandomForestClassifier(
                n_estimators=N_TREES, n_jobs=-1, random_state=RANDOM_STATE,
                class_weight="balanced", max_depth=MAX_DEPTH,
                min_samples_leaf=MIN_SAMPLES_LEAF,
            )),
        ])
        model = CalibratedClassifierCV(base, method="isotonic", cv=5)
        model.fit(Xtr, ytr)

        y_proba = model.predict_proba(Xte)[:, 1]
        y_pred_05 = (y_proba >= 0.5).astype(int)
        f1_05 = f1_score(yte, y_pred_05, zero_division=0)

        # F1-optimal seuil
        prec, rec, thr = precision_recall_curve(yte, y_proba)
        f1_per_t = 2 * prec * rec / (prec + rec + 1e-9)
        best_idx = int(np.argmax(f1_per_t[:-1])) if len(thr) > 0 else 0
        f1_opt = float(f1_per_t[best_idx])
        best_t = float(thr[best_idx]) if len(thr) > 0 else 0.5

        try:
            auc = roc_auc_score(yte, y_proba)
        except ValueError:
            auc = float("nan")
        try:
            ap = average_precision_score(yte, y_proba)
        except ValueError:
            ap = float("nan")

        # Gap train/test pour overfitting
        f1_train = f1_score(ytr, (model.predict_proba(Xtr)[:, 1] >= 0.5).astype(int))

        results.append({
            "held_out_host": held_out,
            "n_train": int(tr_mask.sum()),
            "n_test": int(te_mask.sum()),
            "n_test_positive": int(yte.sum()),
            "balance_test": float(yte.mean()),
            "f1_default_05": float(f1_05),
            "f1_optimal": f1_opt,
            "best_threshold": best_t,
            "roc_auc": float(auc),
            "avg_precision": float(ap),
            "f1_train_05": float(f1_train),
            "overfit_gap": float(f1_train - f1_05),
        })

        print(f"Test = {held_out:30s}  "
              f"F1@0.5={f1_05:.3f}  F1_opt={f1_opt:.3f}  "
              f"AUC={auc:.3f}  gap={f1_train - f1_05:+.3f}")

    df_res = pd.DataFrame(results)
    print("\n=== RÉSUMÉ ===")
    print(f"F1 moyen (seuil 0.5)     = {df_res['f1_default_05'].mean():.4f} "
          f"+/- {df_res['f1_default_05'].std():.4f}")
    print(f"F1 moyen (seuil optimal) = {df_res['f1_optimal'].mean():.4f} "
          f"+/- {df_res['f1_optimal'].std():.4f}")
    print(f"AUC moyen                = {df_res['roc_auc'].mean():.4f} "
          f"+/- {df_res['roc_auc'].std():.4f}")
    print(f"Average Precision moyen  = {df_res['avg_precision'].mean():.4f} "
          f"+/- {df_res['avg_precision'].std():.4f}")
    print(f"Overfit gap moyen        = {df_res['overfit_gap'].mean():+.4f} "
          f"(train F1 - test F1)")

    df_res.to_csv(RESULTS_DIR / "loho_cv_results.csv", index=False)
    summary = {
        "method": "Leave-One-Host-Out CV (4 folds)",
        "f1_05_mean": float(df_res["f1_default_05"].mean()),
        "f1_05_std": float(df_res["f1_default_05"].std()),
        "f1_optimal_mean": float(df_res["f1_optimal"].mean()),
        "f1_optimal_std": float(df_res["f1_optimal"].std()),
        "roc_auc_mean": float(df_res["roc_auc"].mean()),
        "roc_auc_std": float(df_res["roc_auc"].std()),
        "ap_mean": float(df_res["avg_precision"].mean()),
        "ap_std": float(df_res["avg_precision"].std()),
        "overfit_gap_mean": float(df_res["overfit_gap"].mean()),
        "per_host": results,
    }
    with open(RESULTS_DIR / "loho_cv_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[OK] {RESULTS_DIR / 'loho_cv_results.csv'}")
    print(f"[OK] {RESULTS_DIR / 'loho_cv_summary.json'}")


if __name__ == "__main__":
    main()
