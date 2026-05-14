"""SIEM v4 — LOOHO CV avec LightGBM (best model)."""
import json
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)

warnings.filterwarnings("ignore")

DATA = Path("siem_windows/data/processed_v4")
RES = Path("siem_windows/results_v4")
ART = Path("siem_windows/saved_models_v4")
RES.mkdir(exist_ok=True, parents=True)
RANDOM_STATE = 42


def main():
    df_tr = pd.read_parquet(DATA / "train.parquet")
    df_te = pd.read_parquet(DATA / "test.parquet")
    df_all = pd.concat([df_tr, df_te], ignore_index=True)
    fc = json.load(open(ART / "feature_columns.json"))

    X = df_all[fc].fillna(0).values
    y = df_all["label"].values
    hosts = df_all["host"].values
    unique_hosts = sorted(set(hosts))
    print(f"LOOHO v4 : {unique_hosts}, total {len(df_all)} fenêtres")

    results = []
    for held in unique_hosts:
        tr_m = hosts != held
        te_m = hosts == held
        Xtr, Xte = X[tr_m], X[te_m]
        ytr, yte = y[tr_m], y[te_m]

        scale_pos = (ytr == 0).sum() / max((ytr == 1).sum(), 1)
        base = LGBMClassifier(
            n_estimators=400, max_depth=6, learning_rate=0.05,
            num_leaves=31, subsample=0.9, colsample_bytree=0.8,
            class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE,
            verbose=-1,
        )
        m = CalibratedClassifierCV(base, method="isotonic", cv=5)
        m.fit(Xtr, ytr)
        proba = m.predict_proba(Xte)[:, 1]
        pred05 = (proba >= 0.5).astype(int)
        f1_05 = f1_score(yte, pred05, zero_division=0)

        prec, rec, thr = precision_recall_curve(yte, proba)
        macro = []
        for t in thr:
            p = (proba >= t).astype(int)
            macro.append((f1_score(yte, p, pos_label=1, zero_division=0)
                          + f1_score(yte, p, pos_label=0, zero_division=0)) / 2)
        if macro:
            bi = int(np.argmax(macro))
            best_t = float(thr[bi])
            best_macro = float(macro[bi])
        else:
            best_t, best_macro = 0.5, 0.0
        try:
            auc = roc_auc_score(yte, proba)
            ap = average_precision_score(yte, proba)
        except ValueError:
            auc, ap = float("nan"), float("nan")

        f1_train = f1_score(ytr, (m.predict_proba(Xtr)[:, 1] >= 0.5).astype(int),
                             zero_division=0)
        results.append({
            "held_out_host": held,
            "n_train": int(tr_m.sum()),
            "n_test": int(te_m.sum()),
            "n_test_positive": int(yte.sum()),
            "f1_05": float(f1_05),
            "f1_macro_optimal": float(best_macro),
            "best_threshold": best_t,
            "roc_auc": float(auc),
            "avg_precision": float(ap),
            "f1_train_05": float(f1_train),
            "overfit_gap": float(f1_train - f1_05),
        })
        print(f"Test={held:30s}  F1@0.5={f1_05:.3f}  F1_macro={best_macro:.3f}  "
              f"AUC={auc:.3f}  gap={f1_train-f1_05:+.3f}")

    dfr = pd.DataFrame(results)
    print("\n=== RÉSUMÉ LOOHO v4 ===")
    for col in ["f1_05", "f1_macro_optimal", "roc_auc", "avg_precision"]:
        print(f"  {col:25s} = {dfr[col].mean():.4f} +/- {dfr[col].std():.4f}")
    print(f"  overfit_gap moyen        = {dfr['overfit_gap'].mean():+.4f}")

    dfr.to_csv(RES / "loho_cv_results.csv", index=False)
    summary = {
        "method": "LOOHO 4 folds (LightGBM v4)",
        "f1_05_mean": float(dfr["f1_05"].mean()),
        "f1_05_std": float(dfr["f1_05"].std()),
        "f1_macro_mean": float(dfr["f1_macro_optimal"].mean()),
        "f1_macro_std": float(dfr["f1_macro_optimal"].std()),
        "roc_auc_mean": float(dfr["roc_auc"].mean()),
        "roc_auc_std": float(dfr["roc_auc"].std()),
        "ap_mean": float(dfr["avg_precision"].mean()),
        "ap_std": float(dfr["avg_precision"].std()),
        "overfit_gap_mean": float(dfr["overfit_gap"].mean()),
        "per_host": results,
    }
    with open(RES / "loho_cv_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nOK -> {RES}/loho_cv_results.csv")
    print(f"OK -> {RES}/loho_cv_summary.json")


if __name__ == "__main__":
    main()
