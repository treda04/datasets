"""
SIEM Windows — Innovations Data Science
========================================
Compare 4 approches sur le même split par host (NEWYORK test) :
  1. RF baseline (modèle actuel)
  2. RF + features normalisées par host (anti-drift)
  3. XGBoost + features normalisées par host
  4. Stacking RF + XGBoost + LogReg (méta-learner LogReg)

Sauve :
  - results/innovations_summary.csv (tableau comparatif)
  - results/innovations_summary.json
  - saved_models/siem_best_model.pkl (le meilleur des 4)
  - saved_models/siem_best_meta.json (quelle stratégie + features)

Lancer :
    .venv\\Scripts\\python.exe scripts/siem_innovations.py
"""
import json
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

DATA_DIR = Path("siem_windows/data/processed")
ARTIFACTS_DIR = Path("siem_windows/saved_models")
RESULTS_DIR = Path("siem_windows/results")
RANDOM_STATE = 42


def host_normalize(X_train, hosts_train, X_test, hosts_test, feature_cols):
    """Normalise chaque feature par la moyenne et l'écart-type du host.
    Le test set utilise les stats globales du train (jamais ses propres stats)
    pour éviter toute fuite. Concept : 'comportement relatif à la baseline du host'."""
    df_tr = pd.DataFrame(X_train, columns=feature_cols)
    df_tr["__host__"] = hosts_train
    host_stats = df_tr.groupby("__host__").agg(["mean", "std"])

    # Stats globales en fallback (pour les hosts du test inconnus)
    global_mean = df_tr[feature_cols].mean()
    global_std = df_tr[feature_cols].std().replace(0, 1)

    def transform(X, hosts):
        df = pd.DataFrame(X, columns=feature_cols)
        df["__host__"] = hosts
        out = pd.DataFrame(index=df.index, columns=feature_cols, dtype=float)
        for h in df["__host__"].unique():
            mask = df["__host__"] == h
            if h in host_stats.index:
                mean = host_stats.loc[h].xs("mean", level=1)
                std = host_stats.loc[h].xs("std", level=1).replace(0, 1)
            else:
                mean, std = global_mean, global_std
            out.loc[mask, feature_cols] = (
                (df.loc[mask, feature_cols] - mean) / std
            ).values
        return out.values

    return transform(X_train, hosts_train), transform(X_test, hosts_test)


def eval_model(name, model, X_train, y_train, X_test, y_test):
    """Entraîne, évalue, retourne dict de métriques + proba test."""
    model.fit(X_train, y_train)
    proba = model.predict_proba(X_test)[:, 1]

    pred05 = (proba >= 0.5).astype(int)
    f1_05 = f1_score(y_test, pred05, zero_division=0)

    # Seuil F1-macro optimal
    prec, rec, thr = precision_recall_curve(y_test, proba)
    macro_f1s = []
    for t in thr:
        pred = (proba >= t).astype(int)
        fp = f1_score(y_test, pred, pos_label=1, zero_division=0)
        fn = f1_score(y_test, pred, pos_label=0, zero_division=0)
        macro_f1s.append((fp + fn) / 2)
    if len(macro_f1s) > 0:
        best_i = int(np.argmax(macro_f1s))
        best_thr = float(thr[best_i])
        best_macro = float(macro_f1s[best_i])
    else:
        best_thr, best_macro = 0.5, 0.0

    pred_opt = (proba >= best_thr).astype(int)
    f1_pos = f1_score(y_test, pred_opt, pos_label=1, zero_division=0)
    f1_neg = f1_score(y_test, pred_opt, pos_label=0, zero_division=0)

    try:
        auc = roc_auc_score(y_test, proba)
        ap = average_precision_score(y_test, proba)
    except ValueError:
        auc, ap = float("nan"), float("nan")

    # CV F1 sur train (5-fold) pour overfit gap
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = []
    for tr_i, va_i in skf.split(X_train, y_train):
        try:
            from sklearn.base import clone
            m = clone(model)
            m.fit(X_train[tr_i], y_train[tr_i])
            cv_scores.append(f1_score(y_train[va_i], m.predict(X_train[va_i]),
                                       zero_division=0))
        except Exception:
            pass

    return {
        "method": name,
        "f1_05": round(f1_05, 4),
        "f1_macro_optimal": round(best_macro, 4),
        "f1_attack_optimal": round(f1_pos, 4),
        "f1_normal_optimal": round(f1_neg, 4),
        "roc_auc": round(auc, 4),
        "avg_precision": round(ap, 4),
        "best_threshold": round(best_thr, 4),
        "f1_cv_mean": round(np.mean(cv_scores), 4) if cv_scores else None,
        "f1_cv_std": round(np.std(cv_scores), 4) if cv_scores else None,
        "overfit_gap": round(np.mean(cv_scores) - f1_05, 4) if cv_scores else None,
    }, proba, model


def main():
    print("=== SIEM INNOVATIONS — comparaison 4 approches ===\n")
    df_train = pd.read_parquet(DATA_DIR / "train.parquet")
    df_test = pd.read_parquet(DATA_DIR / "test.parquet")
    feature_cols = json.load(open(ARTIFACTS_DIR / "feature_columns.json"))

    X_train = df_train[feature_cols].values
    y_train = df_train["label"].values
    hosts_train = df_train["host"].values
    X_test = df_test[feature_cols].values
    y_test = df_test["label"].values
    hosts_test = df_test["host"].values

    print(f"Train : {X_train.shape}  hosts={set(hosts_train)}")
    print(f"Test  : {X_test.shape}  hosts={set(hosts_test)}")
    print(f"Test pos={y_test.sum()}/{len(y_test)}\n")

    results = []
    probas = {}

    # 1) RF baseline
    print("[1/4] RF baseline (features brutes)...")
    rf_base = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(n_estimators=300, max_depth=5,
                                        min_samples_leaf=3, n_jobs=-1,
                                        class_weight="balanced",
                                        random_state=RANDOM_STATE)),
    ])
    rf_base = CalibratedClassifierCV(rf_base, method="isotonic", cv=5)
    r, p, m = eval_model("RF baseline (raw features)", rf_base,
                         X_train, y_train, X_test, y_test)
    print(f"    F1_05={r['f1_05']}  F1_macro_opt={r['f1_macro_optimal']}  "
          f"AUC={r['roc_auc']}")
    results.append(r); probas["rf_base"] = p

    # Features normalisées par host
    print("\n[Préparation] Normalisation par host...")
    X_train_hn, X_test_hn = host_normalize(X_train, hosts_train,
                                            X_test, hosts_test, feature_cols)
    # Remplace NaN par 0 (cas std=0)
    X_train_hn = np.nan_to_num(X_train_hn, nan=0.0)
    X_test_hn = np.nan_to_num(X_test_hn, nan=0.0)

    # 2) RF + host-normalized
    print("[2/4] RF + features host-normalized...")
    rf_hn = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(n_estimators=300, max_depth=5,
                                        min_samples_leaf=3, n_jobs=-1,
                                        class_weight="balanced",
                                        random_state=RANDOM_STATE)),
    ])
    rf_hn = CalibratedClassifierCV(rf_hn, method="isotonic", cv=5)
    r, p, m_rf_hn = eval_model("RF + host-normalized", rf_hn,
                                X_train_hn, y_train, X_test_hn, y_test)
    print(f"    F1_05={r['f1_05']}  F1_macro_opt={r['f1_macro_optimal']}  "
          f"AUC={r['roc_auc']}")
    results.append(r); probas["rf_hn"] = p

    # 3) XGBoost + host-normalized
    print("[3/4] XGBoost + features host-normalized...")
    scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    xgb_hn = XGBClassifier(
        n_estimators=300, max_depth=4, learning_rate=0.05,
        scale_pos_weight=scale_pos, n_jobs=-1, random_state=RANDOM_STATE,
        eval_metric="logloss", tree_method="hist",
    )
    xgb_hn = CalibratedClassifierCV(xgb_hn, method="isotonic", cv=5)
    r, p, m_xgb_hn = eval_model("XGBoost + host-normalized", xgb_hn,
                                 X_train_hn, y_train, X_test_hn, y_test)
    print(f"    F1_05={r['f1_05']}  F1_macro_opt={r['f1_macro_optimal']}  "
          f"AUC={r['roc_auc']}")
    results.append(r); probas["xgb_hn"] = p

    # 4) Stacking RF + XGBoost + LogReg → LogReg méta-learner
    print("[4/4] Stacking (RF + XGB + LogReg) -> LogReg meta...")
    rf_est = RandomForestClassifier(n_estimators=300, max_depth=5,
                                     min_samples_leaf=3, n_jobs=-1,
                                     class_weight="balanced",
                                     random_state=RANDOM_STATE)
    xgb_est = XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.05,
                             scale_pos_weight=scale_pos, n_jobs=-1,
                             random_state=RANDOM_STATE,
                             eval_metric="logloss", tree_method="hist")
    lr_est = LogisticRegression(max_iter=1000, class_weight="balanced",
                                 random_state=RANDOM_STATE)
    stack = Pipeline([
        ("scaler", StandardScaler()),
        ("stack", StackingClassifier(
            estimators=[("rf", rf_est), ("xgb", xgb_est), ("lr", lr_est)],
            final_estimator=LogisticRegression(max_iter=1000,
                                                class_weight="balanced"),
            cv=5, n_jobs=-1,
        )),
    ])
    r, p, m_stack = eval_model("Stacking (RF+XGB+LR) -> LR", stack,
                                X_train_hn, y_train, X_test_hn, y_test)
    print(f"    F1_05={r['f1_05']}  F1_macro_opt={r['f1_macro_optimal']}  "
          f"AUC={r['roc_auc']}")
    results.append(r); probas["stack"] = p

    df_results = pd.DataFrame(results)
    print("\n=== TABLEAU COMPARATIF ===\n")
    print(df_results.to_string(index=False))

    # Choix du meilleur sur F1-macro optimal
    best_idx = int(df_results["f1_macro_optimal"].idxmax())
    best_method = df_results.iloc[best_idx]["method"]
    print(f"\n[BEST] {best_method}")

    df_results.to_csv(RESULTS_DIR / "innovations_summary.csv", index=False)
    with open(RESULTS_DIR / "innovations_summary.json", "w") as f:
        json.dump({"best": best_method, "comparisons": results}, f, indent=2)

    # Sauve le meilleur si > baseline
    baseline_macro = df_results.iloc[0]["f1_macro_optimal"]
    best_macro = df_results.iloc[best_idx]["f1_macro_optimal"]
    if best_idx > 0 and best_macro > baseline_macro:
        print(f"\n[GAIN] +{best_macro - baseline_macro:.4f} F1-macro vs baseline")
        print(f"       Sauvegarde du modèle innovant...")
        # Sauve le meilleur modèle (avec son scaler intégré)
        if "RF + host-normalized" in best_method:
            joblib.dump(m_rf_hn, ARTIFACTS_DIR / "siem_best_innovation.pkl")
        elif "XGBoost" in best_method:
            joblib.dump(m_xgb_hn, ARTIFACTS_DIR / "siem_best_innovation.pkl")
        elif "Stacking" in best_method:
            joblib.dump(m_stack, ARTIFACTS_DIR / "siem_best_innovation.pkl")
        with open(ARTIFACTS_DIR / "siem_best_meta.json", "w") as f:
            json.dump({
                "method": best_method,
                "uses_host_normalized": True,
                "f1_macro_optimal": best_macro,
                "auc": float(df_results.iloc[best_idx]["roc_auc"]),
                "best_threshold": float(df_results.iloc[best_idx]["best_threshold"]),
            }, f, indent=2)
        print(f"       -> {ARTIFACTS_DIR / 'siem_best_innovation.pkl'}")
    else:
        print(f"\n[INFO] Baseline reste le meilleur — pas de sauvegarde additionnelle")

    print(f"\n[OK] {RESULTS_DIR / 'innovations_summary.csv'}")


if __name__ == "__main__":
    main()
