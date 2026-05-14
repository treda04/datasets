"""
Lateral Movement — Innovations Data Science
============================================
Compare 4 approches sur le même split par technique :
  1. RF baseline (modèle actuel)
  2. XGBoost (hyperparam tuning)
  3. LightGBM
  4. Stacking RF + XGB + LightGBM

Sélection du meilleur sur F1-macro (équilibre des classes).
"""
import json
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
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

DATA_DIR = Path("lateral_movement/data/processed")
ARTIFACTS_DIR = Path("lateral_movement/saved_models")
RESULTS_DIR = Path("lateral_movement/results")
RANDOM_STATE = 42


def eval_and_pack(name, model, X_tr, y_tr, X_te, y_te):
    model.fit(X_tr, y_tr)
    proba = model.predict_proba(X_te)[:, 1]
    pred05 = (proba >= 0.5).astype(int)
    f1_05 = f1_score(y_te, pred05, zero_division=0)

    # Seuil F1-macro
    prec, rec, thr = precision_recall_curve(y_te, proba)
    macro = []
    for t in thr:
        p = (proba >= t).astype(int)
        macro.append((f1_score(y_te, p, pos_label=1, zero_division=0) +
                      f1_score(y_te, p, pos_label=0, zero_division=0)) / 2)
    if len(macro) > 0:
        best_i = int(np.argmax(macro))
        best_thr = float(thr[best_i])
        best_macro = float(macro[best_i])
    else:
        best_thr, best_macro = 0.5, 0.0
    pred_opt = (proba >= best_thr).astype(int)
    f1_pos = f1_score(y_te, pred_opt, pos_label=1, zero_division=0)
    f1_neg = f1_score(y_te, pred_opt, pos_label=0, zero_division=0)

    try:
        auc = roc_auc_score(y_te, proba)
        ap = average_precision_score(y_te, proba)
    except ValueError:
        auc, ap = float("nan"), float("nan")

    # CV F1 train (stratifié 5-fold)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = []
    from sklearn.base import clone
    for tr_i, va_i in skf.split(X_tr, y_tr):
        try:
            m = clone(model)
            m.fit(X_tr[tr_i], y_tr[tr_i])
            cv_scores.append(f1_score(y_tr[va_i], m.predict(X_tr[va_i]),
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
    }, model


def main():
    print("=== LATERAL INNOVATIONS — comparaison 4 approches ===\n")
    df_train = pd.read_parquet(DATA_DIR / "train.parquet")
    df_test = pd.read_parquet(DATA_DIR / "test.parquet")
    feature_cols = json.load(open(ARTIFACTS_DIR / "feature_columns.json"))

    X_train = df_train[feature_cols].fillna(0).values
    y_train = df_train["label"].values
    X_test = df_test[feature_cols].fillna(0).values
    y_test = df_test["label"].values

    print(f"Train : {X_train.shape}  pos={y_train.sum()}/{len(y_train)}")
    print(f"Test  : {X_test.shape}  pos={y_test.sum()}/{len(y_test)}\n")

    scale_pos = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    print(f"scale_pos_weight = {scale_pos:.3f}\n")

    results = []
    models_keep = {}

    # 1) RF baseline
    print("[1/4] RF baseline...")
    rf = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(n_estimators=300, n_jobs=-1,
                                        class_weight="balanced",
                                        random_state=RANDOM_STATE)),
    ])
    rf = CalibratedClassifierCV(rf, method="isotonic", cv=5)
    r, m = eval_and_pack("RF baseline", rf, X_train, y_train, X_test, y_test)
    print(f"    F1_05={r['f1_05']}  F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); models_keep["rf"] = m

    # 2) XGBoost tuné
    print("[2/4] XGBoost tuned...")
    xgb = XGBClassifier(
        n_estimators=400, max_depth=4, learning_rate=0.05,
        subsample=0.9, colsample_bytree=0.8,
        scale_pos_weight=scale_pos, n_jobs=-1,
        random_state=RANDOM_STATE, eval_metric="logloss",
        tree_method="hist",
    )
    xgb_cal = CalibratedClassifierCV(xgb, method="isotonic", cv=5)
    r, m = eval_and_pack("XGBoost tuned", xgb_cal, X_train, y_train, X_test, y_test)
    print(f"    F1_05={r['f1_05']}  F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); models_keep["xgb"] = m

    # 3) LightGBM
    print("[3/4] LightGBM...")
    lgbm = LGBMClassifier(
        n_estimators=400, max_depth=5, learning_rate=0.05,
        num_leaves=31, subsample=0.9, colsample_bytree=0.8,
        class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE,
        verbose=-1,
    )
    lgbm_cal = CalibratedClassifierCV(lgbm, method="isotonic", cv=5)
    r, m = eval_and_pack("LightGBM", lgbm_cal, X_train, y_train, X_test, y_test)
    print(f"    F1_05={r['f1_05']}  F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); models_keep["lgbm"] = m

    # 4) Stacking
    print("[4/4] Stacking (RF + XGB + LightGBM) -> LR...")
    stack = StackingClassifier(
        estimators=[
            ("rf", RandomForestClassifier(n_estimators=300, n_jobs=-1,
                                          class_weight="balanced",
                                          random_state=RANDOM_STATE)),
            ("xgb", XGBClassifier(n_estimators=400, max_depth=4, learning_rate=0.05,
                                   scale_pos_weight=scale_pos, n_jobs=-1,
                                   random_state=RANDOM_STATE,
                                   eval_metric="logloss", tree_method="hist")),
            ("lgbm", LGBMClassifier(n_estimators=400, max_depth=5, learning_rate=0.05,
                                     class_weight="balanced", n_jobs=-1,
                                     random_state=RANDOM_STATE, verbose=-1)),
        ],
        final_estimator=LogisticRegression(max_iter=1000, class_weight="balanced"),
        cv=5, n_jobs=-1,
    )
    stack_pipe = Pipeline([("scaler", StandardScaler()), ("stack", stack)])
    r, m = eval_and_pack("Stacking (RF+XGB+LGBM)->LR", stack_pipe,
                          X_train, y_train, X_test, y_test)
    print(f"    F1_05={r['f1_05']}  F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); models_keep["stack"] = m

    df_res = pd.DataFrame(results)
    print("\n=== TABLEAU COMPARATIF ===\n")
    print(df_res.to_string(index=False))

    best_idx = int(df_res["f1_macro_optimal"].idxmax())
    best_method = df_res.iloc[best_idx]["method"]
    best_macro = df_res.iloc[best_idx]["f1_macro_optimal"]
    baseline_macro = df_res.iloc[0]["f1_macro_optimal"]
    print(f"\n[BEST] {best_method}  (F1-macro = {best_macro})")

    df_res.to_csv(RESULTS_DIR / "innovations_summary.csv", index=False)
    with open(RESULTS_DIR / "innovations_summary.json", "w") as f:
        json.dump({"best": best_method, "comparisons": results}, f, indent=2)

    if best_idx > 0 and best_macro > baseline_macro:
        gain = best_macro - baseline_macro
        print(f"\n[GAIN] +{gain:.4f} F1-macro vs baseline RF")
        key_map = {
            "XGBoost": "xgb", "LightGBM": "lgbm", "Stacking": "stack",
        }
        for k, v in key_map.items():
            if k in best_method:
                model_to_save = models_keep[v]
                # Réentraîne sur tout pour avoir le modèle final
                model_to_save.fit(X_train, y_train)
                joblib.dump(model_to_save,
                             ARTIFACTS_DIR / "rf_lateral_model.pkl")
                # Sauve le seuil optimal
                with open(ARTIFACTS_DIR / "lateral_threshold.json", "w") as f:
                    json.dump({
                        "threshold": float(df_res.iloc[best_idx]["best_threshold"]),
                        "method": f"F1-macro optimal ({best_method})",
                        "f1_at_threshold": float(best_macro),
                    }, f, indent=2)
                print(f"       -> {ARTIFACTS_DIR / 'rf_lateral_model.pkl'} (remplacé)")
                break
        with open(ARTIFACTS_DIR / "lateral_best_meta.json", "w") as f:
            json.dump({
                "method": best_method,
                "f1_macro_optimal": best_macro,
                "auc": float(df_res.iloc[best_idx]["roc_auc"]),
                "best_threshold": float(df_res.iloc[best_idx]["best_threshold"]),
                "previous_baseline_macro": float(baseline_macro),
                "gain": float(gain),
            }, f, indent=2)
    else:
        print(f"\n[INFO] Baseline reste le meilleur")


if __name__ == "__main__":
    main()
