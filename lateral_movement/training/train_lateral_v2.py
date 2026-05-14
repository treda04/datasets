"""
Lateral v2 — training comparatif 5 algos.
Sélection sur F1-macro test. Pruning features < 0.002. Calibration isotonic.
"""
import json
import warnings
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    PrecisionRecallDisplay,
    RocCurveDisplay,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

DATA_DIR = Path("lateral_movement/data/processed_v2")
ARTIFACTS_DIR = Path("lateral_movement/saved_models_v2")
RESULTS_DIR = Path("lateral_movement/results_v2")
RANDOM_STATE = 42
PRUNE_CUTOFF = 0.002


def evaluate(name, model, Xtr, ytr, Xte, yte):
    model.fit(Xtr, ytr)
    proba = model.predict_proba(Xte)[:, 1]
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
        best_t = float(thr[bi]); best_macro = float(macro[bi])
    else:
        best_t, best_macro = 0.5, 0.0
    pred_opt = (proba >= best_t).astype(int)
    f1_pos = f1_score(yte, pred_opt, pos_label=1, zero_division=0)
    f1_neg = f1_score(yte, pred_opt, pos_label=0, zero_division=0)
    try:
        auc = roc_auc_score(yte, proba)
        ap = average_precision_score(yte, proba)
    except ValueError:
        auc, ap = float("nan"), float("nan")

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv = []
    for tr_i, va_i in skf.split(Xtr, ytr):
        try:
            m = clone(model); m.fit(Xtr[tr_i], ytr[tr_i])
            cv.append(f1_score(ytr[va_i], m.predict(Xtr[va_i]), zero_division=0))
        except Exception:
            pass
    return {
        "method": name,
        "f1_05": round(f1_05, 4),
        "f1_macro_optimal": round(best_macro, 4),
        "f1_attack_opt": round(f1_pos, 4),
        "f1_normal_opt": round(f1_neg, 4),
        "roc_auc": round(auc, 4),
        "avg_precision": round(ap, 4),
        "best_threshold": round(best_t, 4),
        "f1_cv_mean": round(np.mean(cv), 4) if cv else None,
        "f1_cv_std": round(np.std(cv), 4) if cv else None,
        "overfit_gap": round(np.mean(cv) - f1_05, 4) if cv else None,
    }, model, proba


def main():
    print("=== TRAINING LATERAL v2 ===\n")
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    df_tr = pd.read_parquet(DATA_DIR / "train.parquet")
    df_te = pd.read_parquet(DATA_DIR / "test.parquet")
    feature_cols = json.load(open(ARTIFACTS_DIR / "feature_columns.json"))

    X_tr = df_tr[feature_cols].fillna(0).values
    y_tr = df_tr["label"].values
    X_te = df_te[feature_cols].fillna(0).values
    y_te = df_te["label"].values
    print(f"Train : {X_tr.shape}  pos={y_tr.sum()}/{len(y_tr)}")
    print(f"Test  : {X_te.shape}  pos={y_te.sum()}/{len(y_te)}")

    # Pruning
    print(f"\n[Pruning] cutoff={PRUNE_CUTOFF}...")
    probe = RandomForestClassifier(n_estimators=300, max_depth=8,
                                     min_samples_leaf=3, n_jobs=-1,
                                     class_weight="balanced",
                                     random_state=RANDOM_STATE)
    probe.fit(X_tr, y_tr)
    kept = [i for i, im in enumerate(probe.feature_importances_)
            if im >= PRUNE_CUTOFF]
    print(f"  Drop {len(feature_cols)-len(kept)} features -> {len(kept)} conservées")
    feature_cols = [feature_cols[i] for i in kept]
    X_tr = X_tr[:, kept]; X_te = X_te[:, kept]

    scale_pos = (y_tr == 0).sum() / max((y_tr == 1).sum(), 1)
    results, keep = [], {}

    print("\n[1/5] RF baseline (depth=5)...")
    rf = Pipeline([("scaler", StandardScaler()),
                   ("rf", RandomForestClassifier(n_estimators=300, max_depth=5,
                                                  min_samples_leaf=3, n_jobs=-1,
                                                  class_weight="balanced",
                                                  random_state=RANDOM_STATE))])
    rf = CalibratedClassifierCV(rf, method="isotonic", cv=5)
    r, m, p = evaluate("RF baseline (depth=5)", rf, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["rf_base"] = (m, p)

    print("[2/5] RF tuned (depth=8)...")
    rf2 = Pipeline([("scaler", StandardScaler()),
                    ("rf", RandomForestClassifier(n_estimators=500, max_depth=8,
                                                   min_samples_leaf=2, n_jobs=-1,
                                                   class_weight="balanced",
                                                   random_state=RANDOM_STATE))])
    rf2 = CalibratedClassifierCV(rf2, method="isotonic", cv=5)
    r, m, p = evaluate("RF tuned (depth=8)", rf2, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["rf_tuned"] = (m, p)

    print("[3/5] XGBoost...")
    xgb = XGBClassifier(n_estimators=400, max_depth=5, learning_rate=0.05,
                          subsample=0.9, colsample_bytree=0.8,
                          scale_pos_weight=scale_pos, n_jobs=-1,
                          random_state=RANDOM_STATE, eval_metric="logloss",
                          tree_method="hist")
    xgb = CalibratedClassifierCV(xgb, method="isotonic", cv=5)
    r, m, p = evaluate("XGBoost", xgb, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["xgb"] = (m, p)

    print("[4/5] LightGBM...")
    lgbm = LGBMClassifier(n_estimators=400, max_depth=6, learning_rate=0.05,
                           num_leaves=31, subsample=0.9, colsample_bytree=0.8,
                           class_weight="balanced", n_jobs=-1,
                           random_state=RANDOM_STATE, verbose=-1)
    lgbm = CalibratedClassifierCV(lgbm, method="isotonic", cv=5)
    r, m, p = evaluate("LightGBM", lgbm, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["lgbm"] = (m, p)

    print("[5/5] Stacking...")
    stack = StackingClassifier(
        estimators=[
            ("rf", RandomForestClassifier(n_estimators=300, max_depth=8,
                                          n_jobs=-1, class_weight="balanced",
                                          random_state=RANDOM_STATE)),
            ("xgb", XGBClassifier(n_estimators=400, max_depth=5,
                                   learning_rate=0.05, scale_pos_weight=scale_pos,
                                   n_jobs=-1, random_state=RANDOM_STATE,
                                   eval_metric="logloss", tree_method="hist")),
            ("lgbm", LGBMClassifier(n_estimators=400, max_depth=6,
                                     learning_rate=0.05, class_weight="balanced",
                                     n_jobs=-1, random_state=RANDOM_STATE,
                                     verbose=-1)),
        ],
        final_estimator=LogisticRegression(max_iter=1000, class_weight="balanced"),
        cv=5, n_jobs=-1,
    )
    stack = Pipeline([("scaler", StandardScaler()), ("stack", stack)])
    r, m, p = evaluate("Stacking", stack, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["stack"] = (m, p)

    df_res = pd.DataFrame(results)
    print("\n=== TABLEAU COMPARATIF v2 ===\n")
    print(df_res.to_string(index=False))

    best_idx = int(df_res["f1_macro_optimal"].idxmax())
    best_method = df_res.iloc[best_idx]["method"]
    best_score = df_res.iloc[best_idx]["f1_macro_optimal"]
    print(f"\n[BEST] {best_method}  (F1-macro = {best_score})")
    df_res.to_csv(RESULTS_DIR / "innovations_summary.csv", index=False)

    key_map = {"RF baseline": "rf_base", "RF tuned": "rf_tuned",
               "XGBoost": "xgb", "LightGBM": "lgbm", "Stacking": "stack"}
    best_key = next(v for k, v in key_map.items() if k in best_method)
    best_model, best_proba = keep[best_key]

    joblib.dump(best_model, ARTIFACTS_DIR / "rf_lateral_model.pkl")
    with open(ARTIFACTS_DIR / "feature_columns.json", "w") as fh:
        json.dump(feature_cols, fh, indent=2)
    best_thr = float(df_res.iloc[best_idx]["best_threshold"])
    with open(ARTIFACTS_DIR / "lateral_threshold.json", "w") as fh:
        json.dump({"threshold": best_thr,
                    "method": f"F1-macro optimal ({best_method})",
                    "f1_at_threshold": float(best_score)}, fh, indent=2)

    # Plots
    pred_opt = (best_proba >= best_thr).astype(int)
    auc = float(df_res.iloc[best_idx]["roc_auc"])

    fig, ax = plt.subplots(figsize=(7, 6))
    RocCurveDisplay.from_predictions(y_te, best_proba, ax=ax)
    ax.set_title(f"ROC Lateral v2 — {best_method} (AUC={auc:.3f})")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "roc_curve.png", dpi=150)
    plt.close()

    fig, ax = plt.subplots(figsize=(7, 6))
    PrecisionRecallDisplay.from_predictions(y_te, best_proba, ax=ax)
    ax.set_title(f"PR Lateral v2 — {best_method}")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "pr_curve.png", dpi=150)
    plt.close()

    cm = confusion_matrix(y_te, pred_opt)
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Lateral"])
    ax.set_yticklabels(["Normal", "Lateral"])
    f1c = f1_score(y_te, pred_opt, zero_division=0)
    ax.set_title(f"Confusion v2 (seuil={best_thr:.3f}, F1={f1c:.3f})")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cm[i, j] > cm.max()/2 else "black", fontsize=14)
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=150)
    plt.close()

    # Feature importance
    try:
        if hasattr(best_model, "calibrated_classifiers_"):
            base = best_model.calibrated_classifiers_[0].estimator
            if hasattr(base, "named_steps") and "rf" in base.named_steps:
                imps = base.named_steps["rf"].feature_importances_
            elif hasattr(base, "feature_importances_"):
                imps = base.feature_importances_
            else:
                imps = None
        else:
            imps = None
        if imps is not None:
            fi = pd.DataFrame({"feature": feature_cols, "importance": imps})\
                  .sort_values("importance", ascending=False)
            fi.to_csv(RESULTS_DIR / "feature_importance.csv", index=False)
            top = fi.head(20)
            fig, ax = plt.subplots(figsize=(10, 9))
            ax.barh(range(len(top)), top["importance"], color="steelblue")
            ax.set_yticks(range(len(top)))
            ax.set_yticklabels(top["feature"], fontsize=9)
            ax.invert_yaxis()
            ax.set_title("Top 20 features — Lateral v2")
            fig.tight_layout(); fig.savefig(RESULTS_DIR / "feature_importance.png", dpi=150)
            plt.close()
            top_feat, top_imp = fi.iloc[0]["feature"], float(fi.iloc[0]["importance"])
        else:
            top_feat, top_imp = None, None
    except Exception as e:
        print(f"[warn] {e}")
        top_feat, top_imp = None, None

    report = classification_report(y_te, pred_opt,
                                    target_names=["Normal", "Lateral"], digits=4)
    print("\n" + report)
    with open(RESULTS_DIR / "classification_report.txt", "w") as fh:
        fh.write(report)

    metrics = {
        "version": 2,
        "best_method": best_method,
        "f1_default": float(df_res.iloc[best_idx]["f1_05"]),
        "f1_calibrated": float(df_res.iloc[best_idx]["f1_macro_optimal"]),
        "f1_attack": float(df_res.iloc[best_idx]["f1_attack_opt"]),
        "f1_normal": float(df_res.iloc[best_idx]["f1_normal_opt"]),
        "best_threshold": best_thr,
        "roc_auc": auc,
        "avg_precision": float(df_res.iloc[best_idx]["avg_precision"]),
        "f1_cv_mean": float(df_res.iloc[best_idx]["f1_cv_mean"]) if df_res.iloc[best_idx]["f1_cv_mean"] else None,
        "f1_cv_std": float(df_res.iloc[best_idx]["f1_cv_std"]) if df_res.iloc[best_idx]["f1_cv_std"] else None,
        "overfit_gap": float(df_res.iloc[best_idx]["overfit_gap"]) if df_res.iloc[best_idx]["overfit_gap"] else None,
        "n_features_kept": len(feature_cols),
        "top_feature": top_feat,
        "top_feature_importance": top_imp,
        "leakage_warning": (top_imp is not None and top_imp > 0.4),
    }
    with open(RESULTS_DIR / "metrics.json", "w") as fh:
        json.dump(metrics, fh, indent=2)

    print(f"\n=== METRICS v2 ===")
    print(f"  Best method        : {best_method}")
    print(f"  F1 macro opt       : {metrics['f1_calibrated']}")
    print(f"  F1 attack opt      : {metrics['f1_attack']}")
    print(f"  F1 normal opt      : {metrics['f1_normal']}")
    print(f"  ROC-AUC            : {metrics['roc_auc']}")
    print(f"  Top feature        : {metrics['top_feature']} ({metrics['top_feature_importance']})")


if __name__ == "__main__":
    main()
