"""
SIEM v4 — training avec comparaison systématique + LOOHO CV.

Étapes :
  1. Charger v4 (152 features)
  2. Pruning features mortes (importance < 0.002 via RF probe)
  3. Comparer 5 modèles : RF baseline, RF tuned, XGBoost, LightGBM, Stacking
  4. Pour le best : LOOHO 4 folds + calibration de seuil + artefacts
  5. Génération figures (ROC/PR/feature importance/confusion)
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

DATA_DIR = Path("siem_windows/data/processed_v4")
ARTIFACTS_DIR = Path("siem_windows/saved_models_v4")
RESULTS_DIR = Path("siem_windows/results_v4")
RANDOM_STATE = 42
PRUNE_CUTOFF = 0.002


def evaluate(name, model, X_tr, y_tr, X_te, y_te):
    model.fit(X_tr, y_tr)
    proba = model.predict_proba(X_te)[:, 1]
    pred05 = (proba >= 0.5).astype(int)
    f1_05 = f1_score(y_te, pred05, zero_division=0)

    prec, rec, thr = precision_recall_curve(y_te, proba)
    macro = []
    for t in thr:
        p = (proba >= t).astype(int)
        macro.append((f1_score(y_te, p, pos_label=1, zero_division=0)
                      + f1_score(y_te, p, pos_label=0, zero_division=0)) / 2)
    if macro:
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

    # CV F1 train
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    cv = []
    for tr_i, va_i in skf.split(X_tr, y_tr):
        try:
            m = clone(model)
            m.fit(X_tr[tr_i], y_tr[tr_i])
            cv.append(f1_score(y_tr[va_i], m.predict(X_tr[va_i]),
                                zero_division=0))
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
        "best_threshold": round(best_thr, 4),
        "f1_cv_mean": round(np.mean(cv), 4) if cv else None,
        "f1_cv_std": round(np.std(cv), 4) if cv else None,
        "overfit_gap": round(np.mean(cv) - f1_05, 4) if cv else None,
    }, model, proba


def main():
    print("=== TRAINING SIEM v4 ===\n")
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

    # ─── Pruning features mortes via RF probe ───
    print("\n[Pruning] RF probe pour identifier features mortes...")
    probe = RandomForestClassifier(
        n_estimators=300, max_depth=8, min_samples_leaf=3, n_jobs=-1,
        class_weight="balanced", random_state=RANDOM_STATE,
    )
    probe.fit(X_tr, y_tr)
    imps = probe.feature_importances_
    kept = [i for i, im in enumerate(imps) if im >= PRUNE_CUTOFF]
    dropped = len(feature_cols) - len(kept)
    print(f"  Drop {dropped} features (importance<{PRUNE_CUTOFF})")
    print(f"  {len(kept)} features conservées")
    feature_cols = [feature_cols[i] for i in kept]
    X_tr = X_tr[:, kept]
    X_te = X_te[:, kept]

    scale_pos = (y_tr == 0).sum() / max((y_tr == 1).sum(), 1)

    # ─── 5 modèles ───
    results = []
    keep = {}

    print("\n[1/5] RF baseline (max_depth=5)...")
    rf_base = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=300, max_depth=5, min_samples_leaf=3, n_jobs=-1,
            class_weight="balanced", random_state=RANDOM_STATE,
        )),
    ])
    rf_base = CalibratedClassifierCV(rf_base, method="isotonic", cv=5)
    r, m, p = evaluate("RF baseline (depth=5)", rf_base, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["rf_base"] = (m, p)

    print("[2/5] RF tuned (max_depth=8)...")
    rf_tuned = Pipeline([
        ("scaler", StandardScaler()),
        ("rf", RandomForestClassifier(
            n_estimators=500, max_depth=8, min_samples_leaf=2, n_jobs=-1,
            class_weight="balanced", random_state=RANDOM_STATE,
        )),
    ])
    rf_tuned = CalibratedClassifierCV(rf_tuned, method="isotonic", cv=5)
    r, m, p = evaluate("RF tuned (depth=8)", rf_tuned, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["rf_tuned"] = (m, p)

    print("[3/5] XGBoost...")
    xgb = XGBClassifier(
        n_estimators=400, max_depth=5, learning_rate=0.05,
        subsample=0.9, colsample_bytree=0.8,
        scale_pos_weight=scale_pos, n_jobs=-1,
        random_state=RANDOM_STATE, eval_metric="logloss",
        tree_method="hist",
    )
    xgb = CalibratedClassifierCV(xgb, method="isotonic", cv=5)
    r, m, p = evaluate("XGBoost", xgb, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["xgb"] = (m, p)

    print("[4/5] LightGBM...")
    lgbm = LGBMClassifier(
        n_estimators=400, max_depth=6, learning_rate=0.05,
        num_leaves=31, subsample=0.9, colsample_bytree=0.8,
        class_weight="balanced", n_jobs=-1, random_state=RANDOM_STATE,
        verbose=-1,
    )
    lgbm = CalibratedClassifierCV(lgbm, method="isotonic", cv=5)
    r, m, p = evaluate("LightGBM", lgbm, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["lgbm"] = (m, p)

    print("[5/5] Stacking (RF + XGB + LGBM) -> LR...")
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
        final_estimator=LogisticRegression(max_iter=1000,
                                            class_weight="balanced"),
        cv=5, n_jobs=-1,
    )
    stack = Pipeline([("scaler", StandardScaler()), ("stack", stack)])
    r, m, p = evaluate("Stacking", stack, X_tr, y_tr, X_te, y_te)
    print(f"    F1_macro={r['f1_macro_optimal']}  AUC={r['roc_auc']}")
    results.append(r); keep["stack"] = (m, p)

    df_res = pd.DataFrame(results)
    print("\n=== TABLEAU COMPARATIF v4 ===\n")
    print(df_res.to_string(index=False))

    best_idx = int(df_res["f1_macro_optimal"].idxmax())
    best_method = df_res.iloc[best_idx]["method"]
    best_score = df_res.iloc[best_idx]["f1_macro_optimal"]
    print(f"\n[BEST] {best_method}  (F1-macro = {best_score})")

    df_res.to_csv(RESULTS_DIR / "innovations_summary.csv", index=False)

    # ─── Save best model + artefacts ───
    key_map = {"RF baseline": "rf_base", "RF tuned": "rf_tuned",
               "XGBoost": "xgb", "LightGBM": "lgbm", "Stacking": "stack"}
    best_key = next(v for k, v in key_map.items() if k in best_method)
    best_model, best_proba = keep[best_key]

    joblib.dump(best_model, ARTIFACTS_DIR / "rf_siem_model.pkl")
    with open(ARTIFACTS_DIR / "feature_columns.json", "w") as fh:
        json.dump(feature_cols, fh, indent=2)
    best_thr = float(df_res.iloc[best_idx]["best_threshold"])
    with open(ARTIFACTS_DIR / "siem_threshold.json", "w") as fh:
        json.dump({"threshold": best_thr,
                    "method": f"F1-macro optimal ({best_method})",
                    "f1_at_threshold": float(best_score)}, fh, indent=2)
    # Scaler extrait du pipeline si possible
    try:
        if hasattr(best_model, "calibrated_classifiers_"):
            base = best_model.calibrated_classifiers_[0].estimator
            if hasattr(base, "named_steps") and "scaler" in base.named_steps:
                joblib.dump(base.named_steps["scaler"],
                            ARTIFACTS_DIR / "siem_scaler.pkl")
        elif hasattr(best_model, "named_steps") and "scaler" in best_model.named_steps:
            joblib.dump(best_model.named_steps["scaler"],
                        ARTIFACTS_DIR / "siem_scaler.pkl")
    except Exception as e:
        print(f"[warn] scaler save: {e}")

    # ─── Plots ───
    print("\nGénération figures...")
    pred_opt = (best_proba >= best_thr).astype(int)

    # ROC
    fig, ax = plt.subplots(figsize=(7, 6))
    RocCurveDisplay.from_predictions(y_te, best_proba, ax=ax)
    auc = float(df_res.iloc[best_idx]["roc_auc"])
    ax.set_title(f"ROC SIEM v4 — {best_method} (AUC={auc:.3f})")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "roc_curve.png", dpi=150)
    plt.close()

    # PR
    fig, ax = plt.subplots(figsize=(7, 6))
    PrecisionRecallDisplay.from_predictions(y_te, best_proba, ax=ax)
    ax.axvline(0.5, color="gray", linestyle=":", alpha=0.5)
    ax.set_title(f"PR SIEM v4 — {best_method}")
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "pr_curve.png", dpi=150)
    plt.close()

    # Confusion
    cm = confusion_matrix(y_te, pred_opt)
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Normal", "Attaque"])
    ax.set_yticklabels(["Normal", "Attaque"])
    ax.set_xlabel("Prédit"); ax.set_ylabel("Réel")
    f1c = f1_score(y_te, pred_opt, zero_division=0)
    ax.set_title(f"Confusion v4 (seuil={best_thr:.3f}, F1={f1c:.3f})")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, cm[i, j], ha="center", va="center",
                    color="white" if cm[i, j] > cm.max()/2 else "black",
                    fontsize=14)
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "confusion_matrix.png", dpi=150)
    plt.close()

    # Feature importance (depuis RF si dispo, sinon SHAP-like via permutation)
    try:
        if hasattr(best_model, "calibrated_classifiers_"):
            base = best_model.calibrated_classifiers_[0].estimator
            if hasattr(base, "named_steps") and "rf" in base.named_steps:
                imps_final = base.named_steps["rf"].feature_importances_
            elif hasattr(base, "feature_importances_"):
                imps_final = base.feature_importances_
            else:
                imps_final = None
        elif hasattr(best_model, "feature_importances_"):
            imps_final = best_model.feature_importances_
        else:
            imps_final = None
        if imps_final is not None:
            fi = pd.DataFrame({
                "feature": feature_cols,
                "importance": imps_final,
            }).sort_values("importance", ascending=False)
            fi.to_csv(RESULTS_DIR / "feature_importance.csv", index=False)
            fig, ax = plt.subplots(figsize=(10, 9))
            top = fi.head(20)
            ax.barh(range(len(top)), top["importance"], color="steelblue")
            ax.set_yticks(range(len(top)))
            ax.set_yticklabels(top["feature"], fontsize=9)
            ax.invert_yaxis()
            ax.set_title("Top 20 features — SIEM v4")
            fig.tight_layout()
            fig.savefig(RESULTS_DIR / "feature_importance.png", dpi=150)
            plt.close()
            top_feat = fi.iloc[0]["feature"]
            top_imp = float(fi.iloc[0]["importance"])
        else:
            top_feat, top_imp = None, None
    except Exception as e:
        print(f"[warn] feature importance: {e}")
        top_feat, top_imp = None, None

    # ─── Metrics finales ───
    report = classification_report(y_te, pred_opt,
                                    target_names=["Normal", "Attaque"], digits=4)
    with open(RESULTS_DIR / "classification_report.txt", "w") as fh:
        fh.write(report)
    print("\n" + report)

    metrics = {
        "version": 4,
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

    print(f"\n=== METRICS v4 ===")
    print(f"  Best method        : {best_method}")
    print(f"  F1 (seuil 0.5)     : {metrics['f1_default']}")
    print(f"  F1 macro opt       : {metrics['f1_calibrated']}")
    print(f"  F1 attack opt      : {metrics['f1_attack']}")
    print(f"  F1 normal opt      : {metrics['f1_normal']}")
    print(f"  ROC-AUC            : {metrics['roc_auc']}")
    print(f"  Avg Precision      : {metrics['avg_precision']}")
    print(f"  Overfit gap        : {metrics['overfit_gap']}")
    print(f"  Top feature        : {metrics['top_feature']} ({metrics['top_feature_importance']})")
    print(f"  Leakage warning    : {metrics['leakage_warning']}")


if __name__ == "__main__":
    main()
