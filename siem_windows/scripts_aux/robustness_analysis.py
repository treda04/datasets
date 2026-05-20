"""Phase 6 (post-livraison) — analyse de robustesse du modèle siem_windows.

Toutes les analyses sont *strictement supervisées* (interdit non-supervisé par règle PFE).
Le pipeline production (pipeline/*.py) n'est PAS modifié — ce script est en lecture seule
sur les artefacts existants + écriture dans results/robustness/.

Quatre analyses :
  A) Bootstrap 1000 ré-échantillonnages sur test  -> IC 95% des métriques
  B) Repeated Stratified K-Fold (10 × 3)           -> variance CV solide
  C) Permutation test 500 itérations (AUC)         -> p-value statistique
  D) Benchmark 6 algos supervisés (mêmes data)    -> RF est-il le meilleur ?

Sortie :
  results/robustness/robustness_report.json
  results/robustness/bootstrap_distributions.png
  results/robustness/baseline_comparison.png
  results/robustness/permutation_null.png
"""
from __future__ import annotations

import json
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

from sklearn.ensemble import (
    ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import (
    RepeatedStratifiedKFold, StratifiedKFold, cross_val_predict, cross_val_score,
    permutation_test_score,
)
from sklearn.metrics import (
    f1_score, fbeta_score, precision_score, recall_score, roc_auc_score,
    average_precision_score, confusion_matrix,
)
from sklearn.utils import resample

# imports optionnels
try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

try:
    from lightgbm import LGBMClassifier
    HAS_LGB = True
except ImportError:
    HAS_LGB = False

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)
sns.set_theme(style="whitegrid", palette="muted")

# ============================================================================
# PATHS + LOADING
# ============================================================================
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (  # noqa: E402
    MODELS_DIR, PROCESSED_DIR, RANDOM_STATE, RF_PARAMS,
)

OUT_DIR = Path(__file__).resolve().parent.parent / "results" / "robustness"
OUT_DIR.mkdir(parents=True, exist_ok=True)

print("=== Chargement des artefacts production ===")
X_train = np.load(PROCESSED_DIR / "X_train.npy")
X_test = np.load(PROCESSED_DIR / "X_test.npy")
y_train = np.load(PROCESSED_DIR / "y_train.npy")
y_test = np.load(PROCESSED_DIR / "y_test.npy")
model_prod = joblib.load(MODELS_DIR / "model.pkl")
manifest_prod = json.loads((MODELS_DIR / "manifest.json").read_text())
threshold_prod = float(manifest_prod["decision_threshold"])

print(f"  X_train={X_train.shape} ({int(y_train.sum())} positifs)")
print(f"  X_test ={X_test.shape}  ({int(y_test.sum())} positifs)")
print(f"  Modèle prod : {type(model_prod).__name__}, seuil = {threshold_prod}")


# ============================================================================
# UTILS — métriques + tuning seuil sur CV-train
# ============================================================================
def metrics_at_threshold(y_true, y_proba, thr):
    y_pred = (y_proba >= thr).astype(int)
    return {
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "f2": float(fbeta_score(y_true, y_pred, beta=2, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
    }


def tune_threshold_f2(estimator, X_tr, y_tr, cv):
    """Retourne le seuil qui maximise le F2 sur la CV-train."""
    proba_cv = cross_val_predict(
        estimator, X_tr, y_tr, cv=cv, method="predict_proba", n_jobs=-1
    )[:, 1]
    best_t, best_f2 = 0.50, -1.0
    for t in np.linspace(0.05, 0.95, 19):
        f2 = fbeta_score(y_tr, (proba_cv >= t).astype(int), beta=2, zero_division=0)
        if f2 > best_f2:
            best_f2, best_t = float(f2), float(t)
    return best_t


# ============================================================================
# A — BOOTSTRAP 1000 ré-échantillonnages sur le TEST set
# ============================================================================
print("\n[A] Bootstrap test set (1000 réplications) ...")

y_proba_test_prod = model_prod.predict_proba(X_test)[:, 1]
y_pred_test_prod = (y_proba_test_prod >= threshold_prod).astype(int)

n_boot = 1000
boot = {"f1": [], "f2": [], "precision": [], "recall": [], "auc": []}
rng = np.random.default_rng(RANDOM_STATE)
n = len(X_test)
for _ in range(n_boot):
    idx = rng.integers(0, n, size=n)  # avec remise
    y_true_b = y_test[idx]
    y_proba_b = y_proba_test_prod[idx]
    y_pred_b = y_pred_test_prod[idx]

    # AUC peut échouer si une seule classe dans le sample
    try:
        auc_b = roc_auc_score(y_true_b, y_proba_b)
    except Exception:
        continue
    boot["auc"].append(auc_b)
    boot["f1"].append(f1_score(y_true_b, y_pred_b, zero_division=0))
    boot["f2"].append(fbeta_score(y_true_b, y_pred_b, beta=2, zero_division=0))
    boot["precision"].append(precision_score(y_true_b, y_pred_b, zero_division=0))
    boot["recall"].append(recall_score(y_true_b, y_pred_b, zero_division=0))

ci = {}
for k, arr in boot.items():
    a = np.array(arr)
    ci[k] = {
        "mean": float(a.mean()),
        "median": float(np.median(a)),
        "std": float(a.std()),
        "ci95_low": float(np.percentile(a, 2.5)),
        "ci95_high": float(np.percentile(a, 97.5)),
        "n_samples": int(len(a)),
    }
    print(f"  {k:10s} mean={ci[k]['mean']:.4f}  IC95=[{ci[k]['ci95_low']:.4f}, {ci[k]['ci95_high']:.4f}]")

# Figure : histogrammes bootstrap
fig, axes = plt.subplots(1, 5, figsize=(20, 4))
metric_order = ["f1", "f2", "precision", "recall", "auc"]
for ax, m in zip(axes, metric_order):
    a = np.array(boot[m])
    ax.hist(a, bins=40, color="#2980b9", alpha=0.7, edgecolor="white")
    ax.axvline(ci[m]["mean"], color="#c0392b", lw=2, label=f"mean={ci[m]['mean']:.3f}")
    ax.axvline(ci[m]["ci95_low"], color="#27ae60", ls="--", lw=1.5,
               label=f"IC95=[{ci[m]['ci95_low']:.3f},{ci[m]['ci95_high']:.3f}]")
    ax.axvline(ci[m]["ci95_high"], color="#27ae60", ls="--", lw=1.5)
    ax.set_title(m.upper())
    ax.set_xlabel(m)
    ax.legend(fontsize=8, loc="best")
fig.suptitle("Bootstrap 1000 réplications sur test (Day 2) — distribution des métriques", y=1.02)
plt.tight_layout()
plt.savefig(OUT_DIR / "bootstrap_distributions.png", dpi=120, bbox_inches="tight")
plt.close()
print(f"  -> {OUT_DIR / 'bootstrap_distributions.png'}")


# ============================================================================
# B — REPEATED Stratified K-Fold (10 × 3)
# ============================================================================
print("\n[B] Repeated Stratified K-Fold (10 reps × 3 folds = 30 évaluations) ...")

rskf = RepeatedStratifiedKFold(n_splits=3, n_repeats=10, random_state=RANDOM_STATE)
rf_for_cv = RandomForestClassifier(**RF_PARAMS)

cv_f1_arr = cross_val_score(rf_for_cv, X_train, y_train, cv=rskf, scoring="f1", n_jobs=-1)
cv_auc_arr = cross_val_score(rf_for_cv, X_train, y_train, cv=rskf, scoring="roc_auc", n_jobs=-1)

rcv = {
    "n_evaluations": int(len(cv_f1_arr)),
    "f1": {
        "mean": float(cv_f1_arr.mean()), "std": float(cv_f1_arr.std()),
        "ci95_low": float(np.percentile(cv_f1_arr, 2.5)),
        "ci95_high": float(np.percentile(cv_f1_arr, 97.5)),
    },
    "auc": {
        "mean": float(cv_auc_arr.mean()), "std": float(cv_auc_arr.std()),
        "ci95_low": float(np.percentile(cv_auc_arr, 2.5)),
        "ci95_high": float(np.percentile(cv_auc_arr, 97.5)),
    },
}
print(f"  CV F1  : mean={rcv['f1']['mean']:.4f} std={rcv['f1']['std']:.4f}  "
      f"IC95=[{rcv['f1']['ci95_low']:.4f}, {rcv['f1']['ci95_high']:.4f}]")
print(f"  CV AUC : mean={rcv['auc']['mean']:.4f} std={rcv['auc']['std']:.4f}  "
      f"IC95=[{rcv['auc']['ci95_low']:.4f}, {rcv['auc']['ci95_high']:.4f}]")


# ============================================================================
# C — PERMUTATION TEST (p-value AUC)
# ============================================================================
print("\n[C] Permutation test (500 itérations, AUC) ...")

skf_perm = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)
rf_for_perm = RandomForestClassifier(**RF_PARAMS)

# On évalue l'AUC sur train via CV, perms = 500
score_real, scores_perm, pvalue = permutation_test_score(
    rf_for_perm, X_train, y_train, scoring="roc_auc",
    cv=skf_perm, n_permutations=500, n_jobs=-1, random_state=RANDOM_STATE,
)

perm_section = {
    "n_permutations": 500,
    "scoring": "roc_auc",
    "score_real": float(score_real),
    "score_perm_mean": float(np.mean(scores_perm)),
    "score_perm_std": float(np.std(scores_perm)),
    "p_value": float(pvalue),
    "interpretation": (
        "Score réel est significativement supérieur au hasard (p < 0.01)"
        if pvalue < 0.01 else
        "Significatif (p < 0.05)" if pvalue < 0.05 else
        "Non significatif (p >= 0.05) — modèle pourrait être au hasard"
    ),
}
print(f"  Score réel   = {score_real:.4f}")
print(f"  Score perm   = {np.mean(scores_perm):.4f} ± {np.std(scores_perm):.4f}")
print(f"  p-value      = {pvalue:.4f}")
print(f"  Verdict      : {perm_section['interpretation']}")

# Figure : distribution null + score réel
fig, ax = plt.subplots(figsize=(9, 5))
ax.hist(scores_perm, bins=30, color="#7f8c8d", alpha=0.7, label="Distribution null (labels permutés)")
ax.axvline(score_real, color="#c0392b", lw=3, label=f"Score réel = {score_real:.3f}")
ax.set_title(f"Permutation test — AUC ROC (500 itérations)\np-value = {pvalue:.4f}")
ax.set_xlabel("AUC")
ax.set_ylabel("Fréquence")
ax.legend()
plt.tight_layout()
plt.savefig(OUT_DIR / "permutation_null.png", dpi=120, bbox_inches="tight")
plt.close()
print(f"  -> {OUT_DIR / 'permutation_null.png'}")


# ============================================================================
# D — BENCHMARK BASELINES SUPERVISÉS
# ============================================================================
print("\n[D] Benchmark 6 algorithmes supervisés (split fixe + tuning seuil F2) ...")

skf_bench = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)

def make_models():
    models = []
    models.append(("LogReg L2", LogisticRegression(
        C=1.0, class_weight="balanced", max_iter=5000, random_state=RANDOM_STATE,
    )))
    models.append(("RandomForest (prod)", RandomForestClassifier(**RF_PARAMS)))
    models.append(("ExtraTrees", ExtraTreesClassifier(
        n_estimators=200, max_depth=15, min_samples_leaf=5,
        class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    )))
    models.append(("GradientBoosting", GradientBoostingClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.05,
        random_state=RANDOM_STATE,
    )))
    if HAS_XGB:
        # scale_pos_weight = ratio neg/pos
        neg = int((y_train == 0).sum())
        pos = max(1, int((y_train == 1).sum()))
        models.append(("XGBoost", XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.05,
            scale_pos_weight=neg / pos, eval_metric="logloss",
            tree_method="hist", random_state=RANDOM_STATE, n_jobs=-1,
        )))
    if HAS_LGB:
        models.append(("LightGBM", LGBMClassifier(
            n_estimators=200, max_depth=-1, num_leaves=31, learning_rate=0.05,
            class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
            verbose=-1,
        )))
    return models


bench_rows = []
for name, est in make_models():
    # Tune seuil sur CV-train
    try:
        best_t = tune_threshold_f2(est, X_train, y_train, skf_bench)
    except Exception:
        best_t = 0.50

    # Fit puis évaluer sur test
    est.fit(X_train, y_train)
    proba = est.predict_proba(X_test)[:, 1]
    m_test = metrics_at_threshold(y_test, proba, best_t)
    try:
        auc_v = float(roc_auc_score(y_test, proba))
    except Exception:
        auc_v = float("nan")
    try:
        ap_v = float(average_precision_score(y_test, proba))
    except Exception:
        ap_v = float("nan")

    cv_f1 = cross_val_score(est, X_train, y_train, cv=skf_bench, scoring="f1", n_jobs=-1)
    cv_auc = cross_val_score(est, X_train, y_train, cv=skf_bench, scoring="roc_auc", n_jobs=-1)
    gap = abs(cv_f1.mean() - m_test["f1"])

    bench_rows.append({
        "model": name,
        "threshold": best_t,
        "cv_f1_mean": float(cv_f1.mean()),
        "cv_f1_std": float(cv_f1.std()),
        "cv_auc_mean": float(cv_auc.mean()),
        "test_f1": m_test["f1"],
        "test_f2": m_test["f2"],
        "test_precision": m_test["precision"],
        "test_recall": m_test["recall"],
        "test_auc": auc_v,
        "test_ap": ap_v,
        "gap_cv_test_f1": gap,
    })
    print(f"  {name:25s} thr={best_t:.2f} | "
          f"F1={m_test['f1']:.3f} F2={m_test['f2']:.3f} "
          f"Rec={m_test['recall']:.3f} Prec={m_test['precision']:.3f} "
          f"AUC={auc_v:.3f}  gap={gap:.3f}")

bench_df = pd.DataFrame(bench_rows)

# Figure : barplot F1 / F2 / Recall par modèle
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
for ax, metric, label in zip(
    axes,
    ["test_f1", "test_f2", "test_auc"],
    ["F1 (test)", "F2 (test)", "AUC ROC (test)"],
):
    sorted_df = bench_df.sort_values(metric, ascending=True)
    colors = ["#c0392b" if "prod" in m else "#2980b9" for m in sorted_df["model"]]
    ax.barh(sorted_df["model"], sorted_df[metric], color=colors)
    ax.set_title(label)
    ax.set_xlabel(metric)
    for i, v in enumerate(sorted_df[metric]):
        ax.text(v + 0.005, i, f"{v:.3f}", va="center", fontsize=9)
fig.suptitle("Benchmark des algorithmes supervisés — test Day 2 (seuil F2 tuné sur CV-train)", y=1.02)
plt.tight_layout()
plt.savefig(OUT_DIR / "baseline_comparison.png", dpi=120, bbox_inches="tight")
plt.close()
print(f"  -> {OUT_DIR / 'baseline_comparison.png'}")

# Best model selon F2 (cible IDS)
best = bench_df.sort_values("test_f2", ascending=False).iloc[0]
print(f"\n  Meilleur F2 : {best['model']} (F2={best['test_f2']:.4f}, F1={best['test_f1']:.4f})")


# ============================================================================
# SAUVEGARDE
# ============================================================================
report = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "context": {
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_train_positive": int(y_train.sum()),
        "n_test_positive": int(y_test.sum()),
        "production_model": type(model_prod).__name__,
        "production_threshold": threshold_prod,
    },
    "A_bootstrap_test": ci,
    "B_repeated_cv_train": rcv,
    "C_permutation_test_auc": perm_section,
    "D_baseline_benchmark": bench_rows,
    "best_model_by_test_f2": {
        "name": best["model"],
        "f1": float(best["test_f1"]),
        "f2": float(best["test_f2"]),
        "recall": float(best["test_recall"]),
        "auc": float(best["test_auc"]),
    },
}

(OUT_DIR / "robustness_report.json").write_text(
    json.dumps(report, indent=2, default=str), encoding="utf-8"
)
print(f"\nOK -> {OUT_DIR / 'robustness_report.json'}")
print("\n=== RÉSUMÉ ===")
print(f"  F1 prod        : {ci['f1']['mean']:.4f}  IC95 [{ci['f1']['ci95_low']:.4f}, {ci['f1']['ci95_high']:.4f}]")
print(f"  Recall prod    : {ci['recall']['mean']:.4f}  IC95 [{ci['recall']['ci95_low']:.4f}, {ci['recall']['ci95_high']:.4f}]")
print(f"  AUC prod       : {ci['auc']['mean']:.4f}  IC95 [{ci['auc']['ci95_low']:.4f}, {ci['auc']['ci95_high']:.4f}]")
print(f"  p-value (AUC)  : {perm_section['p_value']:.4f}")
print(f"  Meilleur F2    : {best['model']}  (F2 = {best['test_f2']:.4f})")
