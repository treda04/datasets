"""Génère notebooks/02_modeling.ipynb."""
from __future__ import annotations

import json
from pathlib import Path

NB_PATH = Path(__file__).resolve().parent.parent / "notebooks" / "02_modeling.ipynb"

CELLS = [
    ("markdown", """# Phase 2 — Modeling SIEM Windows (APT29)

**Notebook :** `02_modeling.ipynb`
**Modèle :** RandomForest balanced (200, max_depth=15, min_samples_leaf=5) + StandardScaler
**Split :** temporel Day 1 → train / Day 2 → test
**Évaluation :** CV 3-fold sur train + une seule passe test

Sorties :
- `results/modeling/metrics.json`
- `results/modeling/confusion_matrix.png`
- `results/modeling/roc_pr_curves.png`
- `results/modeling/feature_importance.png`
- `results/modeling/per_day_metrics.png`
"""),
    ("code", """# Cellule 1 — Imports + paths

from __future__ import annotations
import json, math, re, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, cross_val_score, cross_val_predict
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score, fbeta_score,
    precision_score, recall_score, roc_auc_score, roc_curve,
    precision_recall_curve, average_precision_score,
)

sns.set_theme(style="whitegrid", palette="muted")

BASE = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
RAW = {
    "day1": BASE / "data" / "raw" / "day1" / "apt29_evals_day1_manual_2020-05-01225525.json",
    "day2": BASE / "data" / "raw" / "day2" / "apt29_evals_day2_manual_2020-05-02035409.json",
}
MOD = BASE / "results" / "modeling"
MOD.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42
WINDOW_RULE = "1min"
MIN_EVENTS = 5
CV_FOLDS = 3   # 5 positifs en train -> 3-fold = ~1-2 positifs/fold (5-fold serait aberrant)

print("BASE :", BASE)
print("RANDOM_STATE =", RANDOM_STATE, "| WINDOW_RULE =", WINDOW_RULE, "| CV_FOLDS =", CV_FOLDS)
"""),
    ("code", """# Cellule 2 — Streaming Day 1 + Day 2

ESSENTIAL_FIELDS = [
    "@timestamp", "EventID", "Hostname", "Channel",
    "CommandLine", "ScriptBlockText", "TargetImage", "TargetObject",
    "Image", "ParentImage", "LogonType", "TargetUserName", "IpAddress",
    "SourceImage",
]

def stream_events(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                yield json.loads(line)
            except Exception:
                continue

rows = []
for day, path in RAW.items():
    print(f"  stream {day} ({path.stat().st_size/1024/1024:.0f} MB) ...")
    for i, ev in enumerate(stream_events(path)):
        if i % 200000 == 0 and i > 0:
            print(f"     {i:,} lus")
        out = {k: ev.get(k) for k in ESSENTIAL_FIELDS}
        out["day"] = day
        rows.append(out)

df = pd.DataFrame(rows)
del rows
print("Events :", df.shape)
"""),
    ("code", """# Cellule 3 — Nettoyage + normalisation

df["EventID"] = df["EventID"].astype(str)
df["Channel"] = df["Channel"].astype(str).str.casefold()
df["Hostname"] = df["Hostname"].astype(str).str.split('.').str[0].str.upper()
df["ts"] = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
df = df.dropna(subset=["ts"]).reset_index(drop=True)

for col in ["CommandLine", "ScriptBlockText", "TargetImage", "TargetObject", "SourceImage", "Image"]:
    df[col] = df[col].fillna("").astype(str)

df["window"] = df["ts"].dt.floor(WINDOW_RULE)

cmd_concat = (df["CommandLine"] + " " + df["ScriptBlockText"]).str.lower()
tobj = df["TargetObject"].str.lower()
ti = df["TargetImage"].str.lower()
si = df["SourceImage"].str.lower()

import re as _re
P_ENC = _re.compile(r"\\s-e(?:nc|c|ncoded\\w*)?\\s")
P_DL  = _re.compile(r"downloadstring|iex\\s*\\(|invoke-expression|downloadfile")
P_REG = _re.compile(r"\\\\(?:run|runonce)\\\\")

df["is_ps_enc"] = cmd_concat.str.contains(P_ENC, na=False)
df["is_ps_dl"]  = cmd_concat.str.contains(P_DL,  na=False)
df["is_mimi"]   = cmd_concat.str.contains("mimikatz", regex=False, na=False)
df["is_reg_run"] = tobj.str.contains(P_REG, na=False)
df["is_lsass_strict"] = (
    (df["EventID"] == "10")
    & ti.str.contains("lsass.exe", regex=False, na=False)
    & ~si.str.startswith(("c:\\\\windows\\\\system32\\\\", "c:\\\\windows\\\\syswow64\\\\"))
)
df["is_lsass_raw"] = (df["EventID"] == "10") & ti.str.contains("lsass.exe", regex=False, na=False)

print("Events nettoyés :", len(df))
print("Marqueurs event-level :")
for col in ["is_ps_enc", "is_ps_dl", "is_mimi", "is_reg_run", "is_lsass_strict", "is_lsass_raw"]:
    print(f"  {col:20s} {int(df[col].sum()):>6}")
"""),
    ("code", """# Cellule 4 — Compute features par fenêtre (1 min × Hostname × day)

TARGET_EIDS = ["1","3","7","8","10","11","12","13","22",
               "4103","4104","4624","4625","4648","4672","4688",
               "4697","4698","4702","4768","4769","4771","4776"]

from math import log2

def entropy_of_counts(counts: np.ndarray) -> float:
    total = counts.sum()
    if total <= 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())

def compute_features(group: pd.DataFrame) -> dict:
    eids = group["EventID"].astype(str)
    counts = eids.value_counts()
    total = len(group)

    feat = {
        "total_events": float(total),
        "events_per_minute": float(total),  # window = 1 min
        "distinct_eventids": float(counts.shape[0]),
        "entropy_eventids": entropy_of_counts(counts.values),
    }
    for eid in TARGET_EIDS:
        feat[f"cnt_{eid}"] = float(counts.get(eid, 0))

    # Scores composites
    feat["brute_force_score"] = feat["cnt_4625"] + feat.get("cnt_4771", 0) + feat.get("cnt_4776", 0)
    feat["lateral_move_score"] = feat["cnt_4648"] + feat["cnt_4624"] + feat["cnt_4672"]
    feat["persistence_score"] = feat["cnt_4697"] + feat["cnt_4698"] + feat["cnt_4702"]
    feat["execution_score"] = feat["cnt_4688"] + feat["cnt_1"] + feat["cnt_4104"]
    feat["kerberos_score"] = feat["cnt_4768"] + feat["cnt_4769"] + feat["cnt_4771"]

    # Ratios
    tot_logon = max(1.0, feat["cnt_4624"] + feat["cnt_4625"])
    feat["logon_failure_ratio"] = feat["cnt_4625"] / tot_logon

    # Bonus : nb event-level signaux dans la fenêtre (utilisé seulement pour labelling)
    for col in ["is_ps_enc", "is_ps_dl", "is_mimi", "is_reg_run", "is_lsass_strict", "is_lsass_raw"]:
        feat[col] = int(group[col].sum())
    return feat

print("Function compute_features prête (" + str(len(TARGET_EIDS) + 11) + " features attendues)")
"""),
    ("code", """# Cellule 5 — Fenêtrage + features + labels

groups = df.groupby(["day", "Hostname", "window"], sort=False)
rows = []
for (day, host, w), g in groups:
    if len(g) < MIN_EVENTS:
        continue
    feat = compute_features(g)
    feat["day"] = day
    feat["Hostname"] = host
    feat["window"] = w
    rows.append(feat)

windows_df = pd.DataFrame(rows)

# Rule V1 stricte (cf EDA Phase 1)
def label_v1(r) -> int:
    if r["is_ps_enc"] > 0 or r["is_ps_dl"] > 0 or r["is_mimi"] > 0 or r["is_reg_run"] > 0:
        return 1
    if r["is_lsass_strict"] > 0:
        return 1
    return 0

# Rule V2 enrichie : on ajoute "≥ 3 LSASS handle events / fenêtre" (filtre bruit système naturel)
def label_v2(r) -> int:
    if label_v1(r) == 1:
        return 1
    if r["is_lsass_raw"] >= 3:
        return 1
    return 0

windows_df["label_v1"] = windows_df.apply(label_v1, axis=1)
windows_df["label_v2"] = windows_df.apply(label_v2, axis=1)

# Technique majoritaire dans la fenêtre (debug uniquement, dropée plus tard)
def majority_tech(r):
    cands = []
    if r["is_ps_enc"] > 0: cands.append("T1059.001_encoded")
    if r["is_ps_dl"]  > 0: cands.append("T1059.001_download")
    if r["is_mimi"]   > 0: cands.append("T1003_mimikatz")
    if r["is_reg_run"] > 0: cands.append("T1547.001_registry")
    if r["is_lsass_strict"] > 0: cands.append("T1003.001_lsass_strict")
    if r["is_lsass_raw"]    >= 3: cands.append("T1003.001_lsass_volume")
    return cands[0] if cands else None
windows_df["technique"] = windows_df.apply(majority_tech, axis=1)

print("Fenêtres totales :", len(windows_df))
print()
print("=== Comparaison stratégies de labelling ===")
print("label_v1 (strict) :", windows_df["label_v1"].value_counts().to_dict())
print("label_v2 (enrichi LSASS ≥3) :", windows_df["label_v2"].value_counts().to_dict())
print()
print("=== Distribution par jour (label_v2) ===")
print(windows_df.groupby(["day", "label_v2"]).size().unstack(fill_value=0))
"""),
    ("code", """# Cellule 6 — Choix labelling = V2 (enrichi) + matrices X/y

LABEL_COL = "label_v2"
print(f"Stratégie retenue : {LABEL_COL} ({windows_df[LABEL_COL].sum()} positifs sur {len(windows_df)} fenêtres)")

# Colonnes à dropper (anti-leakage)
DROP_COLS = ["Hostname", "window", "day", "technique", "label_v1", "label_v2",
             "is_ps_enc", "is_ps_dl", "is_mimi", "is_reg_run",
             "is_lsass_strict", "is_lsass_raw"]

feature_cols = [c for c in windows_df.columns if c not in DROP_COLS]
print(f"Nombre de features : {len(feature_cols)}")
print("Features :", feature_cols)

train_df = windows_df[windows_df["day"] == "day1"].copy()
test_df  = windows_df[windows_df["day"] == "day2"].copy()
print(f"Train (Day 1) : {len(train_df)} fenêtres | {train_df[LABEL_COL].sum()} positives")
print(f"Test  (Day 2) : {len(test_df)} fenêtres | {test_df[LABEL_COL].sum()} positives")

X_train = train_df[feature_cols].fillna(0).values.astype(float)
y_train = train_df[LABEL_COL].values.astype(int)
X_test  = test_df[feature_cols].fillna(0).values.astype(float)
y_test  = test_df[LABEL_COL].values.astype(int)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

print(f"X_train_s : {X_train_s.shape} | X_test_s : {X_test_s.shape}")
print(f"Class balance train : {np.bincount(y_train)} | test : {np.bincount(y_test)}")
"""),
    ("code", """# Cellule 7 — RandomForest balanced + CV 3-fold sur train

rf = RandomForestClassifier(
    n_estimators=200, max_depth=15, min_samples_leaf=5,
    class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
)

skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
cv_f1 = cross_val_score(rf, X_train_s, y_train, cv=skf, scoring="f1", n_jobs=-1)
cv_auc = cross_val_score(rf, X_train_s, y_train, cv=skf, scoring="roc_auc", n_jobs=-1)
print(f"CV F1  : mean={cv_f1.mean():.4f}  std={cv_f1.std():.4f}  folds={cv_f1.round(3).tolist()}")
print(f"CV AUC : mean={cv_auc.mean():.4f}  std={cv_auc.std():.4f}  folds={cv_auc.round(3).tolist()}")

# Fit final sur tout le train
rf.fit(X_train_s, y_train)
print("Modèle fit sur Day 1 complet — ready for evaluation on Day 2")
"""),
    ("code", """# Cellule 7-bis — Tuning seuil sur CV-train (max F2 score)
# Méthode reprise d'ADFA-LD v2 : on tire les probas sur le train via cross_val_predict
# (chaque sample est prédit par un modèle qui ne l'a JAMAIS vu), on balaye les seuils,
# on choisit celui qui maximise le F2. Aucune fuite vers le test.

y_train_proba = cross_val_predict(rf, X_train_s, y_train, cv=skf,
                                  method="predict_proba", n_jobs=-1)[:, 1]

thresholds = np.linspace(0.05, 0.95, 19)
best_thr, best_f2 = 0.50, 0.0
scan = []
for t in thresholds:
    yp = (y_train_proba >= t).astype(int)
    f2t = fbeta_score(y_train, yp, beta=2, zero_division=0)
    f1t = f1_score(y_train, yp, zero_division=0)
    pt = precision_score(y_train, yp, zero_division=0)
    rt = recall_score(y_train, yp, zero_division=0)
    scan.append((float(t), float(f1t), float(f2t), float(pt), float(rt)))
    if f2t > best_f2:
        best_f2, best_thr = f2t, float(t)

print(f"Seuil retenu (max F2 sur CV-train) : {best_thr:.2f}  (F2_train_cv = {best_f2:.4f})")
print(f"(Le seuil par défaut 0.50 donnait F2_cv = {scan[8][2]:.4f})")
DECISION_THRESHOLD = best_thr
"""),
    ("code", """# Cellule 8 — Évaluation Day 2 (test) avec seuil tuné

y_proba = rf.predict_proba(X_test_s)[:, 1]
y_pred = (y_proba >= DECISION_THRESHOLD).astype(int)

f1  = f1_score(y_test, y_pred)
f2  = fbeta_score(y_test, y_pred, beta=2)
pr  = precision_score(y_test, y_pred, zero_division=0)
rc  = recall_score(y_test, y_pred, zero_division=0)
try:
    auc = roc_auc_score(y_test, y_proba)
except Exception:
    auc = float("nan")
try:
    ap  = average_precision_score(y_test, y_proba)
except Exception:
    ap = float("nan")
gap = abs(cv_f1.mean() - f1)

print(f"=== TEST METRICS (Day 2) — seuil = {DECISION_THRESHOLD:.2f} ===")
print(f"  F1        : {f1:.4f}   (cible >= 0.78)")
print(f"  F2        : {f2:.4f}   (cible >= 0.80)")
print(f"  Recall    : {rc:.4f}   (cible >= 0.80)")
print(f"  Precision : {pr:.4f}   (cible >= 0.70)")
print(f"  AUC ROC   : {auc:.4f}   (cible >= 0.85)")
print(f"  Avg Prec  : {ap:.4f}")
print(f"  Gap CV-Test F1 : {gap:.4f}   (cible < 0.10)")
print()
print(classification_report(y_test, y_pred, target_names=["Normal(0)", "Attaque(1)"], digits=4))
"""),
    ("code", """# Cellule 9 — Confusion matrix

cm = confusion_matrix(y_test, y_pred)
fig, ax = plt.subplots(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False,
            xticklabels=["Normal(0)", "Attaque(1)"],
            yticklabels=["Normal(0)", "Attaque(1)"], ax=ax)
ax.set_title(f"Matrice de Confusion — Test Day 2\\nF1={f1:.3f} | Recall={rc:.3f} | Precision={pr:.3f}")
ax.set_ylabel("Vérité terrain")
ax.set_xlabel("Prédiction modèle")
plt.tight_layout()
plt.savefig(MOD / "confusion_matrix.png", dpi=120, bbox_inches="tight")
plt.close()
print("OK :", MOD / "confusion_matrix.png")
print("Confusion matrix raw :", cm.tolist())
"""),
    ("code", """# Cellule 10 — ROC + PR curves

fig, axes = plt.subplots(1, 2, figsize=(13, 5))

try:
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    axes[0].plot(fpr, tpr, color="#c0392b", lw=2, label=f"AUC = {auc:.3f}")
    axes[0].plot([0, 1], [0, 1], lw=1, ls="--", color="grey")
    axes[0].set_title("Courbe ROC (test Day 2)")
    axes[0].set_xlabel("False Positive Rate")
    axes[0].set_ylabel("True Positive Rate")
    axes[0].legend(loc="lower right")
except Exception as e:
    axes[0].text(0.5, 0.5, f"ROC indisponible : {e}", ha="center", va="center", transform=axes[0].transAxes)

try:
    prec_arr, rec_arr, _ = precision_recall_curve(y_test, y_proba)
    axes[1].plot(rec_arr, prec_arr, color="#2980b9", lw=2, label=f"AP = {ap:.3f}")
    axes[1].axhline(y=y_test.mean(), color="grey", ls="--", lw=1, label=f"Baseline = {y_test.mean():.3f}")
    axes[1].set_title("Courbe Precision-Recall (test Day 2)")
    axes[1].set_xlabel("Recall")
    axes[1].set_ylabel("Precision")
    axes[1].legend(loc="best")
except Exception as e:
    axes[1].text(0.5, 0.5, f"PR indisponible : {e}", ha="center", va="center", transform=axes[1].transAxes)

plt.tight_layout()
plt.savefig(MOD / "roc_pr_curves.png", dpi=120, bbox_inches="tight")
plt.close()
print("OK :", MOD / "roc_pr_curves.png")
"""),
    ("code", """# Cellule 11 — Feature importance (top 15)

importances = pd.Series(rf.feature_importances_, index=feature_cols).sort_values(ascending=False)
top = importances.head(15)
max_imp = float(importances.max())

fig, ax = plt.subplots(figsize=(10, 6))
colors = ["#c0392b" if v > 0.25 else "#2980b9" for v in top.values]
ax.barh(top.index[::-1], top.values[::-1], color=colors[::-1])
ax.set_title(f"Top 15 features — RandomForest importance\\nMax importance = {max_imp:.3f} (cible < 0.25)")
ax.set_xlabel("Importance Gini (somme = 1)")
ax.axvline(0.25, color="red", ls="--", lw=1, alpha=0.5, label="Seuil shortcut (0.25)")
ax.legend()
plt.tight_layout()
plt.savefig(MOD / "feature_importance.png", dpi=120, bbox_inches="tight")
plt.close()
print("OK :", MOD / "feature_importance.png")
print()
print("Top 10 features :")
print(importances.head(10).round(4).to_string())
"""),
    ("code", """# Cellule 12 — Sauvegarde metrics.json

metrics_payload = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "config": {
        "random_state": RANDOM_STATE,
        "window_rule": WINDOW_RULE,
        "min_events_per_window": MIN_EVENTS,
        "cv_folds": CV_FOLDS,
        "label_strategy": LABEL_COL,
        "decision_threshold": float(DECISION_THRESHOLD),
        "n_features": len(feature_cols),
        "feature_names": feature_cols,
        "rf_params": {
            "n_estimators": 200, "max_depth": 15, "min_samples_leaf": 5,
            "class_weight": "balanced", "random_state": RANDOM_STATE,
        },
    },
    "data": {
        "n_windows_total": int(len(windows_df)),
        "n_train": int(len(train_df)),
        "n_test": int(len(test_df)),
        "n_train_positive": int(train_df[LABEL_COL].sum()),
        "n_test_positive": int(test_df[LABEL_COL].sum()),
        "imbalance_train": float(
            (1 - train_df[LABEL_COL].mean()) / max(train_df[LABEL_COL].mean(), 1e-9)
        ),
    },
    "cv": {
        "f1_mean": float(cv_f1.mean()),
        "f1_std": float(cv_f1.std()),
        "f1_folds": [float(x) for x in cv_f1],
        "auc_mean": float(cv_auc.mean()),
        "auc_std": float(cv_auc.std()),
        "auc_folds": [float(x) for x in cv_auc],
    },
    "test": {
        "f1": float(f1),
        "f2": float(f2),
        "precision": float(pr),
        "recall": float(rc),
        "auc_roc": float(auc) if not math.isnan(auc) else None,
        "avg_precision": float(ap) if not math.isnan(ap) else None,
        "gap_cv_test_f1": float(gap),
        "confusion_matrix": cm.tolist(),
    },
    "threshold_scan": [
        {"threshold": t, "f1": fv, "f2": f2v, "precision": p, "recall": r}
        for (t, fv, f2v, p, r) in scan
    ],
    "feature_importance": {
        "max": float(importances.max()),
        "top15": {k: float(v) for k, v in importances.head(15).items()},
    },
    "targets_check": {
        "f1_ge_0_78": bool(f1 >= 0.78),
        "recall_ge_0_80": bool(rc >= 0.80),
        "precision_ge_0_70": bool(pr >= 0.70),
        "auc_ge_0_85": bool((not math.isnan(auc)) and auc >= 0.85),
        "gap_lt_0_10": bool(gap < 0.10),
        "max_importance_lt_0_25": bool(float(importances.max()) < 0.25),
    },
}

(MOD / "metrics.json").write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")
print("OK :", MOD / "metrics.json")
print()
print("=== STATUT DES CIBLES ===")
for k, v in metrics_payload["targets_check"].items():
    flag = "[OK]" if v else "[KO]"
    print(f"  {flag}  {k}")
"""),
    ("markdown", """## Synthèse Phase 2

Une fois cette cellule terminée :

- ✅ Pipeline complet exécuté en notebook (stream + features + RF + CV + test)
- ✅ Label V2 enrichi (LSASS handle volume) testé contre V1 strict
- ✅ Métriques exhaustives sauvegardées dans `results/modeling/metrics.json`
- ✅ 3 figures officielles produites (confusion, ROC+PR, feature importance)

**Si toutes les cibles passent →** Phase 3 (extraction en pipeline production).
**Si certaines échouent →** documenter dans AVANCEMENT.md ce qui passe / ce qui ne passe pas, et décider si on itère (relâchement de règles, tuning seuil, suppression d'une feature dominante…) avant Phase 3.
"""),
]


def build_cells(spec):
    out = []
    for kind, src in spec:
        cell = {"cell_type": kind, "metadata": {}}
        if kind == "code":
            cell["execution_count"] = None
            cell["outputs"] = []
        cell["source"] = src.splitlines(keepends=True)
        out.append(cell)
    return out


def main():
    nb = {
        "cells": build_cells(CELLS),
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.11"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NB_PATH.parent.mkdir(parents=True, exist_ok=True)
    NB_PATH.write_text(json.dumps(nb, indent=1), encoding="utf-8")
    print("Generated:", NB_PATH)


if __name__ == "__main__":
    main()
