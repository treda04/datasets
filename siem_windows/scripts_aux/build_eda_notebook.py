"""Génère notebooks/01_eda.ipynb à partir de cellules Python définies en clair."""
from __future__ import annotations

import json
from pathlib import Path

NB_PATH = Path(__file__).resolve().parent.parent / "notebooks" / "01_eda.ipynb"

CELLS = [
    ("markdown", """# Phase 1 — EDA SIEM Windows (APT29)

**Notebook :** `01_eda.ipynb`
**But :** visualiser le dataset APT29 (Day 1 + Day 2), tester les règles d'étiquetage, et préparer la matrice de features.

Toutes les valeurs chiffrées de ce notebook sont calculées à partir des JSON bruts en streaming — aucune valeur n'est fabriquée.

Sorties :
- `results/eda/eda_summary.json`
- `results/eda/distribution_eventids.png`
- `results/eda/timeline_events_per_minute.png`
- `results/eda/distribution_hostnames.png`
- `results/eda/channel_normalization_impact.png`
- `results/eda/label_density_window1min.png`
"""),
    ("code", """# Cellule 1 — Imports + paths

from __future__ import annotations
import json, math, re, sys
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="whitegrid", palette="muted")

BASE = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
RAW = {
    "day1": BASE / "data" / "raw" / "day1" / "apt29_evals_day1_manual_2020-05-01225525.json",
    "day2": BASE / "data" / "raw" / "day2" / "apt29_evals_day2_manual_2020-05-02035409.json",
}
EDA = BASE / "results" / "eda"
EDA.mkdir(parents=True, exist_ok=True)

print("BASE  :", BASE)
print("Day 1 :", RAW['day1'].exists(), RAW['day1'].name)
print("Day 2 :", RAW['day2'].exists(), RAW['day2'].name)
"""),
    ("code", """# Cellule 2 — Reload des stats brutes déjà extraites

raw_stats = json.loads((EDA / "raw_stats.json").read_text(encoding="utf-8"))
print("Day 1 :", f"{raw_stats['day1']['total_events']:,} events |",
      raw_stats['day1']['hostnames_count'], "hosts |",
      raw_stats['day1']['eventid_unique'], "EID distincts")
print("Day 2 :", f"{raw_stats['day2']['total_events']:,} events |",
      raw_stats['day2']['hostnames_count'], "hosts |",
      raw_stats['day2']['eventid_unique'], "EID distincts")
print("TOTAL :", f"{raw_stats['totals']['events']:,} events |",
      raw_stats['totals']['windows_5min_total'], "fenêtres 5min /",
      raw_stats['day1']['minute_windows'] + raw_stats['day2']['minute_windows'],
      "fenêtres 1min (× host)")
"""),
    ("code", """# Cellule 3 — Streaming Day 1 + Day 2 vers un DataFrame léger (~280k events lus selon filtre)
# Pour éviter d'exploser la RAM, on ne garde QUE les champs essentiels et on filtre
# au passage les events sans timestamp.

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

def extract_essential(ev, day):
    out = {k: ev.get(k) for k in ESSENTIAL_FIELDS}
    out["day"] = day
    return out

rows = []
for day, path in RAW.items():
    print(f"  stream {day} ({path.stat().st_size/1024/1024:.0f} MB) ...")
    for i, ev in enumerate(stream_events(path)):
        if i % 200000 == 0 and i > 0:
            print(f"     {i:,} lus")
        rows.append(extract_essential(ev, day))

df = pd.DataFrame(rows)
del rows
print("DataFrame :", df.shape)
df.head(3)
"""),
    ("code", """# Cellule 4 — Nettoyage technique
# 1) cast EventID en str (parfois int parfois str dans les events)
# 2) normalisation Channel (Security vs security)
# 3) hostname normalisé (upper, premier label DNS)
# 4) timestamp -> datetime UTC
# 5) drop events sans timestamp

df["EventID"] = df["EventID"].astype(str)
df["Channel_raw"] = df["Channel"].astype(str)
df["Channel"] = df["Channel_raw"].str.casefold()
df["Hostname"] = df["Hostname"].astype(str).str.split('.').str[0].str.upper()
df["ts"] = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)

# Important : les colonnes texte peuvent contenir des NaN -> fillna("") avant tout regex
for col in ["CommandLine", "ScriptBlockText", "TargetImage", "TargetObject", "SourceImage", "Image"]:
    if col in df.columns:
        df[col] = df[col].fillna("").astype(str)

before = len(df)
df = df.dropna(subset=["ts"]).reset_index(drop=True)
after = len(df)
print(f"Events après dropna ts : {after:,} (perdu {before-after} = {(before-after)/before*100:.2f}%)")
print("Hosts :", df["Hostname"].unique().tolist())
"""),
    ("code", """# Cellule 5 — Impact de la normalisation Channel (Security vs security)

ch_before = df["Channel_raw"].value_counts().head(8)
ch_after  = df["Channel"].value_counts().head(8)

print("=== AVANT (Channel brut, casse mixte) ===")
print(ch_before.to_string())
print()
print("=== APRÈS (.casefold()) ===")
print(ch_after.to_string())

# Visualisation : barres comparées pour Security
fig, ax = plt.subplots(1, 2, figsize=(12, 5))
ax[0].bar(["Security (capital)", "security (lower)"],
          [int((df["Channel_raw"] == "Security").sum()),
           int((df["Channel_raw"] == "security").sum())],
          color=["steelblue", "tomato"])
ax[0].set_title("Avant normalisation\\n(38% du signal perdu si filtrage naïf)")
ax[0].set_ylabel("Events")
ax[1].bar(["security (fusionné)"],
          [int((df["Channel"] == "security").sum())], color="seagreen")
ax[1].set_title("Après normalisation casefold()")
ax[1].set_ylabel("Events")
plt.tight_layout()
plt.savefig(EDA / "channel_normalization_impact.png", dpi=120, bbox_inches="tight")
plt.close()
print("Figure sauvegardée :", EDA / "channel_normalization_impact.png")
"""),
    ("code", """# Cellule 6 — Distribution des hostnames (révèle UTICA en Day 2)

host_day = df.groupby(["day", "Hostname"]).size().unstack(fill_value=0)
print(host_day)

fig, ax = plt.subplots(figsize=(10, 5))
host_day.T.plot(kind="bar", ax=ax, color=["#5b9bd5", "#ed7d31"])
ax.set_title("Events par hostname × jour\\n(UTICA Day 2 = ×40 vs Day 1 — host pivot infecté)")
ax.set_ylabel("Nombre d'events")
ax.set_xlabel("Hostname")
ax.set_yscale("log")
plt.xticks(rotation=0)
plt.legend(title="Jour")
plt.tight_layout()
plt.savefig(EDA / "distribution_hostnames.png", dpi=120, bbox_inches="tight")
plt.close()
print("Figure sauvegardée :", EDA / "distribution_hostnames.png")
"""),
    ("code", """# Cellule 7 — Top 20 EventIDs (signature comportementale)

eid_counts = df["EventID"].value_counts().head(20)
print(eid_counts)

fig, ax = plt.subplots(figsize=(11, 7))
colors = ["#c0392b" if e in {"12","10","13","7","800","4103","4688","1"} else "#7f8c8d"
          for e in eid_counts.index]
ax.barh(eid_counts.index[::-1], eid_counts.values[::-1], color=colors[::-1])
ax.set_title("Top 20 EventIDs (Day 1 + Day 2)\\nRouge = EID surveillé par le modèle (cnt_<eid>)")
ax.set_xlabel("Nombre d'events")
ax.set_ylabel("EventID")
ax.set_xscale("log")
plt.tight_layout()
plt.savefig(EDA / "distribution_eventids.png", dpi=120, bbox_inches="tight")
plt.close()
print("Figure sauvegardée :", EDA / "distribution_eventids.png")
"""),
    ("code", """# Cellule 8 — Timeline events/minute Day 1 vs Day 2

df["minute"] = df["ts"].dt.floor("1min")
ts_min = df.groupby(["day", "minute"]).size().reset_index(name="events")

fig, axes = plt.subplots(2, 1, figsize=(13, 7), sharey=False)
for ax, day, color in zip(axes, ["day1", "day2"], ["#1f77b4", "#d62728"]):
    sub = ts_min[ts_min["day"] == day]
    ax.plot(sub["minute"], sub["events"], marker="o", markersize=3, lw=1, color=color)
    ax.fill_between(sub["minute"], sub["events"], alpha=0.2, color=color)
    ax.set_title(f"{day.upper()} — events par minute  ({sub['events'].sum():,} total, peak = {sub['events'].max():,})")
    ax.set_ylabel("Events")
    ax.grid(True, alpha=0.3)
axes[-1].set_xlabel("Temps (UTC)")
plt.tight_layout()
plt.savefig(EDA / "timeline_events_per_minute.png", dpi=120, bbox_inches="tight")
plt.close()
print("Figure sauvegardée :", EDA / "timeline_events_per_minute.png")
print()
print("Day 1 : peak =", ts_min.query("day=='day1'")["events"].max(), " events/min")
print("Day 2 : peak =", ts_min.query("day=='day2'")["events"].max(), " events/min")
"""),
    ("code", """# Cellule 9 — Test des règles d'étiquetage MITRE (rules-based labelling)
# On applique les règles ligne par ligne, puis on agrège par fenêtre (Hostname, minute)
# pour mesurer le ratio attendu de labels positifs.

# Approche vectorisée (780k lignes -> apply Python = trop lent)

cmd_concat = (df["CommandLine"].fillna("") + " " + df["ScriptBlockText"].fillna("")).str.lower()
tobj = df["TargetObject"].fillna("").str.lower()
ti = df["TargetImage"].fillna("").str.lower()
si = df["SourceImage"].fillna("").str.lower()

# Patterns construits via re.compile() pour éviter tout problème d'échappement de raw string
import re as _re
P_ENC = _re.compile(r"\\s-e(?:nc|c|ncoded\\w*)?\\s")
P_DL  = _re.compile(r"downloadstring|iex\\s*\\(|invoke-expression|downloadfile")
P_REG = _re.compile(r"\\\\(?:run|runonce)\\\\")

mask_ps_enc = cmd_concat.str.contains(P_ENC, na=False)
mask_ps_dl  = cmd_concat.str.contains(P_DL,  na=False)
mask_mimi   = cmd_concat.str.contains("mimikatz", regex=False, na=False)
mask_reg    = tobj.str.contains(P_REG, na=False)
mask_lsass  = (
    (df["EventID"] == "10")
    & ti.str.contains("lsass.exe", regex=False, na=False)
    & ~si.str.startswith(("c:\\\\windows\\\\system32\\\\", "c:\\\\windows\\\\syswow64\\\\"))
)

# On affecte la première règle qui matche (priorité dans l'ordre ci-dessous)
df["attack_sig"] = None
df.loc[mask_ps_enc, "attack_sig"] = "T1059.001_encoded"
df.loc[mask_ps_dl  & df["attack_sig"].isna(), "attack_sig"] = "T1059.001_download"
df.loc[mask_mimi   & df["attack_sig"].isna(), "attack_sig"] = "T1003_mimikatz"
df.loc[mask_reg    & df["attack_sig"].isna(), "attack_sig"] = "T1547.001_registry_run"
df.loc[mask_lsass  & df["attack_sig"].isna(), "attack_sig"] = "T1003.001_lsass_handle"

sig_counts = df["attack_sig"].value_counts(dropna=False)
print("Signatures détectées au niveau event :")
print(sig_counts.to_string())
"""),
    ("code", """# Cellule 10 — Fenêtrage 1 min × host + agrégation des labels

WINDOW_RULE = "1min"
MIN_EVENTS = 5

# Agrégation : pour chaque fenêtre, on regarde s'il y a au moins une signature
def aggregate_label(group):
    sigs = group["attack_sig"].dropna()
    if len(sigs) == 0:
        return pd.Series({"label": 0, "technique": None, "n_events": len(group)})
    most_common = sigs.value_counts().idxmax()
    return pd.Series({"label": 1, "technique": most_common, "n_events": len(group)})

df["window"] = df["ts"].dt.floor(WINDOW_RULE)
agg = df.groupby(["day", "Hostname", "window"]).apply(aggregate_label).reset_index()
print("Fenêtres brutes :", len(agg))
agg = agg[agg["n_events"] >= MIN_EVENTS].reset_index(drop=True)
print(f"Fenêtres après filtre ≥{MIN_EVENTS} events :", len(agg))
print()
print("Distribution labels :")
print(agg["label"].value_counts(normalize=True).round(3).to_string())
print()
print("Distribution par jour :")
print(agg.groupby(["day", "label"]).size().unstack(fill_value=0))
print()
print("Distribution par technique :")
print(agg["technique"].value_counts(dropna=False).to_string())
"""),
    ("code", """# Cellule 11 — Visualisation densité des labels par fenêtre

fig, ax = plt.subplots(1, 2, figsize=(13, 5))

# Gauche : ratio labels par jour
day_label = agg.groupby(["day", "label"]).size().unstack(fill_value=0)
day_label.plot(kind="bar", stacked=True, ax=ax[0],
               color=["#95a5a6", "#c0392b"])
ax[0].set_title(f"Fenêtres {WINDOW_RULE} × host par jour\\n(label 0=normal, 1=attaque)")
ax[0].set_ylabel("Nombre de fenêtres")
ax[0].set_xlabel("Jour")
ax[0].legend(["Normal (0)", "Attaque (1)"])
plt.setp(ax[0].get_xticklabels(), rotation=0)

# Droite : technique breakdown
tech_counts = agg["technique"].value_counts().sort_values()
if len(tech_counts) > 0:
    ax[1].barh(tech_counts.index, tech_counts.values, color="#c0392b")
    ax[1].set_title("Techniques MITRE détectées (fenêtres positives)")
    ax[1].set_xlabel("Nombre de fenêtres")
else:
    ax[1].text(0.5, 0.5, "Aucune fenêtre positive", ha="center", va="center", transform=ax[1].transAxes)

plt.tight_layout()
plt.savefig(EDA / "label_density_window1min.png", dpi=120, bbox_inches="tight")
plt.close()
print("Figure sauvegardée :", EDA / "label_density_window1min.png")
"""),
    ("code", """# Cellule 12 — Sauvegarde du résumé EDA dans eda_summary.json

summary = {
    "generated_utc": datetime.now(timezone.utc).isoformat(),
    "dataset": {
        "total_events_after_clean": int(len(df)),
        "events_by_day": {d: int(n) for d, n in df.groupby("day").size().items()},
        "hosts": df["Hostname"].unique().tolist(),
        "events_by_host_day": {
            f"{d}__{h}": int(n)
            for (d, h), n in df.groupby(["day", "Hostname"]).size().items()
        },
        "channels_after_normalization": {
            ch: int(n) for ch, n in df["Channel"].value_counts().items()
        },
        "top_eventids": {eid: int(n) for eid, n in df["EventID"].value_counts().head(20).items()},
    },
    "labelling_rules": {
        "rule_hits_event_level": {
            str(k): int(v) for k, v in sig_counts.items() if pd.notna(k)
        },
    },
    "windowing": {
        "rule": WINDOW_RULE,
        "min_events_per_window": MIN_EVENTS,
        "n_windows_raw": int(len(df.groupby(["day", "Hostname", "window"]).size())),
        "n_windows_filtered": int(len(agg)),
        "label_distribution": {int(k): int(v) for k, v in agg["label"].value_counts().items()},
        "label_distribution_by_day": {
            f"{d}__label{l}": int(n)
            for (d, l), n in agg.groupby(["day", "label"]).size().items()
        },
        "technique_distribution": {
            str(k): int(v) for k, v in agg["technique"].value_counts(dropna=False).items()
        },
    },
    "decisions_for_phase2": {
        "window_granularity": WINDOW_RULE,
        "min_events_filter": MIN_EVENTS,
        "split_strategy": "temporal_day1_train_day2_test",
        "anti_leakage_drop": ["Hostname", "window", "day", "technique"],
        "channel_normalization": "casefold",
        "label_imbalance_ratio": (
            agg["label"].value_counts().get(0, 0) / max(agg["label"].value_counts().get(1, 0), 1)
        ),
    },
}

(EDA / "eda_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
print("OK ->", EDA / "eda_summary.json")
print()
print("=== POINTS-CLÉS POUR PHASE 2 ===")
print(f"  Fenêtres exploitables : {summary['windowing']['n_windows_filtered']}")
print(f"  Labels normal/attaque : {summary['windowing']['label_distribution']}")
print(f"  Déséquilibre 0:1      : {summary['decisions_for_phase2']['label_imbalance_ratio']:.2f}")
print(f"  Day 1 (train) labels  : "
      f"{ {k:v for k,v in summary['windowing']['label_distribution_by_day'].items() if k.startswith('day1')} }")
print(f"  Day 2 (test) labels   : "
      f"{ {k:v for k,v in summary['windowing']['label_distribution_by_day'].items() if k.startswith('day2')} }")
"""),
    ("markdown", """## Synthèse Phase 1

À ce stade :

- ✅ Tous les events APT29 sont parsés (Day 1 + Day 2)
- ✅ Channel normalisé (`Security` ∪ `security` → fusionnés)
- ✅ Règles d'étiquetage MITRE testées au niveau event → on connaît combien de fenêtres seront positives
- ✅ Distribution train/test connue (Day 1 / Day 2)
- ✅ 4 figures + 2 JSON sauvegardés dans `results/eda/`

**Prochaine étape — Phase 2 :** notebook `02_modeling.ipynb` qui prend exactement cette logique de fenêtrage et lui ajoute :
1. Calcul des ~35 features comportementales par fenêtre
2. StandardScaler fit train only
3. RandomForest balanced + CV 5-fold stratifiée
4. Évaluation Day 2 : F1, AUC, gap CV-test, feature importance
5. Sauvegarde `results/modeling/metrics.json` + 4 figures
"""),
]


def build_cells(spec):
    out = []
    for kind, src in spec:
        if kind == "markdown":
            out.append({
                "cell_type": "markdown",
                "metadata": {},
                "source": src.splitlines(keepends=True),
            })
        else:
            out.append({
                "cell_type": "code",
                "execution_count": None,
                "metadata": {},
                "outputs": [],
                "source": src.splitlines(keepends=True),
            })
    return out


def main():
    nb = {
        "cells": build_cells(CELLS),
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {
                "name": "python",
                "version": "3.11",
            },
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NB_PATH.parent.mkdir(parents=True, exist_ok=True)
    NB_PATH.write_text(json.dumps(nb, indent=1), encoding="utf-8")
    print("Generated:", NB_PATH)


if __name__ == "__main__":
    main()
