"""Constantes, paths et fonctions partagées du pipeline siem_windows.

Toute modification de constante (RANDOM_STATE, WINDOW_RULE, RF_PARAMS, etc.) DOIT être
faite ici puis re-déclencher la chaîne preprocess -> train -> evaluate pour garantir la
cohérence des artefacts produits.
"""
from __future__ import annotations

import json
import re
from math import log2
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd

# ============================================================================
# PATHS
# ============================================================================
BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DAY1 = BASE_DIR / "data" / "raw" / "day1" / "apt29_evals_day1_manual_2020-05-01225525.json"
RAW_DAY2 = BASE_DIR / "data" / "raw" / "day2" / "apt29_evals_day2_manual_2020-05-02035409.json"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
MODELS_DIR = BASE_DIR / "saved_models" / "v1_final"
RESULTS_DIR = BASE_DIR / "results" / "final"

# ============================================================================
# CONSTANTES PIPELINE
# ============================================================================
RANDOM_STATE = 42
WINDOW_RULE = "1min"
MIN_EVENTS_PER_WINDOW = 5
CV_FOLDS = 3  # 17 positifs en train, 3-fold = ~5-6 positifs/fold (5-fold serait <4)
LABEL_STRATEGY = "label_v2"  # label_v1 = strict, label_v2 = + LSASS volume rule

RF_PARAMS = dict(
    n_estimators=200,
    max_depth=15,
    min_samples_leaf=5,
    class_weight="balanced",
    random_state=RANDOM_STATE,
    n_jobs=-1,
)

# Seuil de décision tuné en Phase 2 sur CV-train (max F2)
DECISION_THRESHOLD_DEFAULT = 0.30

# ============================================================================
# CHAMPS JSON ESSENTIELS À EXTRAIRE
# ============================================================================
ESSENTIAL_FIELDS = [
    "@timestamp", "EventID", "Hostname", "Channel",
    "CommandLine", "ScriptBlockText", "TargetImage", "TargetObject",
    "Image", "ParentImage", "LogonType", "TargetUserName", "IpAddress",
    "SourceImage",
]

# EID surveillés pour les features cnt_<eid>
TARGET_EIDS = [
    "1", "3", "7", "8", "10", "11", "12", "13", "22",
    "4103", "4104",
    "4624", "4625", "4648", "4672", "4688",
    "4697", "4698", "4702",
    "4768", "4769", "4771", "4776",
]

# Colonnes interdites en input modèle (anti-leakage / debug)
DROP_COLS = [
    "Hostname", "window", "day", "technique",
    "label_v1", "label_v2",
    "is_ps_enc", "is_ps_dl", "is_mimi", "is_reg_run",
    "is_lsass_strict", "is_lsass_raw",
]

# ============================================================================
# PATTERNS REGEX (label rules)
# ============================================================================
RX_PS_ENC = re.compile(r"\s-e(?:nc|c|ncoded\w*)?\s")
RX_PS_DL = re.compile(r"downloadstring|iex\s*\(|invoke-expression|downloadfile")
RX_REG_RUN = re.compile(r"\\(?:run|runonce)\\")

SYSTEM32_PREFIXES = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")

# ============================================================================
# IO STREAMING
# ============================================================================
def stream_events(path: Path) -> Iterator[dict]:
    """Yield events from a JSON Lines file (Mordor OTRF format)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_raw_to_dataframe() -> pd.DataFrame:
    """Stream Day 1 + Day 2 vers un DataFrame nettoyé prêt pour le fenêtrage."""
    rows = []
    for day, path in (("day1", RAW_DAY1), ("day2", RAW_DAY2)):
        print(f"  stream {day} ({path.stat().st_size/1024/1024:.0f} MB) ...")
        for i, ev in enumerate(stream_events(path)):
            if i % 200000 == 0 and i > 0:
                print(f"     {i:,} lus")
            out = {k: ev.get(k) for k in ESSENTIAL_FIELDS}
            out["day"] = day
            rows.append(out)
    df = pd.DataFrame(rows)

    df["EventID"] = df["EventID"].astype(str)
    df["Channel"] = df["Channel"].astype(str).str.casefold()
    df["Hostname"] = df["Hostname"].astype(str).str.split(".").str[0].str.upper()
    df["ts"] = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["ts"]).reset_index(drop=True)

    for col in ["CommandLine", "ScriptBlockText", "TargetImage", "TargetObject",
                "SourceImage", "Image"]:
        df[col] = df[col].fillna("").astype(str)

    df["window"] = df["ts"].dt.floor(WINDOW_RULE)

    cmd = (df["CommandLine"] + " " + df["ScriptBlockText"]).str.lower()
    tobj = df["TargetObject"].str.lower()
    ti = df["TargetImage"].str.lower()
    si = df["SourceImage"].str.lower()

    df["is_ps_enc"] = cmd.str.contains(RX_PS_ENC, na=False)
    df["is_ps_dl"] = cmd.str.contains(RX_PS_DL, na=False)
    df["is_mimi"] = cmd.str.contains("mimikatz", regex=False, na=False)
    df["is_reg_run"] = tobj.str.contains(RX_REG_RUN, na=False)
    df["is_lsass_strict"] = (
        (df["EventID"] == "10")
        & ti.str.contains("lsass.exe", regex=False, na=False)
        & ~si.str.startswith(SYSTEM32_PREFIXES)
    )
    df["is_lsass_raw"] = (df["EventID"] == "10") & ti.str.contains(
        "lsass.exe", regex=False, na=False
    )
    return df


# ============================================================================
# FEATURE ENGINEERING
# ============================================================================
def _entropy(counts: np.ndarray) -> float:
    total = counts.sum()
    if total <= 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-(p * np.log2(p)).sum())


def compute_window_features(group: pd.DataFrame) -> dict:
    eids = group["EventID"].astype(str)
    counts = eids.value_counts()
    total = len(group)

    feat = {
        "total_events": float(total),
        "events_per_minute": float(total),  # window = 1 min
        "distinct_eventids": float(counts.shape[0]),
        "entropy_eventids": _entropy(counts.values),
    }
    for eid in TARGET_EIDS:
        feat[f"cnt_{eid}"] = float(counts.get(eid, 0))

    feat["brute_force_score"] = feat["cnt_4625"] + feat.get("cnt_4771", 0) + feat.get("cnt_4776", 0)
    feat["lateral_move_score"] = feat["cnt_4648"] + feat["cnt_4624"] + feat["cnt_4672"]
    feat["persistence_score"] = feat["cnt_4697"] + feat["cnt_4698"] + feat["cnt_4702"]
    feat["execution_score"] = feat["cnt_4688"] + feat["cnt_1"] + feat["cnt_4104"]
    feat["kerberos_score"] = feat["cnt_4768"] + feat["cnt_4769"] + feat["cnt_4771"]

    tot_logon = max(1.0, feat["cnt_4624"] + feat["cnt_4625"])
    feat["logon_failure_ratio"] = feat["cnt_4625"] / tot_logon

    for col in ["is_ps_enc", "is_ps_dl", "is_mimi", "is_reg_run",
                "is_lsass_strict", "is_lsass_raw"]:
        feat[col] = int(group[col].sum())
    return feat


# ============================================================================
# LABELLING
# ============================================================================
def label_v1(row) -> int:
    if row["is_ps_enc"] > 0 or row["is_ps_dl"] > 0 or row["is_mimi"] > 0 or row["is_reg_run"] > 0:
        return 1
    if row["is_lsass_strict"] > 0:
        return 1
    return 0


def label_v2(row) -> int:
    if label_v1(row) == 1:
        return 1
    if row["is_lsass_raw"] >= 3:
        return 1
    return 0


def majority_technique(row) -> str | None:
    cands = []
    if row["is_ps_enc"] > 0: cands.append("T1059.001_encoded")
    if row["is_ps_dl"] > 0: cands.append("T1059.001_download")
    if row["is_mimi"] > 0: cands.append("T1003_mimikatz")
    if row["is_reg_run"] > 0: cands.append("T1547.001_registry")
    if row["is_lsass_strict"] > 0: cands.append("T1003.001_lsass_strict")
    if row["is_lsass_raw"] >= 3: cands.append("T1003.001_lsass_volume")
    return cands[0] if cands else None


def build_windows(df: pd.DataFrame) -> pd.DataFrame:
    """À partir du DataFrame events, produit le DataFrame de fenêtres + labels."""
    rows = []
    for (day, host, w), g in df.groupby(["day", "Hostname", "window"], sort=False):
        if len(g) < MIN_EVENTS_PER_WINDOW:
            continue
        feat = compute_window_features(g)
        feat["day"] = day
        feat["Hostname"] = host
        feat["window"] = w
        rows.append(feat)
    out = pd.DataFrame(rows)
    out["label_v1"] = out.apply(label_v1, axis=1)
    out["label_v2"] = out.apply(label_v2, axis=1)
    out["technique"] = out.apply(majority_technique, axis=1)
    return out
