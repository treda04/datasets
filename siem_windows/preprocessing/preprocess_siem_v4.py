"""
SIEM Windows v4 — préprocesseur enrichi (issue de l'EDA des 175 EventIDs).

Nouveautés vs v3 :
  1. ALL_MONITORED étendu : 24 -> ~40 EventIDs (Security + Sysmon majeurs +
     PowerShell + WFP). Sélectionné via chi² sur la distribution réelle.
  2. Catégories MITRE ATT&CK étendues : credential_dumping, image_load,
     registry_mod, powershell, wfp_network, remote_thread, raw_access,
     network_conn, file_create, en plus des 7 catégories v3.
  3. Rolling-window features : pour chaque score catégorie + total_events,
     ajoute mean/std/delta sur les 3 fenêtres précédentes du même host.
  4. Ratio features : process_per_minute, registry_per_minute,
     network_per_minute, encore plus interprétables que les counts bruts.

Sortie :
  siem_windows/data/processed_v4/{train,test}.parquet
  siem_windows/data/processed_v4/{X,y}_{train,test}.csv
  siem_windows/data/processed_v4/manifest.json
  siem_windows/saved_models_v4/feature_columns.json
"""
import gzip
import json
import time
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

warnings.filterwarnings("ignore")

# ───── CONFIG ─────
RAW_DAY1 = Path("siem_windows/data/raw/day1")
RAW_DAY2 = Path("siem_windows/data/raw/day2")
OUTPUT_DIR = Path("siem_windows/data/processed_v4")
ARTIFACTS_DIR = Path("siem_windows/saved_models_v4")
WINDOW_MIN = 5
WINDOW_STEP_MIN = 1
RANDOM_STATE = 42
SPLIT_TEST_SIZE = 0.25
ROLLING_K = 3  # nb fenêtres précédentes pour rolling features

APT29_ATTACK_WINDOWS = {
    "day1": [
        ("2020-05-02T03:18:00Z", "2020-05-02T04:30:00Z", "Initial Access + Execution"),
        ("2020-05-02T04:30:00Z", "2020-05-02T05:30:00Z", "Persistence + Discovery"),
    ],
    "day2": [
        ("2020-05-02T08:10:00Z", "2020-05-02T08:35:00Z", "APT29 day2 active phase"),
    ],
}

# ───── ATTACK_EVENTIDS v4 (chi²-selected + curated MITRE) ─────
# Catégorie -> EventIDs. Plusieurs EventIDs peuvent appartenir à plusieurs
# catégories (ex: 4672 = priv esc + lateral move). On garde la sémantique MITRE.
ATTACK_EVENTIDS_V4 = {
    # Security log (héritées de v3)
    "brute_force":        [4625, 4771, 4776],
    "lateral_move":       [4648, 4624, 4672],
    "persistence":        [4697, 4698, 4702, 4720, 4726],
    "priv_escalation":    [4728, 4732, 4756, 4738],
    "recon":              [4798, 4799, 4661],
    "execution":          [4688, 4696],
    "kerberos":           [4768, 4769, 4770, 4773],
    # NOUVELLES catégories (Sysmon + PowerShell + WFP)
    "credential_dump":    [10],              # ProcessAccess (T1003) - lift=1.61
    "image_load":         [7],               # T1574 DLL side-load - lift=2.00
    "registry_mod":       [12, 13],          # T1112 - chi²=8304+5892
    "powershell":         [800, 4103, 4104], # T1059.001 - chi²=1900+287
    "wfp_network":        [5154, 5156, 5158, 5447],  # T1071/T1562 - lift haut
    "remote_thread":      [8],               # T1055 Process Injection - lift=117
    "raw_access":         [9],               # kernel access (suspect)
    "network_conn":       [3],               # T1071 Sysmon NetConn - lift=1.79
    "file_create":        [11],              # T1105 Ingress Tool Transfer
    "process_create_sys": [1],               # T1059 Sysmon ProcCreate - lift=2.89
    "rights_adjust":      [4703],            # User Right Adjusted
    "object_access":      [4656, 4658, 4663],  # File access tracking
}
ALL_MONITORED = sorted({eid for ids in ATTACK_EVENTIDS_V4.values() for eid in ids})
print(f"ATTACK_EVENTIDS_V4 : {len(ATTACK_EVENTIDS_V4)} catégories, "
      f"{len(ALL_MONITORED)} EventIDs monitorés")


# ───── PARSING IDENTIQUE V3 ─────
def get_field(event: dict, *paths) -> object:
    for path in paths:
        v = event
        for p in path.split("."):
            if isinstance(v, dict):
                v = v.get(p)
            else:
                v = None
                break
        if v is not None and v != "":
            return v
    return None


def iter_events(raw_dir: Path) -> Iterator[dict]:
    if not raw_dir.exists():
        return
    files = (list(raw_dir.rglob("*.json")) + list(raw_dir.rglob("*.jsonl"))
             + list(raw_dir.rglob("*.json.gz")))
    for f in files:
        opener = gzip.open if f.suffix == ".gz" else open
        try:
            with opener(f, "rt", encoding="utf-8", errors="ignore") as fh:
                first = fh.readline()
                if not first:
                    continue
                fh.seek(0)
                if first.strip().startswith("{"):
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
                else:
                    try:
                        data = json.load(fh)
                        if isinstance(data, list):
                            for ev in data:
                                yield ev
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[warn] {f.name}: {e}")


def parse_event(event: dict) -> dict | None:
    ts_raw = get_field(event, "@timestamp", "EventTime", "TimeCreated",
                       "Event.System.TimeCreated.SystemTime",
                       "winlog.time_created")
    if not ts_raw:
        return None
    try:
        if isinstance(ts_raw, (int, float)):
            ts_unix = float(ts_raw)
        else:
            ts_str = str(ts_raw).rstrip("Z")
            if "." in ts_str:
                base, frac = ts_str.split(".", 1)
                frac = frac[:6].ljust(6, "0")
                ts_str = f"{base}.{frac}"
            ts_unix = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return None

    host = get_field(event, "Hostname", "host.name", "winlog.computer_name",
                      "Computer", "ComputerName") or "UNKNOWN"
    eid_raw = get_field(event, "EventID", "winlog.event_id",
                         "event.code", "Event.System.EventID", "event_id")
    try:
        event_id = int(eid_raw) if eid_raw is not None else 0
    except (ValueError, TypeError):
        event_id = 0
    if event_id == 0:
        return None
    return {"ts": ts_unix, "host": str(host), "event_id": event_id}


# ───── FEATURE EXTRACTION V4 (étendu) ─────
def extract_features_from_window(events: list[dict]) -> dict:
    if not events:
        return {}

    event_ids = [e["event_id"] for e in events]
    cnt = Counter(event_ids)
    total = len(event_ids)

    row = {
        "total_events": total,
        "events_per_minute": total / WINDOW_MIN,
    }

    # Counts pour les EventIDs monitorés
    for eid in ALL_MONITORED:
        row[f"cnt_{eid}"] = cnt.get(eid, 0)

    # Scores par catégorie MITRE
    for cat, eids in ATTACK_EVENTIDS_V4.items():
        row[f"{cat}_score"] = sum(cnt.get(e, 0) for e in eids)

    # Ratios v4 (interprétables)
    successes = cnt.get(4624, 0)
    failures = cnt.get(4625, 0) + cnt.get(4771, 0)
    row["logon_failure_ratio"] = (
        failures / (successes + failures) if (successes + failures) > 0 else 0
    )
    # Ratio d'events monitorés vs total (signal de "couverture")
    monitored_total = sum(cnt.get(e, 0) for e in ALL_MONITORED)
    row["monitored_event_ratio"] = monitored_total / total if total > 0 else 0

    # Densité par type (per_minute = score / 5)
    for cat in ["credential_dump", "image_load", "registry_mod",
                "powershell", "remote_thread", "network_conn",
                "process_create_sys"]:
        row[f"{cat}_per_min"] = row[f"{cat}_score"] / WINDOW_MIN

    # Entropy + diversité
    unique_cnt = len(set(event_ids))
    if unique_cnt > 1:
        probs = np.array(list(cnt.values())) / total
        row["entropy_eventids"] = float(-np.sum(probs * np.log2(probs + 1e-10)))
    else:
        row["entropy_eventids"] = 0.0
    row["distinct_eventids"] = unique_cnt
    row["distinct_monitored"] = sum(1 for e in ALL_MONITORED if cnt.get(e, 0) > 0)

    return row


def parse_iso(s: str) -> float:
    return datetime.fromisoformat(s.rstrip("Z")).replace(tzinfo=timezone.utc).timestamp()


def is_window_attack(window_center_ts: float, day_key: str) -> int:
    for start_iso, end_iso, _tactic in APT29_ATTACK_WINDOWS.get(day_key, []):
        if parse_iso(start_iso) <= window_center_ts <= parse_iso(end_iso):
            return 1
    return 0


def build_windows(events_by_host: dict[str, list[dict]], day_key: str) -> pd.DataFrame:
    rows = []
    win_sec = WINDOW_MIN * 60
    step_sec = WINDOW_STEP_MIN * 60

    for host, evs in events_by_host.items():
        if not evs:
            continue
        evs_sorted = sorted(evs, key=lambda e: e["ts"])
        ts_first = evs_sorted[0]["ts"]
        ts_last = evs_sorted[-1]["ts"]
        if ts_last - ts_first < win_sec / 2:
            continue

        i_left = 0
        t = ts_first
        while t <= ts_last:
            t_end = t + win_sec
            while i_left < len(evs_sorted) and evs_sorted[i_left]["ts"] < t:
                i_left += 1
            window_events = []
            j = i_left
            while j < len(evs_sorted) and evs_sorted[j]["ts"] < t_end:
                window_events.append(evs_sorted[j])
                j += 1
            if window_events:
                feat = extract_features_from_window(window_events)
                feat["host"] = host
                feat["window_start_ts"] = t
                feat["window_end_ts"] = t_end
                feat["label"] = is_window_attack((t + t_end) / 2, day_key)
                rows.append(feat)
            t += step_sec
    return pd.DataFrame(rows)


def add_rolling_features(df: pd.DataFrame, base_cols: list[str], k: int = ROLLING_K) -> pd.DataFrame:
    """Ajoute mean/std/delta des k fenêtres précédentes par host
    (utiliser pour temporal smoothing, capture les bursts)."""
    df = df.sort_values(["host", "window_start_ts"]).reset_index(drop=True)
    for col in base_cols:
        # Mean / std des k fenêtres précédentes (rolling fermé à droite)
        grp = df.groupby("host")[col]
        df[f"{col}_roll{k}_mean"] = grp.transform(
            lambda s: s.shift(1).rolling(k, min_periods=1).mean().fillna(0)
        )
        df[f"{col}_roll{k}_std"] = grp.transform(
            lambda s: s.shift(1).rolling(k, min_periods=1).std().fillna(0)
        )
        # Delta vs fenêtre précédente
        df[f"{col}_delta"] = grp.transform(lambda s: s.diff().fillna(0))
    return df


def main():
    print(f"=== PREPROCESS SIEM v4 ({len(ALL_MONITORED)} EventIDs monitorés) ===")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    all_events = []
    for raw_dir, day_key in [(RAW_DAY1, "day1"), (RAW_DAY2, "day2")]:
        if not raw_dir.exists():
            print(f"[skip] {raw_dir} introuvable")
            continue
        print(f"\n  --- {day_key} ({raw_dir}) ---")
        events_by_host = defaultdict(list)
        n = 0
        for ev in iter_events(raw_dir):
            n += 1
            parsed = parse_event(ev)
            if parsed:
                events_by_host[parsed["host"]].append(parsed)
            if n % 100_000 == 0:
                print(f"      {n} events lus...")
        df_day = build_windows(events_by_host, day_key)
        df_day["day"] = day_key
        print(f"      Events lus : {n}  |  fenêtres : {len(df_day)} "
              f"(positives={int(df_day['label'].sum()) if len(df_day) else 0})")
        all_events.append(df_day)

    df_all = pd.concat(all_events, ignore_index=True)
    print(f"\nFenêtres totales avant rolling : {len(df_all)} "
          f"(pos={int(df_all['label'].sum())})")

    # Rolling features sur les scores catégorie + total
    rolling_base = (
        [f"{cat}_score" for cat in ATTACK_EVENTIDS_V4.keys()]
        + ["total_events", "events_per_minute", "entropy_eventids",
           "distinct_eventids", "logon_failure_ratio",
           "monitored_event_ratio"]
    )
    df_all = add_rolling_features(df_all, rolling_base, k=ROLLING_K)
    print(f"Après rolling : {df_all.shape[1]} colonnes")

    # Split par host (GroupShuffleSplit)
    if df_all["host"].nunique() < 2:
        print("\n[INFO] <2 hosts -> split temporel 80/20")
        df_all = df_all.sort_values("window_start_ts").reset_index(drop=True)
        cutoff = int(len(df_all) * 0.8)
        df_train = df_all.iloc[:cutoff].copy()
        df_test = df_all.iloc[cutoff:].copy()
    else:
        gss = GroupShuffleSplit(n_splits=1, test_size=SPLIT_TEST_SIZE,
                                 random_state=RANDOM_STATE)
        tr_idx, te_idx = next(gss.split(df_all, df_all["label"],
                                          groups=df_all["host"]))
        df_train = df_all.iloc[tr_idx].reset_index(drop=True)
        df_test = df_all.iloc[te_idx].reset_index(drop=True)
        print(f"\n  Split par host : train={sorted(df_train['host'].unique())}, "
              f"test={sorted(df_test['host'].unique())}")

    feature_cols = [c for c in df_train.columns
                    if c not in ("host", "day", "window_start_ts",
                                  "window_end_ts", "label")]

    # Save
    df_train.to_parquet(OUTPUT_DIR / "train.parquet", index=False)
    df_test.to_parquet(OUTPUT_DIR / "test.parquet", index=False)
    df_train[feature_cols].to_csv(OUTPUT_DIR / "X_train.csv", index=False)
    df_test[feature_cols].to_csv(OUTPUT_DIR / "X_test.csv", index=False)
    df_train[["label"]].to_csv(OUTPUT_DIR / "y_train.csv", index=False)
    df_test[["label"]].to_csv(OUTPUT_DIR / "y_test.csv", index=False)

    with open(ARTIFACTS_DIR / "feature_columns.json", "w") as f:
        json.dump(feature_cols, f, indent=2)

    manifest = {
        "version": 4,
        "source": "OTRF Mordor APT29 day1+day2 + EDA-selected EventIDs",
        "split_method": "GroupShuffleSplit by host",
        "window_min": WINDOW_MIN,
        "window_step_min": WINDOW_STEP_MIN,
        "rolling_k": ROLLING_K,
        "n_monitored_eventids": len(ALL_MONITORED),
        "all_monitored_eventids": ALL_MONITORED,
        "attack_categories": list(ATTACK_EVENTIDS_V4.keys()),
        "n_features": len(feature_cols),
        "n_train": len(df_train),
        "n_test": len(df_test),
        "n_train_positive": int(df_train["label"].sum()),
        "n_test_positive": int(df_test["label"].sum()),
        "balance_train": float(df_train["label"].mean()),
        "balance_test": float(df_test["label"].mean()),
        "train_hosts": sorted(df_train["host"].unique().tolist()),
        "test_hosts": sorted(df_test["host"].unique().tolist()),
        "elapsed_sec": round(time.time() - t0, 1),
    }
    with open(OUTPUT_DIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n=== RÉSUMÉ v4 ===")
    print(f"Train : {len(df_train)} fenêtres ({manifest['n_train_positive']} pos, "
          f"{manifest['balance_train']*100:.1f}%)")
    print(f"Test  : {len(df_test)} fenêtres ({manifest['n_test_positive']} pos, "
          f"{manifest['balance_test']*100:.1f}%)")
    print(f"Features : {len(feature_cols)} (vs 21 en v3 -> +{len(feature_cols)-21})")
    print(f"Elapsed : {manifest['elapsed_sec']}s")


if __name__ == "__main__":
    main()
