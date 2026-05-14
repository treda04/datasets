"""
Lateral Movement v2 — préprocesseur enrichi (issue de l'EDA des 112 techniques).

Améliorations vs v1 :
  1. LM_EVENTIDS étendu (24 -> 36 EventIDs) avec les top discriminants chi² :
     +4674 (Priv Object, lift=9.8), +5145 (SMB Admin Shares, lift=5.9 — T1021.002),
     +11 (FileCreate, lift=3.5), +23 (FileDelete, lift=3.2),
     +5158 (WFP bind, lift=1.66), +9 (Sysmon RawAccess), +800 (PS pipeline),
     +4634 (Logoff), +5154/5156/5447 (WFP), +4673 (Sensitive Priv).
  2. Élargissement NÉGATIFS : discovery + collection + defense_evasion +
     credential_access + privilege_escalation (vs discovery + collection seuls).
     -> +75 techniques négatives au lieu de 8.
  3. Rolling features (mean/std/delta sur 3 fenêtres précédentes par technique).
  4. Features identité enrichies : entropy_target_users, entropy_src_ips,
     unique_user_host_pairs.
  5. Cap 5 fenêtres / technique (anti-dominance).
  6. Split GroupShuffleSplit stratifié par label.

Sortie :
  lateral_movement/data/processed_v2/{train,test}.parquet
  lateral_movement/saved_models_v2/feature_columns.json
  lateral_movement/data/processed_v2/manifest.json
"""
import io
import json
import time
import warnings
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

warnings.filterwarnings("ignore")

# ── CONFIG ──
ATOMIC_BASE = Path("siem_dataset/data/otrf_datasets/datasets/atomic/windows")
POS_DIR = ATOMIC_BASE / "lateral_movement" / "host"
# Élargissement des négatifs : on inclut TOUTES les autres tactiques de
# Atomic Red Team (sauf lateral_movement bien sûr). Cela donne un dataset
# beaucoup plus représentatif "lateral vs autre activité d'attaque".
NEG_DIRS = [
    ATOMIC_BASE / "discovery" / "host",
    ATOMIC_BASE / "collection" / "host",
    ATOMIC_BASE / "defense_evasion" / "host",
    ATOMIC_BASE / "credential_access" / "host",
    ATOMIC_BASE / "privilege_escalation" / "host",
    ATOMIC_BASE / "persistence" / "host",
]

OUTPUT_DIR = Path("lateral_movement/data/processed_v2")
ARTIFACTS_DIR = Path("lateral_movement/saved_models_v2")
WINDOW_MIN = 5
WINDOW_STEP_MIN = 1
RANDOM_STATE = 42
MAX_WIN_PER_TECH = 5
ROLLING_K = 3

# ── LM_EVENTIDS v2 (EDA chi²-selected + curated) ──
LM_EVENTIDS_V2 = {
    # Authentification (héritées)
    "logon_success":     [4624],
    "logon_failure":     [4625, 4771],
    "logoff":            [4634],                # NEW lift=2.14
    "explicit_creds":    [4648],
    "special_privs":     [4672],
    "sensitive_priv":    [4673],                # NEW
    "priv_object":       [4674],                # NEW lift=9.8 ! TOP discriminant
    # Services & tasks
    "service_create":    [4697, 4698, 4702],
    # PowerShell
    "powershell":        [4103, 4104, 800],     # +800 NEW chi²=3806
    # Kerberos
    "kerberos_tgs":      [4769],
    "kerberos_tgt":      [4768],
    # Processus
    "process_create":    [4688, 1],
    "process_terminate": [4689, 5],             # NEW
    # Réseau Sysmon + WFP
    "network_conn":      [3, 22],
    "wfp_listen":        [5154],                # NEW
    "wfp_connect":       [5156],                # NEW
    "wfp_bind":          [5158],                # NEW lift=1.66
    "wfp_block":         [5447],                # NEW
    "smb_share":         [5145],                # NEW lift=5.86 T1021.002 !
    # Injection
    "remote_thread":     [8],
    "raw_access":        [9],                   # NEW
    # Image / File
    "image_load":        [7],
    "file_create":       [11],                  # NEW lift=3.48
    "file_delete":       [23],                  # NEW lift=3.19
    # Registry
    "registry":          [12, 13],
    # Object access (file/handle)
    "object_handle_req": [4656],                # NEW
    "object_handle_cls": [4658],                # NEW
    "object_access":     [4663],                # NEW
    "token_duplication": [4690],                # NEW
}
ALL_LM_EVENTIDS = sorted({eid for ids in LM_EVENTIDS_V2.values() for eid in ids})
print(f"LM_EVENTIDS_V2 : {len(LM_EVENTIDS_V2)} catégories, "
      f"{len(ALL_LM_EVENTIDS)} EventIDs monitorés (vs 24 en v1)")


def get_field(event, *paths):
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


def parse_event(event):
    ts_raw = get_field(event, "@timestamp", "EventTime", "TimeCreated",
                       "Event.System.TimeCreated.SystemTime",
                       "winlog.time_created")
    if not ts_raw:
        return None
    try:
        if isinstance(ts_raw, (int, float)):
            ts = float(ts_raw)
        else:
            s = str(ts_raw).rstrip("Z")
            if "." in s:
                base, frac = s.split(".", 1)
                frac = frac[:6].ljust(6, "0")
                s = f"{base}.{frac}"
            ts = datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return None

    host = get_field(event, "Hostname", "host.name", "winlog.computer_name",
                      "Computer", "ComputerName") or "UNKNOWN"
    eid_raw = get_field(event, "EventID", "winlog.event_id", "event.code",
                         "Event.System.EventID", "event_id")
    try:
        eid = int(eid_raw) if eid_raw is not None else 0
    except (ValueError, TypeError):
        eid = 0
    if eid == 0:
        return None

    target = get_field(event, "TargetUserName", "user.target.name") or ""
    src_user = get_field(event, "SubjectUserName", "user.name") or ""
    logon_type = get_field(event, "LogonType", "winlog.event_data.LogonType")
    try:
        logon_type = int(logon_type) if logon_type is not None else None
    except (ValueError, TypeError):
        logon_type = None
    src_ip = get_field(event, "IpAddress", "source.ip",
                        "winlog.event_data.IpAddress") or ""
    return {"ts": ts, "host": str(host), "event_id": eid,
            "target_user": str(target), "src_user": str(src_user),
            "logon_type": logon_type, "src_ip": str(src_ip)}


def iter_events_from_zip(zip_path):
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    with zf.open(name, "r") as fp:
                        first = fp.readline()
                        if not first:
                            continue
                        if first.strip().startswith(b"{"):
                            yield json.loads(first)
                            for line in fp:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    yield json.loads(line)
                                except json.JSONDecodeError:
                                    continue
                        else:
                            buf = io.BytesIO(first + fp.read())
                            try:
                                data = json.load(buf)
                                if isinstance(data, list):
                                    for ev in data:
                                        yield ev
                            except json.JSONDecodeError:
                                continue
                except Exception:
                    continue
    except zipfile.BadZipFile:
        pass


def collect_dir(directory, label):
    samples = []
    if not directory.exists():
        print(f"  [skip] {directory}")
        return samples
    zips = sorted(directory.glob("*.zip"))
    print(f"  {directory.parts[-2]}: {len(zips)} zips")
    for zp in zips:
        technique = zp.stem
        family = technique.split("_", 1)[0] if "_" in technique else technique
        n = 0
        for ev in iter_events_from_zip(zp):
            parsed = parse_event(ev)
            if parsed:
                parsed["technique"] = technique
                parsed["family"] = family
                parsed["label"] = label
                samples.append(parsed)
                n += 1
        # print(f"    {zp.name} -> {n}")
    return samples


# ── Feature extraction v2 ──
def shannon_entropy(values):
    if not values:
        return 0.0
    c = Counter(values)
    total = sum(c.values())
    probs = np.array(list(c.values())) / total
    return float(-np.sum(probs * np.log2(probs + 1e-10)))


def extract_features(events):
    if not events:
        return {}
    eids = [e["event_id"] for e in events]
    cnt = Counter(eids)
    total = len(eids)

    row = {
        "total_events": total,
        "events_per_minute": total / WINDOW_MIN,
    }
    for eid in ALL_LM_EVENTIDS:
        row[f"cnt_{eid}"] = cnt.get(eid, 0)
    for cat, cat_eids in LM_EVENTIDS_V2.items():
        row[f"{cat}_score"] = sum(cnt.get(e, 0) for e in cat_eids)

    # Identité enrichie
    tgt = [e["target_user"] for e in events if e["target_user"]]
    src = [e["src_user"] for e in events if e["src_user"]]
    ips = [e["src_ip"] for e in events if e["src_ip"] and e["src_ip"] != "-"]
    lt = [e["logon_type"] for e in events if e["logon_type"] is not None]

    row["distinct_target_users"] = len(set(tgt))
    row["distinct_src_users"] = len(set(src))
    row["distinct_src_ips"] = len(set(ips))
    row["distinct_logon_types"] = len(set(lt))

    # NEW : entropies sur les utilisateurs/IPs (mesure de "diversité")
    row["entropy_target_users"] = shannon_entropy(tgt)
    row["entropy_src_users"] = shannon_entropy(src)
    row["entropy_src_ips"] = shannon_entropy(ips)

    # NEW : nb pairs uniques (utilisateur, hôte)
    user_host_pairs = {(e["src_user"], e["host"]) for e in events
                       if e["src_user"]}
    row["unique_user_host_pairs"] = len(user_host_pairs)

    # Ratios
    n_type3 = sum(1 for x in lt if x == 3)  # Network logon
    n_type10 = sum(1 for x in lt if x == 10)  # RDP
    n_logons = len(lt)
    row["network_logon_ratio"] = n_type3 / n_logons if n_logons else 0
    row["rdp_logon_ratio"] = n_type10 / n_logons if n_logons else 0
    fail = cnt.get(4625, 0) + cnt.get(4771, 0)
    succ = cnt.get(4624, 0)
    row["logon_failure_ratio"] = fail / (fail + succ) if (fail + succ) else 0

    # Entropie / diversité EventIDs
    if len(set(eids)) > 1:
        probs = np.array(list(cnt.values())) / total
        row["entropy_eventids"] = float(-np.sum(probs * np.log2(probs + 1e-10)))
    else:
        row["entropy_eventids"] = 0.0
    row["distinct_eventids"] = len(set(eids))
    row["distinct_monitored"] = sum(1 for e in ALL_LM_EVENTIDS if cnt.get(e, 0) > 0)

    return row


def build_windows_per_session(samples):
    sessions = defaultdict(list)
    for s in samples:
        sessions[(s["host"], s["technique"])].append(s)

    rows = []
    win_sec = WINDOW_MIN * 60
    step_sec = WINDOW_STEP_MIN * 60
    for (host, technique), evs in sessions.items():
        evs_sorted = sorted(evs, key=lambda e: e["ts"])
        ts_first = evs_sorted[0]["ts"]
        ts_last = evs_sorted[-1]["ts"]
        if ts_last - ts_first < win_sec:
            feat = extract_features(evs_sorted)
            feat.update({"host": host, "technique": technique,
                          "family": evs_sorted[0]["family"],
                          "label": evs_sorted[0]["label"],
                          "window_start_ts": ts_first, "window_end_ts": ts_last})
            rows.append(feat)
            continue
        i_left = 0
        t = ts_first
        while t <= ts_last:
            t_end = t + win_sec
            while i_left < len(evs_sorted) and evs_sorted[i_left]["ts"] < t:
                i_left += 1
            wevs = []
            j = i_left
            while j < len(evs_sorted) and evs_sorted[j]["ts"] < t_end:
                wevs.append(evs_sorted[j])
                j += 1
            if wevs:
                feat = extract_features(wevs)
                feat.update({"host": host, "technique": technique,
                              "family": wevs[0]["family"],
                              "label": wevs[0]["label"],
                              "window_start_ts": t, "window_end_ts": t_end})
                rows.append(feat)
            t += step_sec
    return pd.DataFrame(rows)


def add_rolling(df, base_cols, k=ROLLING_K):
    """Rolling mean/std/delta groupé par technique (vs par host : technique
    est plus pertinent dans Atomic Red Team où chaque zip = un scénario)."""
    df = df.sort_values(["technique", "window_start_ts"]).reset_index(drop=True)
    for col in base_cols:
        grp = df.groupby("technique")[col]
        df[f"{col}_roll{k}_mean"] = grp.transform(
            lambda s: s.shift(1).rolling(k, min_periods=1).mean().fillna(0))
        df[f"{col}_roll{k}_std"] = grp.transform(
            lambda s: s.shift(1).rolling(k, min_periods=1).std().fillna(0))
        df[f"{col}_delta"] = grp.transform(lambda s: s.diff().fillna(0))
    return df


def main():
    print(f"=== PREPROCESS LATERAL v2 ===")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    print("\n[1/4] Lecture POSITIFS (lateral_movement)")
    pos = collect_dir(POS_DIR, label=1)
    print(f"   -> {len(pos):,} events, "
          f"{len({s['technique'] for s in pos})} techniques")

    print("\n[2/4] Lecture NÉGATIFS (6 autres tactiques)")
    neg = []
    for d in NEG_DIRS:
        neg.extend(collect_dir(d, label=0))
    print(f"   -> {len(neg):,} events, "
          f"{len({s['technique'] for s in neg})} techniques")

    print("\n[3/4] Construction fenêtres glissantes + cap...")
    df_pos = build_windows_per_session(pos)
    df_neg = build_windows_per_session(neg) if neg else pd.DataFrame()
    print(f"   Fenêtres brutes : pos={len(df_pos)}, neg={len(df_neg)}")

    def cap(df_in, n):
        if df_in.empty:
            return df_in
        return (df_in.sample(frac=1, random_state=RANDOM_STATE)
                     .groupby("technique", as_index=False)
                     .head(n).reset_index(drop=True))

    df_pos_c = cap(df_pos, MAX_WIN_PER_TECH)
    df_neg_c = cap(df_neg, MAX_WIN_PER_TECH)
    print(f"   Après cap {MAX_WIN_PER_TECH}/technique : "
          f"pos={len(df_pos_c)}, neg={len(df_neg_c)}")

    df = pd.concat([df_pos_c, df_neg_c], ignore_index=True)
    # Rolling
    rolling_base = (
        [f"{cat}_score" for cat in LM_EVENTIDS_V2.keys()]
        + ["total_events", "events_per_minute", "entropy_eventids",
           "distinct_eventids", "logon_failure_ratio",
           "network_logon_ratio", "entropy_target_users",
           "entropy_src_users", "unique_user_host_pairs"]
    )
    df = add_rolling(df, rolling_base, k=ROLLING_K)
    print(f"   Après rolling : {df.shape}")

    # Split stratifié par label par technique
    print("\n[4/4] GroupShuffleSplit stratifié par label par technique...")
    def split_by_group(sub, test_size):
        if sub.empty or sub["technique"].nunique() < 2:
            return sub.copy(), pd.DataFrame()
        gss = GroupShuffleSplit(n_splits=1, test_size=test_size,
                                 random_state=RANDOM_STATE)
        ti, te = next(gss.split(sub, sub["label"], groups=sub["technique"]))
        return sub.iloc[ti], sub.iloc[te]

    df_p = df[df["label"] == 1]
    df_n = df[df["label"] == 0]
    pos_tr, pos_te = split_by_group(df_p, test_size=0.25)
    neg_tr, neg_te = split_by_group(df_n, test_size=0.25)
    df_train = pd.concat([pos_tr, neg_tr], ignore_index=True)
    df_test = pd.concat([pos_te, neg_te], ignore_index=True)

    tr_techs = sorted(df_train["technique"].unique())
    te_techs = sorted(df_test["technique"].unique())
    overlap = set(tr_techs) & set(te_techs)
    print(f"   {len(tr_techs)} techniques train, {len(te_techs)} test, "
          f"{'overlap!' if overlap else 'disjointes ✓'}")
    print(f"   Train : pos={int(df_train['label'].sum())}/{len(df_train)}")
    print(f"   Test  : pos={int(df_test['label'].sum())}/{len(df_test)}")

    feature_cols = [c for c in df.columns
                    if c not in ("host", "technique", "family", "label",
                                  "window_start_ts", "window_end_ts")]

    df_train.to_parquet(OUTPUT_DIR / "train.parquet", index=False)
    df_test.to_parquet(OUTPUT_DIR / "test.parquet", index=False)
    df_train[feature_cols].to_csv(OUTPUT_DIR / "X_train.csv", index=False)
    df_test[feature_cols].to_csv(OUTPUT_DIR / "X_test.csv", index=False)

    with open(ARTIFACTS_DIR / "feature_columns.json", "w") as f:
        json.dump(feature_cols, f, indent=2)

    manifest = {
        "version": 2,
        "source": "Atomic Red Team : lateral_movement (pos) vs "
                  "discovery+collection+defense_evasion+credential_access+"
                  "privilege_escalation+persistence (neg)",
        "split": "GroupShuffleSplit stratifié par label par technique",
        "cap_windows_per_technique": MAX_WIN_PER_TECH,
        "rolling_k": ROLLING_K,
        "n_monitored_eventids": len(ALL_LM_EVENTIDS),
        "all_monitored_eventids": ALL_LM_EVENTIDS,
        "categories": list(LM_EVENTIDS_V2.keys()),
        "n_features": len(feature_cols),
        "n_train": len(df_train),
        "n_test": len(df_test),
        "n_train_positive": int(df_train["label"].sum()),
        "n_test_positive": int(df_test["label"].sum()),
        "balance_train": float(df_train["label"].mean()),
        "balance_test": float(df_test["label"].mean()),
        "train_techniques": tr_techs,
        "test_techniques": te_techs,
        "elapsed_sec": round(time.time() - t0, 1),
    }
    with open(OUTPUT_DIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n=== RÉSUMÉ v2 ===")
    print(f"  Train : {len(df_train)} fenêtres "
          f"({manifest['n_train_positive']} pos, {manifest['balance_train']*100:.1f}%)")
    print(f"  Test  : {len(df_test)} fenêtres "
          f"({manifest['n_test_positive']} pos, {manifest['balance_test']*100:.1f}%)")
    print(f"  Features : {len(feature_cols)} (vs 44 en v1)")
    print(f"  Techniques : {len(tr_techs)+len(te_techs)} "
          f"(vs 37 en v1)")
    print(f"  Elapsed : {manifest['elapsed_sec']}s")


if __name__ == "__main__":
    main()
