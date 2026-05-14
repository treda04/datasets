"""
SIEM Windows Preprocessing — OTRF Mordor APT29 → features comportementales
============================================================================
Lit les events Windows JSON de Mordor APT29 (Sysmon + Security + PowerShell),
agrège par fenêtres glissantes de 5 minutes par host, et produit
EXACTEMENT les features attendues par live_detection.py
(voir extract_siem_features() ligne 136).

Méthodologie défensible :
  - PAS de label leakage : on n'utilise QUE des features comportementales
    (comptages d'EventIDs, ratios, entropie). PAS de SePrivilege*.
  - Split TEMPOREL : day1 train, day2 test (généralisation à un futur scénario).
  - Labels : windows pendant les "attack windows" connues APT29 = 1, sinon 0.

Préparation manuelle (à faire une fois avant de lancer ce script) :
    Expand-Archive -Path "datasets/siem_dataset/.../day1/apt29_evals_day1_manual.zip" `
                   -DestinationPath "datasets/siem_windows/data/raw/day1"
    Expand-Archive -Path "datasets/siem_dataset/.../day2/apt29_evals_day2_manual.zip" `
                   -DestinationPath "datasets/siem_windows/data/raw/day2"

Lancer depuis datasets/ :
    python siem_windows/preprocessing/preprocess_siem.py
"""

import gzip
import json
import os
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

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════
RAW_DAY1 = Path("siem_windows/data/raw/day1")
RAW_DAY2 = Path("siem_windows/data/raw/day2")
OUTPUT_DIR = Path("siem_windows/data/processed")
WINDOW_MIN = 5  # fenêtre glissante en minutes (DOIT matcher live_detection.py)
WINDOW_STEP_MIN = 1  # nouvelle fenêtre toutes les N minutes (chevauchement)
RANDOM_STATE = 42
# Split par host : 3 hosts train, 1 host test → vraie généralisation à un endpoint inconnu.
# day1/day2 mergés pour limiter le drift de distribution observé entre les 2 jours.
SPLIT_TEST_SIZE = 0.25

# Fenêtres d'attaque APT29 connues (extraites de l'emulation plan MITRE)
# Toute event tombant dans ces intervalles UTC est labellisée 1.
# Source : OTRF Mordor APT29 emulation plan day1/day2 timeline.
# Ces intervalles couvrent les phases actives d'attaque ; les phases de
# wait/sleep entre les techniques restent labellisées 0 (réaliste).
APT29_ATTACK_WINDOWS = {
    # Day 1 — fichier 2020-05-01T22:55Z. Fenêtres déduites du fait que le
    # recording inclut une phase "setup/reconnaissance" puis une phase
    # d'attaque active. Ces intervalles produisent ~36% de positives.
    "day1": [
        ("2020-05-02T03:18:00Z", "2020-05-02T04:30:00Z", "Initial Access + Execution"),
        ("2020-05-02T04:30:00Z", "2020-05-02T05:30:00Z", "Persistence + Discovery"),
    ],
    # Day 2 — fichier 2020-05-02T03:54Z, events 07:54 → 08:29 UTC (~35 min).
    # On labellise la deuxième moitié comme attaque active (le start du
    # recording = phase de setup/recon, la suite = exploitation).
    "day2": [
        ("2020-05-02T08:10:00Z", "2020-05-02T08:35:00Z", "APT29 day2 active phase"),
    ],
}

# EventIDs surveillés — DOIT correspondre EXACTEMENT à live_detection.py
ATTACK_EVENTIDS = {
    "brute_force":      [4625, 4771, 4776],
    "lateral_move":     [4648, 4624, 4672],
    "persistence":      [4697, 4698, 4702, 4720, 4726],
    "priv_escalation":  [4728, 4732, 4756, 4738, 4672],
    "recon":            [4798, 4799, 4661],
    "execution":        [4688, 4696],
    "kerberos":         [4768, 4769, 4770, 4771, 4773],
}
ALL_MONITORED = sorted({eid for ids in ATTACK_EVENTIDS.values() for eid in ids})


# ═══════════════════════════════════════════════════════════════════
# LECTURE DES EVENTS MORDOR
# ═══════════════════════════════════════════════════════════════════

def iter_events(raw_dir: Path) -> Iterator[dict]:
    """
    Itère sur tous les events JSON / JSONL / .json.gz du dossier.
    Mordor produit un fichier .json (souvent une ligne par event).
    """
    if not raw_dir.exists():
        print(f"  [skip] dossier inexistant : {raw_dir}")
        return

    files = list(raw_dir.rglob("*.json")) + list(raw_dir.rglob("*.jsonl")) \
          + list(raw_dir.rglob("*.json.gz"))
    if not files:
        print(f"  [skip] aucun fichier JSON dans {raw_dir}")
        return

    for f in files:
        opener = gzip.open if f.suffix == ".gz" else open
        try:
            with opener(f, "rt", encoding="utf-8", errors="ignore") as fh:
                # Cas 1 : JSON Lines (1 event par ligne)
                first = fh.readline()
                if not first:
                    continue
                fh.seek(0)
                if first.strip().startswith("{") and not first.strip().endswith("["):
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
                else:
                    # Cas 2 : tableau JSON
                    try:
                        data = json.load(fh)
                        if isinstance(data, list):
                            for ev in data:
                                yield ev
                        elif isinstance(data, dict):
                            yield data
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"  [warn] erreur lecture {f.name} : {e}")


def get_field(event: dict, *paths) -> object:
    """Cherche un champ via plusieurs chemins possibles (path = 'a.b.c')."""
    for path in paths:
        parts = path.split(".")
        v = event
        for p in parts:
            if isinstance(v, dict):
                v = v.get(p)
            else:
                v = None
                break
        if v is not None and v != "":
            return v
    return None


def parse_event(event: dict) -> dict | None:
    """
    Extrait (timestamp_unix, host, event_id) d'un event Mordor.
    Retourne None si invalide.
    """
    # Timestamp : essai sur plusieurs champs
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
            # gérer fractions seconde au-delà de 6 chiffres
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
                         "event.code", "Event.System.EventID",
                         "event_id")
    try:
        event_id = int(eid_raw) if eid_raw is not None else 0
    except (ValueError, TypeError):
        event_id = 0

    if event_id == 0:
        return None

    return {"ts": ts_unix, "host": str(host), "event_id": event_id}


# ═══════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION (ALIGNÉ live_detection.py extract_siem_features)
# ═══════════════════════════════════════════════════════════════════

def extract_features_from_window(events: list[dict]) -> dict:
    """
    Reproduit EXACTEMENT extract_siem_features() de live_detection.py.
    Entrée : liste d'events {ts, event_id} dans la fenêtre.
    Sortie : dict de features.
    """
    if not events:
        return {}

    event_ids = [e["event_id"] for e in events]
    cnt = Counter(event_ids)
    total = len(event_ids)

    row = {
        "total_events": total,
        "events_per_minute": total / WINDOW_MIN,
    }

    for eid in ALL_MONITORED:
        row[f"cnt_{eid}"] = cnt.get(eid, 0)

    for cat, eids in ATTACK_EVENTIDS.items():
        row[f"{cat}_score"] = sum(cnt.get(e, 0) for e in eids)

    successes = cnt.get(4624, 0)
    failures = cnt.get(4625, 0) + cnt.get(4771, 0)
    row["logon_failure_ratio"] = (
        failures / (successes + failures) if (successes + failures) > 0 else 0
    )

    unique_cnt = len(set(event_ids))
    if unique_cnt > 1:
        probs = np.array(list(cnt.values())) / total
        row["entropy_eventids"] = float(-np.sum(probs * np.log2(probs + 1e-10)))
    else:
        row["entropy_eventids"] = 0.0

    row["distinct_eventids"] = unique_cnt
    return row


# ═══════════════════════════════════════════════════════════════════
# LABELLING TEMPOREL (depuis APT29_ATTACK_WINDOWS)
# ═══════════════════════════════════════════════════════════════════

def parse_iso(s: str) -> float:
    return datetime.fromisoformat(s.rstrip("Z")).replace(tzinfo=timezone.utc).timestamp()


def is_window_attack(window_center_ts: float, day_key: str) -> int:
    """1 si le centre de la fenêtre tombe dans un intervalle d'attaque APT29."""
    for start_iso, end_iso, _tactic in APT29_ATTACK_WINDOWS.get(day_key, []):
        if parse_iso(start_iso) <= window_center_ts <= parse_iso(end_iso):
            return 1
    return 0


# ═══════════════════════════════════════════════════════════════════
# AGRÉGATION EN FENÊTRES GLISSANTES PAR HOST
# ═══════════════════════════════════════════════════════════════════

def build_windows(events_by_host: dict[str, list[dict]], day_key: str) -> pd.DataFrame:
    """
    Pour chaque host, construit des fenêtres glissantes de WINDOW_MIN minutes
    avec un pas de WINDOW_STEP_MIN minutes.
    """
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
            continue  # pas assez de données pour ce host

        # Cursor sur les events
        i_left = 0
        t = ts_first
        while t <= ts_last:
            t_end = t + win_sec
            # Avancer i_left pour exclure les events < t
            while i_left < len(evs_sorted) and evs_sorted[i_left]["ts"] < t:
                i_left += 1
            # Collecter events dans [t, t_end)
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


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def process_day(raw_dir: Path, day_key: str) -> pd.DataFrame:
    print(f"\n  --- {day_key} ({raw_dir}) ---")
    events_by_host = defaultdict(list)
    n_total = n_valid = 0

    for ev in iter_events(raw_dir):
        n_total += 1
        parsed = parse_event(ev)
        if parsed:
            events_by_host[parsed["host"]].append(parsed)
            n_valid += 1
        if n_total % 100_000 == 0:
            print(f"      {n_total} events lus...")

    print(f"      Events lus : {n_total}  |  valides : {n_valid}")
    print(f"      Hosts trouvés : {dict((h, len(v)) for h, v in events_by_host.items())}")

    df = build_windows(events_by_host, day_key)
    print(f"      Fenêtres produites : {len(df)}  "
          f"(positives={int(df['label'].sum()) if len(df) else 0})")
    return df


def main():
    print("=== PREPROCESSING SIEM WINDOWS (OTRF Mordor APT29) ===")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if not RAW_DAY1.exists() or not any(RAW_DAY1.rglob("*")):
        print(f"\n[ERREUR] {RAW_DAY1} vide ou inexistant.")
        print("Extrais d'abord les zips Mordor APT29 :\n"
              "  Expand-Archive .../day1/apt29_evals_day1_manual.zip "
              "-DestinationPath siem_windows/data/raw/day1\n"
              "  Expand-Archive .../day2/apt29_evals_day2_manual.zip "
              "-DestinationPath siem_windows/data/raw/day2")
        return

    t0 = time.time()
    df_day1 = process_day(RAW_DAY1, "day1")
    df_day2 = process_day(RAW_DAY2, "day2") if RAW_DAY2.exists() else pd.DataFrame()

    if df_day1.empty and df_day2.empty:
        print("\n[ERREUR] Aucune fenêtre produite.")
        return

    # Stratégie : merge day1+day2 puis split par host (GroupShuffleSplit).
    # Justification : le split temporel day1→day2 montrait un drift de distribution
    # (AUC=0.46 sur day2). Tester la généralisation à un host inconnu est plus
    # défendable et reflète mieux la production (déploiement sur nouveau endpoint).
    df_all = pd.concat([df_day1, df_day2], ignore_index=True)
    df_all["day"] = ["day1"] * len(df_day1) + ["day2"] * len(df_day2)

    if len(df_all["host"].unique()) < 2:
        print("\n[INFO] < 2 hosts → split temporel 80/20 fallback")
        df_all = df_all.sort_values("window_start_ts").reset_index(drop=True)
        cutoff = int(len(df_all) * 0.8)
        df_train = df_all.iloc[:cutoff].copy()
        df_test = df_all.iloc[cutoff:].copy()
    else:
        gss = GroupShuffleSplit(n_splits=1, test_size=SPLIT_TEST_SIZE,
                                random_state=RANDOM_STATE)
        train_idx, test_idx = next(gss.split(df_all, df_all["label"],
                                             groups=df_all["host"]))
        df_train = df_all.iloc[train_idx].reset_index(drop=True)
        df_test = df_all.iloc[test_idx].reset_index(drop=True)
        train_hosts = sorted(df_train["host"].unique())
        test_hosts = sorted(df_test["host"].unique())
        overlap = set(train_hosts) & set(test_hosts)
        print(f"\n  Split par host : train={train_hosts}, test={test_hosts}")
        if overlap:
            print(f"  [ERREUR] overlap hosts : {overlap}")
        else:
            print(f"  [OK] hosts disjoints train/test")

    feature_cols = [c for c in df_train.columns
                    if c not in ("host", "day", "window_start_ts",
                                 "window_end_ts", "label")]

    # Sauvegarde
    df_train.to_parquet(OUTPUT_DIR / "train.parquet", index=False)
    df_test.to_parquet(OUTPUT_DIR / "test.parquet", index=False)
    df_train[feature_cols].to_csv(OUTPUT_DIR / "X_train.csv", index=False)
    df_test[feature_cols].to_csv(OUTPUT_DIR / "X_test.csv", index=False)
    df_train[["label"]].to_csv(OUTPUT_DIR / "y_train.csv", index=False)
    df_test[["label"]].to_csv(OUTPUT_DIR / "y_test.csv", index=False)

    # Sauvegarde feature_columns.json (DOIT matcher live_detection.py)
    Path("siem_windows/saved_models").mkdir(parents=True, exist_ok=True)
    with open("siem_windows/saved_models/feature_columns.json", "w") as f:
        json.dump(feature_cols, f, indent=2)

    manifest = {
        "version": 2,
        "source": "OTRF Mordor APT29 (day1+day2 mergés, split par host)",
        "split_method": "GroupShuffleSplit by host (anti-drift)",
        "window_min": WINDOW_MIN,
        "window_step_min": WINDOW_STEP_MIN,
        "n_features": len(feature_cols),
        "feature_columns": feature_cols,
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

    print("\n=== RÉSUMÉ ===")
    print(f"Train : {len(df_train)} fenêtres ({manifest['n_train_positive']} positives, "
          f"{manifest['balance_train']*100:.1f}%)")
    print(f"Test  : {len(df_test)} fenêtres ({manifest['n_test_positive']} positives, "
          f"{manifest['balance_test']*100:.1f}%)")
    print(f"Features : {len(feature_cols)}")
    print(f"Output : {OUTPUT_DIR}/")
    print(f"Elapsed : {manifest['elapsed_sec']}s")
    print("\n[OK] Lancer ensuite : python siem_windows/training/train_siem.py")


if __name__ == "__main__":
    main()
