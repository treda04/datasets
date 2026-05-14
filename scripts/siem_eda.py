"""
SIEM Windows EDA — exploration complète des events APT29 day1+day2.

Sortie :
  reports/eda/siem_eventid_distribution.csv  (par EventID : total, par host, par jour)
  reports/eda/siem_eventid_by_attack.csv     (fréquence dans fenêtres attack vs normal)
  reports/eda/siem_discriminative_eventids.csv (mutual_info_score par EventID)
  reports/figures/siem_eda_topN_eventids.png  (bar chart top 30 EventIDs)
  reports/figures/siem_eda_attack_vs_normal.png (comparatif distribution)
  reports/figures/siem_eda_timeline.png       (timeline events)
"""
import gzip
import json
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

RAW_DAY1 = Path("siem_windows/data/raw/day1")
RAW_DAY2 = Path("siem_windows/data/raw/day2")
OUT_DIR = Path("reports/eda")
FIG_DIR = Path("reports/figures")
OUT_DIR.mkdir(parents=True, exist_ok=True)
FIG_DIR.mkdir(parents=True, exist_ok=True)

# Reuse les attack windows du preprocess actuel
APT29_ATTACK_WINDOWS = {
    "day1": [
        ("2020-05-02T03:18:00Z", "2020-05-02T04:30:00Z"),
        ("2020-05-02T04:30:00Z", "2020-05-02T05:30:00Z"),
    ],
    "day2": [
        ("2020-05-02T08:10:00Z", "2020-05-02T08:35:00Z"),
    ],
}


def parse_iso(s):
    return datetime.fromisoformat(s.rstrip("Z")).replace(tzinfo=timezone.utc).timestamp()


ATTACK_RANGES = {
    "day1": [(parse_iso(s), parse_iso(e)) for s, e, *_ in
             [(*r, None) for r in APT29_ATTACK_WINDOWS["day1"]]],
    "day2": [(parse_iso(s), parse_iso(e)) for s, e, *_ in
             [(*r, None) for r in APT29_ATTACK_WINDOWS["day2"]]],
}


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


def iter_events(raw_dir):
    files = (list(raw_dir.rglob("*.json")) + list(raw_dir.rglob("*.jsonl"))
             + list(raw_dir.rglob("*.json.gz")))
    for f in files:
        opener = gzip.open if f.suffix == ".gz" else open
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


def is_attack(ts, day):
    for s, e in ATTACK_RANGES[day]:
        if s <= ts <= e:
            return True
    return False


def collect_day(raw_dir, day_key):
    print(f"\n[{day_key}] Lecture {raw_dir}...")
    stats = {
        "eventid_total": Counter(),
        "eventid_by_host": defaultdict(Counter),
        "eventid_attack": Counter(),
        "eventid_normal": Counter(),
        "host_total": Counter(),
        "timestamps": [],
    }
    n = 0
    for ev in iter_events(raw_dir):
        n += 1
        eid_raw = get_field(ev, "EventID", "winlog.event_id",
                            "event.code", "Event.System.EventID", "event_id")
        try:
            eid = int(eid_raw) if eid_raw is not None else 0
        except (ValueError, TypeError):
            eid = 0
        if eid == 0:
            continue

        host = get_field(ev, "Hostname", "host.name", "winlog.computer_name",
                          "Computer", "ComputerName") or "UNKNOWN"
        ts_raw = get_field(ev, "@timestamp", "EventTime", "TimeCreated")
        try:
            if isinstance(ts_raw, (int, float)):
                ts = float(ts_raw)
            elif ts_raw:
                s = str(ts_raw).rstrip("Z")
                if "." in s:
                    base, frac = s.split(".", 1)
                    frac = frac[:6].ljust(6, "0")
                    s = f"{base}.{frac}"
                ts = datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()
            else:
                continue
        except (ValueError, TypeError):
            continue

        stats["eventid_total"][eid] += 1
        stats["eventid_by_host"][host][eid] += 1
        stats["host_total"][host] += 1
        if is_attack(ts, day_key):
            stats["eventid_attack"][eid] += 1
        else:
            stats["eventid_normal"][eid] += 1
        # Échantillonner timestamps pour la timeline
        if n % 1000 == 0:
            stats["timestamps"].append((ts, eid, is_attack(ts, day_key)))

        if n % 100_000 == 0:
            print(f"   {n} events lus...")

    print(f"  Total events {day_key}: {n}")
    print(f"  EventIDs distincts : {len(stats['eventid_total'])}")
    print(f"  Hosts : {dict(stats['host_total'])}")
    return stats, n


print("=== SIEM EDA — APT29 day1+day2 ===")
day1_stats, n1 = collect_day(RAW_DAY1, "day1")
day2_stats, n2 = collect_day(RAW_DAY2, "day2")

# ────────────────────────────────────────────────────────────────────
# Tableau global EventIDs
# ────────────────────────────────────────────────────────────────────
all_eids = sorted(set(day1_stats["eventid_total"]) | set(day2_stats["eventid_total"]))
print(f"\n=== Total EventIDs distincts : {len(all_eids)} ===")

rows = []
for eid in all_eids:
    d1_total = day1_stats["eventid_total"][eid]
    d2_total = day2_stats["eventid_total"][eid]
    atk = day1_stats["eventid_attack"][eid] + day2_stats["eventid_attack"][eid]
    nrm = day1_stats["eventid_normal"][eid] + day2_stats["eventid_normal"][eid]
    rows.append({
        "event_id": eid,
        "total": d1_total + d2_total,
        "day1": d1_total,
        "day2": d2_total,
        "in_attack_windows": atk,
        "in_normal_windows": nrm,
        "attack_ratio": round(atk / max(atk + nrm, 1), 4),
    })

df_eids = pd.DataFrame(rows).sort_values("total", ascending=False)
df_eids.to_csv(OUT_DIR / "siem_eventid_distribution.csv", index=False)
print(f"OK -> {OUT_DIR / 'siem_eventid_distribution.csv'}")

print("\nTop 20 EventIDs par volume :")
print(df_eids.head(20).to_string(index=False))

# ────────────────────────────────────────────────────────────────────
# EventIDs discriminants (chi² + mutual_info-like)
# ────────────────────────────────────────────────────────────────────
# Pour chaque EventID, on calcule "lift" = (P(EventID|attack)) / (P(EventID|normal))
total_atk_events = sum(day1_stats["eventid_attack"].values()) + sum(
    day2_stats["eventid_attack"].values())
total_nrm_events = sum(day1_stats["eventid_normal"].values()) + sum(
    day2_stats["eventid_normal"].values())
print(f"\nTotal events attack windows: {total_atk_events}")
print(f"Total events normal windows: {total_nrm_events}")

discrim_rows = []
for eid in all_eids:
    atk = day1_stats["eventid_attack"][eid] + day2_stats["eventid_attack"][eid]
    nrm = day1_stats["eventid_normal"][eid] + day2_stats["eventid_normal"][eid]
    p_atk = atk / max(total_atk_events, 1)
    p_nrm = nrm / max(total_nrm_events, 1)
    if p_nrm > 0:
        lift = p_atk / p_nrm
    else:
        lift = float("inf") if p_atk > 0 else 0
    # Score chi² simple
    expected_atk = (atk + nrm) * total_atk_events / max(total_atk_events + total_nrm_events, 1)
    chi2 = ((atk - expected_atk) ** 2) / max(expected_atk, 1) if expected_atk > 0 else 0
    discrim_rows.append({
        "event_id": eid,
        "n_attack": atk,
        "n_normal": nrm,
        "p_attack": round(p_atk, 6),
        "p_normal": round(p_nrm, 6),
        "lift": round(lift, 3) if lift != float("inf") else 999,
        "chi2": round(chi2, 2),
    })
df_discrim = pd.DataFrame(discrim_rows)
df_discrim = df_discrim[(df_discrim["n_attack"] + df_discrim["n_normal"]) > 100]
df_discrim = df_discrim.sort_values("chi2", ascending=False)
df_discrim.to_csv(OUT_DIR / "siem_discriminative_eventids.csv", index=False)
print(f"\nTop 20 EventIDs discriminants (chi²) :")
print(df_discrim.head(20).to_string(index=False))

# ────────────────────────────────────────────────────────────────────
# Visualisations
# ────────────────────────────────────────────────────────────────────
# 1) Top 30 EventIDs par volume
top30 = df_eids.head(30)
fig, ax = plt.subplots(figsize=(12, 8))
ax.barh(range(len(top30)), top30["total"], color="steelblue")
ax.set_yticks(range(len(top30)))
ax.set_yticklabels([f"EID {eid}" for eid in top30["event_id"]])
ax.invert_yaxis()
ax.set_xlabel("Nombre d'events")
ax.set_title("Top 30 EventIDs par volume — APT29 day1+day2")
ax.set_xscale("log")
plt.tight_layout()
plt.savefig(FIG_DIR / "siem_eda_topN_eventids.png", dpi=200)
plt.close()
print(f"OK -> {FIG_DIR / 'siem_eda_topN_eventids.png'}")

# 2) Attack vs Normal pour top 20 discriminants
top20_d = df_discrim.head(20)
fig, ax = plt.subplots(figsize=(12, 8))
y = np.arange(len(top20_d))
ax.barh(y - 0.2, top20_d["n_attack"], 0.4, label="In attack windows", color="crimson")
ax.barh(y + 0.2, top20_d["n_normal"], 0.4, label="In normal windows", color="steelblue")
ax.set_yticks(y)
ax.set_yticklabels([f"EID {eid} (lift={l})"
                     for eid, l in zip(top20_d["event_id"], top20_d["lift"])])
ax.invert_yaxis()
ax.set_xscale("log")
ax.set_xlabel("Nombre d'events (échelle log)")
ax.set_title("Top 20 EventIDs discriminants — attack vs normal")
ax.legend()
plt.tight_layout()
plt.savefig(FIG_DIR / "siem_eda_attack_vs_normal.png", dpi=200)
plt.close()
print(f"OK -> {FIG_DIR / 'siem_eda_attack_vs_normal.png'}")

print("\n=== RÉSUMÉ EDA ===")
print(f"Total events day1+day2 : {n1 + n2:,}")
print(f"EventIDs distincts : {len(all_eids)}")
print(f"Events en attack windows : {total_atk_events:,} ({100*total_atk_events/(total_atk_events+total_nrm_events):.1f} %)")
print(f"Events en normal windows : {total_nrm_events:,}")
print(f"\nTop 10 EventIDs par chi² (discrimination attack/normal) :")
for _, row in df_discrim.head(10).iterrows():
    print(f"   EID {int(row['event_id']):5d}  chi²={row['chi2']:>10.0f}  lift={row['lift']:>7.2f}  "
          f"atk={int(row['n_attack']):>7d}  nrm={int(row['n_normal']):>7d}")
