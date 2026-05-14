"""
Lateral Movement EDA — exploration complète des events Atomic Red Team.

Lit les zips :
  siem_dataset/.../atomic/windows/lateral_movement/host/*.zip (positifs)
  siem_dataset/.../atomic/windows/discovery/host/*.zip          (négatifs candidats)
  siem_dataset/.../atomic/windows/collection/host/*.zip         (négatifs candidats)
  siem_dataset/.../atomic/windows/defense_evasion/host/*.zip    (à évaluer)
  siem_dataset/.../atomic/windows/persistence/host/*.zip        (à évaluer)
  siem_dataset/.../atomic/windows/credential_access/host/*.zip  (à évaluer)
  siem_dataset/.../atomic/windows/execution/host/*.zip          (à évaluer)
  siem_dataset/.../atomic/windows/privilege_escalation/host/*.zip (à évaluer)

Output :
  reports/eda/lateral_eventid_distribution.csv
  reports/eda/lateral_discriminative_eventids.csv
  reports/eda/lateral_technique_volumes.csv
  reports/figures/lateral_eda_topN_eventids.png
  reports/figures/lateral_eda_pos_vs_neg.png
"""
import io
import json
import warnings
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

ATOMIC_BASE = Path("siem_dataset/data/otrf_datasets/datasets/atomic/windows")
OUT_DIR = Path("reports/eda")
FIG_DIR = Path("reports/figures")
OUT_DIR.mkdir(parents=True, exist_ok=True)
FIG_DIR.mkdir(parents=True, exist_ok=True)


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


def iter_events_from_zip(zip_path):
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    with zf.open(name) as fp:
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


def parse_event(ev):
    eid_raw = get_field(ev, "EventID", "winlog.event_id", "event.code",
                         "Event.System.EventID", "event_id")
    try:
        eid = int(eid_raw) if eid_raw is not None else 0
    except (ValueError, TypeError):
        eid = 0
    return eid


def collect_directory(directory, label, category):
    """Pour chaque .zip du dossier, retourne dict {technique: Counter(EventID)}."""
    by_tech = defaultdict(Counter)
    n_events = 0
    if not directory.exists():
        print(f"  [skip] {directory}")
        return by_tech, n_events
    zips = sorted(directory.glob("*.zip"))
    print(f"  {category}: {len(zips)} zips")
    for zp in zips:
        technique = zp.stem
        for ev in iter_events_from_zip(zp):
            eid = parse_event(ev)
            if eid > 0:
                by_tech[technique][eid] += 1
                n_events += 1
    return by_tech, n_events


# ── Collecte ──
print("=== LATERAL EDA — Atomic Red Team ===")
print("\n[1/3] Lecture des zips...")

# Positifs : lateral_movement
pos, n_pos = collect_directory(
    ATOMIC_BASE / "lateral_movement" / "host", label=1, category="lateral_movement"
)
# Négatifs : autres tactiques (sauf lateral)
neg_cats = ["discovery", "collection", "defense_evasion",
            "persistence", "credential_access", "execution",
            "privilege_escalation"]
neg_by_cat = {}
n_neg_total = 0
for cat in neg_cats:
    by_tech, n = collect_directory(ATOMIC_BASE / cat / "host", label=0, category=cat)
    neg_by_cat[cat] = by_tech
    n_neg_total += n

print(f"\nTotal events positifs (lateral_movement) : {n_pos:,}")
print(f"Total events négatifs (autres tactiques) : {n_neg_total:,}")
print(f"  Détail négatifs : "
      f"{ {k: sum(c.total() for c in v.values()) for k, v in neg_by_cat.items()} }")

# ── Agrégation EventIDs ──
pos_counter = Counter()
for tech_cnt in pos.values():
    pos_counter.update(tech_cnt)

neg_counter = Counter()
for cat_data in neg_by_cat.values():
    for tech_cnt in cat_data.values():
        neg_counter.update(tech_cnt)

all_eids = sorted(set(pos_counter) | set(neg_counter))
print(f"\nEventIDs distincts : {len(all_eids)}")

# ── Tableau global ──
rows = []
for eid in all_eids:
    p = pos_counter[eid]
    n = neg_counter[eid]
    total = p + n
    rows.append({
        "event_id": eid,
        "total": total,
        "in_lateral": p,
        "in_other": n,
        "share_lateral": round(p / total, 4) if total > 0 else 0,
    })
df_eids = pd.DataFrame(rows).sort_values("total", ascending=False)
df_eids.to_csv(OUT_DIR / "lateral_eventid_distribution.csv", index=False)
print(f"OK -> {OUT_DIR / 'lateral_eventid_distribution.csv'}")
print(f"\nTop 20 EventIDs par volume :")
print(df_eids.head(20).to_string(index=False))

# ── Chi² discrimination ──
total_pos = sum(pos_counter.values())
total_neg = sum(neg_counter.values())
print(f"\nTotal events positifs : {total_pos:,}")
print(f"Total events négatifs : {total_neg:,}")

discrim = []
for eid in all_eids:
    p = pos_counter[eid]
    n = neg_counter[eid]
    p_p = p / max(total_pos, 1)
    p_n = n / max(total_neg, 1)
    lift = p_p / p_n if p_n > 0 else (999 if p_p > 0 else 0)
    expected_p = (p + n) * total_pos / max(total_pos + total_neg, 1)
    chi2 = ((p - expected_p) ** 2) / max(expected_p, 1) if expected_p > 0 else 0
    discrim.append({
        "event_id": eid,
        "n_lateral": p,
        "n_other": n,
        "p_lateral": round(p_p, 6),
        "p_other": round(p_n, 6),
        "lift": round(lift, 3) if lift != 999 else 999,
        "chi2": round(chi2, 2),
    })
df_d = pd.DataFrame(discrim)
df_d = df_d[(df_d["n_lateral"] + df_d["n_other"]) > 50]
df_d = df_d.sort_values("chi2", ascending=False)
df_d.to_csv(OUT_DIR / "lateral_discriminative_eventids.csv", index=False)
print(f"\nTop 20 EventIDs discriminants (lateral vs autre tactique) :")
print(df_d.head(20).to_string(index=False))

# ── Volumes par technique ──
tech_rows = []
for tech, cnt in pos.items():
    tech_rows.append({
        "category": "lateral_movement", "technique": tech,
        "n_events": cnt.total(),
        "n_distinct_eventids": len(cnt),
    })
for cat, data in neg_by_cat.items():
    for tech, cnt in data.items():
        tech_rows.append({
            "category": cat, "technique": tech,
            "n_events": cnt.total(),
            "n_distinct_eventids": len(cnt),
        })
df_tv = pd.DataFrame(tech_rows).sort_values("n_events", ascending=False)
df_tv.to_csv(OUT_DIR / "lateral_technique_volumes.csv", index=False)
print(f"\nTotal techniques inventoriées : {len(df_tv)} "
      f"(lateral={len(pos)}, autres={sum(len(v) for v in neg_by_cat.values())})")
print(df_tv.head(10).to_string(index=False))

# ── Visualisations ──
top30 = df_eids.head(30)
fig, ax = plt.subplots(figsize=(12, 8))
ax.barh(range(len(top30)), top30["total"], color="steelblue")
ax.set_yticks(range(len(top30)))
ax.set_yticklabels([f"EID {eid}" for eid in top30["event_id"]])
ax.invert_yaxis()
ax.set_xscale("log")
ax.set_xlabel("Nombre d'events (log)")
ax.set_title("Top 30 EventIDs par volume — Atomic Red Team")
plt.tight_layout()
plt.savefig(FIG_DIR / "lateral_eda_topN_eventids.png", dpi=200)
plt.close()
print(f"\nOK -> {FIG_DIR / 'lateral_eda_topN_eventids.png'}")

top20_d = df_d.head(20)
fig, ax = plt.subplots(figsize=(12, 8))
y = np.arange(len(top20_d))
ax.barh(y - 0.2, top20_d["n_lateral"], 0.4, label="In lateral_movement", color="crimson")
ax.barh(y + 0.2, top20_d["n_other"], 0.4, label="In other tactics", color="steelblue")
ax.set_yticks(y)
ax.set_yticklabels([f"EID {eid} (lift={l})"
                     for eid, l in zip(top20_d["event_id"], top20_d["lift"])])
ax.invert_yaxis()
ax.set_xscale("log")
ax.set_xlabel("Nombre d'events (log)")
ax.set_title("Top 20 EventIDs discriminants — lateral vs autre tactique")
ax.legend()
plt.tight_layout()
plt.savefig(FIG_DIR / "lateral_eda_pos_vs_neg.png", dpi=200)
plt.close()
print(f"OK -> {FIG_DIR / 'lateral_eda_pos_vs_neg.png'}")
