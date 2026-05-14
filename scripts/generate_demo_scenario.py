"""Génère data/demo/attack_scenario.jsonl — kill chain APT 60 s.

Stratégie : phases d'attaque utilisent des ÉCHANTILLONS RÉELS issus des
test sets des 4 modèles (défendable scientifiquement, signal cohérent
avec ce que le modèle a appris).

Timeline :
  t=0..20s   : ~110 events bénins (NetFlow réels labels="Normal Traffic",
               syscalls Linux labels=normal)
  t=20s      : Reconnaissance — NetFlow "Port Scanning" réels (CIC-IDS)
  t=25s      : Initial Access — Lateral window réelle pos (brute force)
  t=35s      : Execution — Lateral window réelle (process creation)
  t=45s      : Lateral Movement — SIEM + Lateral windows réelles
  t=50s      : Privilege Escalation — SIEM window réelle
  t=55s      : Data Staging — NetFlow "Web Attacks" / "Brute Force" réels
"""
import json
import random
from pathlib import Path

import pandas as pd

random.seed(42)

OUT = Path("data/demo/attack_scenario.jsonl")
OUT.parent.mkdir(parents=True, exist_ok=True)

T0 = 1717000000.0  # 2024-05-29 epoch (arbitraire, lisible)
HOST_VICTIM = "PC1-CORP"
HOST_SERVER = "DC01-CORP"
HOST_LINUX = "WEB-LINUX-01"

# Feature columns attendues (alignées sur les artefacts en models/)
SIEM_FEATURES = [
    "total_events", "events_per_minute",
    "cnt_4624", "cnt_4648", "cnt_4672", "cnt_4688", "cnt_4697", "cnt_4702",
    "cnt_4720", "cnt_4728", "cnt_4732", "cnt_4738", "cnt_4798", "cnt_4799",
    "lateral_move_score", "persistence_score", "priv_escalation_score",
    "recon_score", "execution_score", "entropy_eventids", "distinct_eventids",
]
LATERAL_FEATURES = [
    "total_events", "events_per_minute",
    "cnt_1", "cnt_3", "cnt_7", "cnt_8", "cnt_12", "cnt_13", "cnt_22",
    "cnt_4103", "cnt_4104", "cnt_4624", "cnt_4625", "cnt_4648", "cnt_4672",
    "cnt_4688", "cnt_4697", "cnt_4698", "cnt_4702", "cnt_4768", "cnt_4769",
    "cnt_4771",
    "logon_success_score", "logon_failure_score", "explicit_creds_score",
    "special_privs_score", "service_create_score", "wmi_score",
    "kerberos_tgs_score", "kerberos_tgt_score", "process_create_score",
    "network_conn_score", "remote_thread_score", "image_load_score",
    "registry_score",
    "distinct_target_users", "distinct_src_users", "distinct_src_ips",
    "distinct_logon_types", "network_logon_ratio", "rdp_logon_ratio",
    "logon_failure_ratio", "entropy_eventids", "distinct_eventids",
]


def empty_window(feats):
    return {f: 0.0 for f in feats}


def benign_siem_window(intensity=1.0):
    """Fenêtre quasi vide : très peu d'activité Windows monitorée
    (l'essentiel des events sont des Sysmon hors monitor du SIEM)."""
    w = empty_window(SIEM_FEATURES)
    w["total_events"] = 30 + random.randint(0, 15)
    w["events_per_minute"] = w["total_events"] / 5
    w["distinct_eventids"] = random.randint(2, 4)
    w["entropy_eventids"] = round(random.uniform(0.3, 0.9), 2)
    return w


def benign_lateral_window():
    """Fenêtre lateral movement bénigne."""
    w = empty_window(LATERAL_FEATURES)
    w["total_events"] = 20 + random.randint(0, 15)
    w["events_per_minute"] = w["total_events"] / 5
    w["cnt_1"] = random.randint(2, 8)
    w["process_create_score"] = w["cnt_1"]
    w["distinct_target_users"] = 1
    w["distinct_src_ips"] = 1
    w["distinct_logon_types"] = 1
    w["entropy_eventids"] = round(random.uniform(0.4, 1.0), 2)
    w["distinct_eventids"] = random.randint(2, 4)
    return w


def benign_netflow():
    """Flux NetFlow réaliste — pattern bénin (long, packets équilibrés)."""
    return {
        "Flow Duration": random.uniform(5e6, 5e7),
        "Total Fwd Packets": random.randint(10, 80),
        "Total Backward Packets": random.randint(10, 80),
        "Fwd Packet Length Std": random.uniform(80, 250),
        "Bwd Packet Length Std": random.uniform(80, 250),
    }


# ────────────────────────────────────────────────────────────────────
# Chargement des échantillons RÉELS pour les phases d'attaque
# ────────────────────────────────────────────────────────────────────
def load_cicids_samples():
    """Charge quelques flux NetFlow normaux + attaques depuis le test set.
    NOTE : X_test.csv est DEJA scalé -> on inverse_transform pour
    obtenir les valeurs brutes attendues par l'orchestrateur (qui re-scale)."""
    import joblib
    X = pd.read_csv("cicids2017/data/processed_v2/X_test.csv")
    y = pd.read_csv("cicids2017/data/processed_v2/y_test.csv")
    le = joblib.load("models/cicids/label_encoder.pkl")
    scaler = joblib.load("models/cicids/scaler.pkl")
    # Inverse scaling pour obtenir les features brutes
    X_raw = pd.DataFrame(scaler.inverse_transform(X.values), columns=X.columns)
    X_raw["__y__"] = y.iloc[:, 0].values
    X_raw["__label__"] = X_raw["__y__"].apply(lambda i: le.classes_[int(i)])
    return X_raw

def load_siem_pos_neg():
    """SIEM v4 : test set issu de processed_v4/ (95 features post-pruning)."""
    df = pd.read_parquet("siem_windows/data/processed_v4/test.parquet")
    fc = json.load(open("siem_windows/saved_models_v4/feature_columns.json"))
    return df, fc

def load_lateral_pos_neg():
    df = pd.read_parquet("lateral_movement/data/processed/test.parquet")
    fc = json.load(open("lateral_movement/saved_models/feature_columns.json"))
    return df, fc

cicids_samples = load_cicids_samples()
siem_df, siem_fc = load_siem_pos_neg()
lat_df, lat_fc = load_lateral_pos_neg()

events = []
eid = 0

# ────────────────────────────────────────────────────────────────────
# Phase 1 : t=0..20s, 110 events bénins (NetFlow + Linux syscalls).
# Le collector réel ne pousse de fenêtre SIEM que quand assez d'events
# Security sont observés -> pas de fenêtres bénignes ici (réaliste).
# ────────────────────────────────────────────────────────────────────
normal_flows = cicids_samples[cicids_samples["__label__"] == "Normal Traffic"].sample(
    n=80, random_state=42,
)
for i, (_, row) in enumerate(normal_flows.iterrows()):
    eid += 1
    t = T0 + (i * 20 / 80)
    feats = {c: float(row[c]) for c in row.index
             if c not in ("__y__", "__label__")}
    events.append({
        "event_id": f"e{eid}", "source": "netflow",
        "host": HOST_VICTIM, "timestamp": t,
        "features": feats,
    })

# Quelques syscalls Linux bénins
for i in range(30):
    eid += 1
    t = T0 + random.uniform(0, 20)
    seq = " ".join(random.choices(
        ["open close read write fstat", "mmap brk read close",
         "execve open close write", "stat fstat read close"],
        k=1,
    ))
    events.append({
        "event_id": f"e{eid}", "source": "linux_syscall",
        "host": HOST_LINUX, "timestamp": t,
        "syscall_sequence": seq,
        "features": {},
    })

# ────────────────────────────────────────────────────────────────────
# t=20s : Reconnaissance réseau (flux Port Scanning RÉELS du test set)
# ────────────────────────────────────────────────────────────────────
scan_flows = cicids_samples[cicids_samples["__label__"] == "Port Scanning"].sample(
    n=5, random_state=42,
)
for i, (_, row) in enumerate(scan_flows.iterrows()):
    eid += 1
    t = T0 + 20 + i * 0.3
    feats = {c: float(row[c]) for c in row.index
             if c not in ("__y__", "__label__")}
    events.append({
        "event_id": f"e{eid}", "source": "netflow",
        "host": HOST_VICTIM, "timestamp": t,
        "features": feats, "phase": "reconnaissance",
    })

# ────────────────────────────────────────────────────────────────────
# t=25s : Initial Access — Brute Force (NetFlow réel "Brute Force" CIC-IDS
# + Lateral window pos réelle)
# ────────────────────────────────────────────────────────────────────
brute_flows = cicids_samples[cicids_samples["__label__"] == "Brute Force"].sample(
    n=3, random_state=42,
)
for i, (_, row) in enumerate(brute_flows.iterrows()):
    eid += 1
    t = T0 + 25 + i * 0.4
    feats = {c: float(row[c]) for c in row.index
             if c not in ("__y__", "__label__")}
    events.append({
        "event_id": f"e{eid}", "source": "netflow",
        "host": HOST_VICTIM, "timestamp": t,
        "features": feats, "phase": "initial_access",
    })

# Une fenêtre Lateral RÉELLE positive (cherche celle avec le plus haut score)
lat_pos = lat_df[lat_df["label"] == 1].sample(n=1, random_state=42).iloc[0]
eid += 1
events.append({
    "event_id": f"e{eid}", "source": "identity_event",
    "host": HOST_VICTIM, "timestamp": T0 + 26,
    "features": {c: float(lat_pos[c]) for c in lat_fc},
    "phase": "initial_access",
})

# ────────────────────────────────────────────────────────────────────
# t=35s : Execution — fenêtre SIEM positive réelle + Lateral pos réelle
# ────────────────────────────────────────────────────────────────────
siem_pos = siem_df[siem_df["label"] == 1].sample(n=1, random_state=42).iloc[0]
eid += 1
events.append({
    "event_id": f"e{eid}", "source": "windows_event",
    "host": HOST_VICTIM, "timestamp": T0 + 35,
    "features": {c: float(siem_pos[c]) for c in siem_fc},
    "phase": "execution",
})

lat_pos2 = lat_df[lat_df["label"] == 1].sample(n=1, random_state=7).iloc[0]
eid += 1
events.append({
    "event_id": f"e{eid}", "source": "identity_event",
    "host": HOST_VICTIM, "timestamp": T0 + 36,
    "features": {c: float(lat_pos2[c]) for c in lat_fc},
    "phase": "execution",
})

# ────────────────────────────────────────────────────────────────────
# t=45s : Lateral Movement — Lateral pos + SIEM pos (DC01)
# ────────────────────────────────────────────────────────────────────
lat_pos3 = lat_df[lat_df["label"] == 1].sample(n=1, random_state=123).iloc[0]
eid += 1
events.append({
    "event_id": f"e{eid}", "source": "identity_event",
    "host": HOST_SERVER, "timestamp": T0 + 45,
    "features": {c: float(lat_pos3[c]) for c in lat_fc},
    "phase": "lateral_movement",
})

siem_pos2 = siem_df[siem_df["label"] == 1].sample(n=1, random_state=2).iloc[0]
eid += 1
events.append({
    "event_id": f"e{eid}", "source": "windows_event",
    "host": HOST_SERVER, "timestamp": T0 + 46,
    "features": {c: float(siem_pos2[c]) for c in siem_fc},
    "phase": "lateral_movement",
})

# ────────────────────────────────────────────────────────────────────
# t=50s : Privilege Escalation — fenêtre SIEM pos réelle
# ────────────────────────────────────────────────────────────────────
siem_pos3 = siem_df[siem_df["label"] == 1].sample(n=1, random_state=33).iloc[0]
eid += 1
events.append({
    "event_id": f"e{eid}", "source": "windows_event",
    "host": HOST_SERVER, "timestamp": T0 + 50,
    "features": {c: float(siem_pos3[c]) for c in siem_fc},
    "phase": "privilege_escalation",
})

# ────────────────────────────────────────────────────────────────────
# t=55s : Data Staging — NetFlow Web Attacks réels
# ────────────────────────────────────────────────────────────────────
web_flows = cicids_samples[cicids_samples["__label__"] == "Web Attacks"].sample(
    n=4, random_state=42,
)
for i, (_, row) in enumerate(web_flows.iterrows()):
    eid += 1
    feats = {c: float(row[c]) for c in row.index
             if c not in ("__y__", "__label__")}
    events.append({
        "event_id": f"e{eid}", "source": "netflow",
        "host": HOST_SERVER, "timestamp": T0 + 55 + i * 0.5,
        "features": feats, "phase": "exfiltration",
    })

# Tri par timestamp pour réalisme de stream
events.sort(key=lambda e: e["timestamp"])
print(f"Total events : {len(events)}")

with OUT.open("w", encoding="utf-8") as f:
    for ev in events:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
print(f"OK -> {OUT}")
