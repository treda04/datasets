"""
MITRE ATT&CK Coverage Evaluation — SIEM Windows v3 & Lateral Movement
======================================================================
Pour chaque modèle, on évalue les performances PAR TECHNIQUE MITRE :
  1. Map EventID Windows/Sysmon -> technique MITRE
  2. Pour chaque fenêtre du test set, lister les techniques présentes
     (= EventIDs avec cnt > 0)
  3. Pour chaque technique T : sous-ensemble de fenêtres contenant T,
     calculer precision/recall/F1 sur ce sous-ensemble
  4. Heatmap (techniques x modèles) avec F1 et support

Inputs  :
  - siem_windows/data/processed/test.parquet
  - siem_windows/saved_models/{rf_siem_model.pkl, siem_threshold.json}
  - lateral_movement/data/processed/test.parquet
  - lateral_movement/saved_models/{rf_lateral_model.pkl, lateral_threshold.json}

Outputs :
  - reports/figures/mitre_coverage.png  (heatmap 300 dpi)
  - reports/mitre_metrics.csv            (métriques par technique x modèle)

NOTE méthodologique : le modèle prédit au niveau FENÊTRE, pas event.
La métrique par technique est donc "performance du modèle sur les
fenêtres où cette technique a au moins un event observé".
"""
import json
import warnings
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap
from sklearn.metrics import precision_recall_fscore_support

warnings.filterwarnings("ignore")

RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)

# ─────────────────────────────────────────────────────────────────────
# 1) MAPPING EventID -> MITRE ATT&CK
# ─────────────────────────────────────────────────────────────────────
# Format : EventID -> (technique_id, technique_name, tactic)
# Choix : 1 technique principale par EventID (la plus représentative).
# Source : MITRE ATT&CK Enterprise v14 + corrélations Windows Security
# documentées par Microsoft et le projet OTRF.

EVENT_TO_TECHNIQUE = {
    # ─── Windows Security log ───
    4624: ("T1078",     "Valid Accounts",                "Initial Access"),
    4625: ("T1110",     "Brute Force",                   "Credential Access"),
    4648: ("T1078.002", "Domain Accounts",               "Initial Access"),
    4661: ("T1087",     "Account Discovery",             "Discovery"),
    4672: ("T1068",     "Exploitation for Priv Esc",     "Privilege Escalation"),
    4688: ("T1059",     "Command and Scripting",         "Execution"),
    4696: ("T1059",     "Command and Scripting",         "Execution"),
    4697: ("T1543.003", "Windows Service",               "Persistence"),
    4698: ("T1053.005", "Scheduled Task",                "Execution"),
    4702: ("T1053.005", "Scheduled Task",                "Execution"),
    4720: ("T1136",     "Create Account",                "Persistence"),
    4726: ("T1531",     "Account Access Removal",        "Impact"),
    4728: ("T1098",     "Account Manipulation",          "Persistence"),
    4732: ("T1098",     "Account Manipulation",          "Persistence"),
    4738: ("T1098",     "Account Manipulation",          "Persistence"),
    4756: ("T1098",     "Account Manipulation",          "Persistence"),
    4768: ("T1558.003", "Kerberoasting",                 "Credential Access"),
    4769: ("T1558.003", "Kerberoasting",                 "Credential Access"),
    4770: ("T1558",     "Steal/Forge Kerberos Tickets",  "Credential Access"),
    4771: ("T1110",     "Brute Force",                   "Credential Access"),
    4773: ("T1558",     "Steal/Forge Kerberos Tickets",  "Credential Access"),
    4776: ("T1110",     "Brute Force",                   "Credential Access"),
    4798: ("T1087",     "Account Discovery",             "Discovery"),
    4799: ("T1087.002", "Domain Account Discovery",      "Discovery"),
    # ─── Sysmon (utilisé surtout par Lateral Movement) ───
    1:    ("T1059",     "Command and Scripting",         "Execution"),
    3:    ("T1071",     "Application Layer Protocol",    "Command and Control"),
    7:    ("T1574",     "Hijack Execution Flow",         "Persistence"),
    8:    ("T1055",     "Process Injection",             "Defense Evasion"),
    12:   ("T1112",     "Modify Registry",               "Defense Evasion"),
    13:   ("T1112",     "Modify Registry",               "Defense Evasion"),
    22:   ("T1071.004", "DNS",                           "Command and Control"),
    4103: ("T1059.001", "PowerShell",                    "Execution"),
    4104: ("T1059.001", "PowerShell",                    "Execution"),
}


def techniques_in_window(row, feature_cols):
    """Retourne la liste des (technique, nom) présents dans la fenêtre
    (= au moins 1 event Windows/Sysmon mappé à cette technique)."""
    techs = set()
    for col in feature_cols:
        if col.startswith("cnt_"):
            try:
                eid = int(col[4:])
            except ValueError:
                continue
            if eid in EVENT_TO_TECHNIQUE and row[col] > 0:
                techs.add(EVENT_TO_TECHNIQUE[eid][0])
    return techs


# ─────────────────────────────────────────────────────────────────────
# 2) ÉVALUATION D'UN MODÈLE PAR TECHNIQUE
# ─────────────────────────────────────────────────────────────────────
def evaluate_model_per_technique(model_name, model, df_test, feature_cols, threshold):
    """Pour chaque technique, calcule precision/recall/F1/support sur
    les fenêtres du test set où cette technique est présente."""
    X_test = df_test[feature_cols].fillna(0).values
    y_test = df_test["label"].values

    # Prédictions du modèle
    y_proba = model.predict_proba(X_test)[:, 1]
    y_pred = (y_proba >= threshold).astype(int)

    # Pour chaque ligne : ensemble de techniques présentes
    tech_per_window = [techniques_in_window(df_test.iloc[i], feature_cols)
                       for i in range(len(df_test))]

    # Toutes les techniques observées
    all_techniques = sorted({t for s in tech_per_window for t in s})

    results = []
    for tech in all_techniques:
        mask = np.array([tech in s for s in tech_per_window])
        n_total = int(mask.sum())
        n_attack = int(((mask) & (y_test == 1)).sum())
        n_normal = int(((mask) & (y_test == 0)).sum())

        if n_total == 0 or n_attack == 0:
            # Aucune fenêtre POSITIVE contenant cette technique = pas évaluable
            results.append({
                "technique_id": tech,
                "technique_name": EVENT_TO_TECHNIQUE_BY_ID.get(tech, ("", "", ""))[1],
                "tactic": EVENT_TO_TECHNIQUE_BY_ID.get(tech, ("", "", ""))[2],
                "support_total": n_total,
                "support_attack": n_attack,
                "support_normal": n_normal,
                "precision": np.nan,
                "recall": np.nan,
                "f1": np.nan,
            })
            continue

        # Métriques sur le sous-ensemble
        try:
            p, r, f, _ = precision_recall_fscore_support(
                y_test[mask], y_pred[mask], pos_label=1,
                average="binary", zero_division=0,
            )
        except ValueError:
            p, r, f = np.nan, np.nan, np.nan

        results.append({
            "technique_id": tech,
            "technique_name": EVENT_TO_TECHNIQUE_BY_ID.get(tech, ("", "", ""))[1],
            "tactic": EVENT_TO_TECHNIQUE_BY_ID.get(tech, ("", "", ""))[2],
            "support_total": n_total,
            "support_attack": n_attack,
            "support_normal": n_normal,
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f), 4),
        })

    df = pd.DataFrame(results)
    df["model"] = model_name
    return df


# Reverse map for displaying names
EVENT_TO_TECHNIQUE_BY_ID = {}
for eid, (tid, name, tactic) in EVENT_TO_TECHNIQUE.items():
    EVENT_TO_TECHNIQUE_BY_ID[tid] = (tid, name, tactic)


# ─────────────────────────────────────────────────────────────────────
# 3) MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    print("=== ÉVALUATION MITRE ATT&CK — SIEM Windows v3 & Lateral Movement ===\n")

    # ───── SIEM Windows v3 ─────
    print("[1/3] SIEM Windows v3...")
    df_siem = pd.read_parquet("siem_windows/data/processed/test.parquet")
    model_siem = joblib.load("siem_windows/saved_models/rf_siem_model.pkl")
    fc_siem = json.load(open("siem_windows/saved_models/feature_columns.json"))
    thr_siem = json.load(open("siem_windows/saved_models/siem_threshold.json"))["threshold"]
    df_siem_metrics = evaluate_model_per_technique(
        "SIEM_Windows_v3", model_siem, df_siem, fc_siem, thr_siem,
    )
    print(f"      {len(df_siem_metrics)} techniques évaluées | "
          f"seuil = {thr_siem:.3f}")

    # ───── Lateral Movement ─────
    print("\n[2/3] Lateral Movement...")
    df_lat = pd.read_parquet("lateral_movement/data/processed/test.parquet")
    model_lat = joblib.load("lateral_movement/saved_models/rf_lateral_model.pkl")
    fc_lat = json.load(open("lateral_movement/saved_models/feature_columns.json"))
    thr_lat = json.load(open("lateral_movement/saved_models/lateral_threshold.json"))["threshold"]
    df_lat_metrics = evaluate_model_per_technique(
        "Lateral_Movement", model_lat, df_lat, fc_lat, thr_lat,
    )
    print(f"      {len(df_lat_metrics)} techniques évaluées | "
          f"seuil = {thr_lat:.3f}")

    # ───── Sauvegarde CSV ─────
    print("\n[3/3] Génération heatmap + CSV...")
    df_all = pd.concat([df_siem_metrics, df_lat_metrics], ignore_index=True)
    cols_order = ["model", "technique_id", "technique_name", "tactic",
                  "f1", "precision", "recall",
                  "support_total", "support_attack", "support_normal"]
    df_all = df_all[cols_order]
    Path("reports").mkdir(exist_ok=True)
    df_all.to_csv("reports/mitre_metrics.csv", index=False)
    print(f"      OK reports/mitre_metrics.csv ({len(df_all)} lignes)")

    # ───── Construction du tableau pivot pour heatmap ─────
    pivot_f1 = df_all.pivot_table(
        index=["technique_id", "technique_name"],
        columns="model", values="f1", aggfunc="first",
    )
    pivot_support = df_all.pivot_table(
        index=["technique_id", "technique_name"],
        columns="model", values="support_total", aggfunc="first",
    )
    # Trier par technique_id
    pivot_f1 = pivot_f1.sort_index()
    pivot_support = pivot_support.sort_index()

    # ───── Heatmap ─────
    Path("reports/figures").mkdir(parents=True, exist_ok=True)
    n_rows = len(pivot_f1)
    fig, ax = plt.subplots(figsize=(10, max(6, 0.45 * n_rows)))
    data = pivot_f1.values.astype(float)
    # Masque pour les NaN (techniques non couvertes par ce modèle)
    masked = np.ma.masked_invalid(data)
    cmap = plt.cm.RdYlGn.copy()
    cmap.set_bad(color="#DDDDDD")
    im = ax.imshow(masked, cmap=cmap, vmin=0.0, vmax=1.0, aspect="auto")

    # Annotations : "F1 (n=support)"
    for i in range(n_rows):
        for j in range(data.shape[1]):
            val = data[i, j]
            sup = pivot_support.values[i, j]
            if np.isnan(val):
                txt = "—"
                color = "#666"
            else:
                txt = f"{val:.2f}\n(n={int(sup) if not np.isnan(sup) else 0})"
                color = "black" if 0.30 <= val <= 0.85 else "white"
            ax.text(j, i, txt, ha="center", va="center",
                    color=color, fontsize=9, fontweight="bold")

    # Labels
    yticklabels = [f"{tid} — {name}" for tid, name in pivot_f1.index]
    ax.set_xticks(range(data.shape[1]))
    ax.set_xticklabels([c.replace("_", " ") for c in pivot_f1.columns],
                       rotation=0, fontsize=10, fontweight="bold")
    ax.set_yticks(range(n_rows))
    ax.set_yticklabels(yticklabels, fontsize=9)
    ax.set_xlabel("")
    ax.set_ylabel("Technique MITRE ATT&CK", fontsize=10, fontweight="bold")
    ax.set_title("Couverture MITRE ATT&CK — F1 par technique\n"
                 "(— = technique non observée dans le test set du modèle)",
                 fontsize=12, fontweight="bold", pad=15)

    # Colorbar
    cbar = plt.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cbar.set_label("F1 score", fontsize=10, fontweight="bold")

    plt.tight_layout()
    out = Path("reports/figures/mitre_coverage.png")
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"      OK {out} ({out.stat().st_size // 1024} KB)")

    # ───── Résumé console ─────
    print("\n=== RÉSUMÉ ===")
    for model in df_all["model"].unique():
        sub = df_all[df_all["model"] == model].dropna(subset=["f1"])
        print(f"\n{model} :")
        print(f"  Techniques évaluables : {len(sub)}")
        if len(sub) > 0:
            print(f"  F1 moyen              : {sub['f1'].mean():.4f}")
            print(f"  F1 médian             : {sub['f1'].median():.4f}")
            print(f"  Best technique        : {sub.loc[sub['f1'].idxmax(), 'technique_id']} "
                  f"({sub['f1'].max():.3f})")
            print(f"  Worst technique       : {sub.loc[sub['f1'].idxmin(), 'technique_id']} "
                  f"({sub['f1'].min():.3f})")


if __name__ == "__main__":
    main()
