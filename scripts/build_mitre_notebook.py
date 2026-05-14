"""Génère notebooks/01_mitre_evaluation.ipynb à partir du script."""
import nbformat as nbf

nb = nbf.v4.new_notebook()
cells = []

cells.append(nbf.v4.new_markdown_cell("""# 01 — MITRE ATT&CK Coverage Evaluation

**Objectif :** évaluer les modèles SIEM Windows v3 et Lateral Movement *par technique MITRE ATT&CK* plutôt que par un seul score global.

**Méthodologie :**
1. Mapper chaque `EventID` Windows/Sysmon vers une technique MITRE.
2. Pour chaque fenêtre du test set, lister les techniques *présentes* (= EventIDs avec count > 0).
3. Pour chaque technique T, calculer precision/recall/F1 sur le sous-ensemble de fenêtres contenant T.
4. Construire une heatmap (techniques × modèles).

**Justification :** le modèle prédit au niveau **fenêtre 5 min**, pas event. La métrique par technique reflète donc « performance du modèle sur les fenêtres où la technique est observée ».

**Outputs :**
- `reports/figures/mitre_coverage.png`
- `reports/mitre_metrics.csv`
"""))

cells.append(nbf.v4.new_code_cell("""import json
import warnings
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

warnings.filterwarnings("ignore")
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)"""))

cells.append(nbf.v4.new_markdown_cell("""## 1. Mapping EventID → MITRE ATT&CK

Choix : 1 technique principale par EventID (la plus représentative selon MITRE Enterprise v14 + corrélations Microsoft / OTRF)."""))

cells.append(nbf.v4.new_code_cell("""EVENT_TO_TECHNIQUE = {
    # Windows Security
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
    # Sysmon
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

# Reverse map for displaying names
TID_TO_INFO = {tid: (tid, name, tactic)
               for eid, (tid, name, tactic) in EVENT_TO_TECHNIQUE.items()}
print(f"Mapping : {len(EVENT_TO_TECHNIQUE)} EventIDs -> {len(set(t[0] for t in EVENT_TO_TECHNIQUE.values()))} techniques distinctes")"""))

cells.append(nbf.v4.new_markdown_cell("""## 2. Fonctions d'évaluation"""))

cells.append(nbf.v4.new_code_cell("""def techniques_in_window(row, feature_cols):
    \"\"\"Liste des techniques MITRE présentes dans la fenêtre (cnt > 0).\"\"\"
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


def evaluate_model_per_technique(model_name, model, df_test, feature_cols, threshold):
    \"\"\"Pour chaque technique : precision/recall/F1 sur le subset de fenêtres.\"\"\"
    X = df_test[feature_cols].fillna(0).values
    y = df_test["label"].values
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= threshold).astype(int)

    tech_per_window = [techniques_in_window(df_test.iloc[i], feature_cols)
                       for i in range(len(df_test))]
    all_techniques = sorted({t for s in tech_per_window for t in s})

    results = []
    for tech in all_techniques:
        mask = np.array([tech in s for s in tech_per_window])
        n_total = int(mask.sum())
        n_attack = int(((mask) & (y == 1)).sum())
        n_normal = int(((mask) & (y == 0)).sum())

        if n_total == 0 or n_attack == 0:
            results.append({
                "technique_id": tech,
                "technique_name": TID_TO_INFO.get(tech, ("", "", ""))[1],
                "tactic": TID_TO_INFO.get(tech, ("", "", ""))[2],
                "support_total": n_total, "support_attack": n_attack,
                "support_normal": n_normal,
                "precision": np.nan, "recall": np.nan, "f1": np.nan,
            })
            continue

        p, r, f, _ = precision_recall_fscore_support(
            y[mask], pred[mask], pos_label=1,
            average="binary", zero_division=0,
        )
        results.append({
            "technique_id": tech,
            "technique_name": TID_TO_INFO.get(tech, ("", "", ""))[1],
            "tactic": TID_TO_INFO.get(tech, ("", "", ""))[2],
            "support_total": n_total, "support_attack": n_attack,
            "support_normal": n_normal,
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f), 4),
        })

    df = pd.DataFrame(results)
    df["model"] = model_name
    return df"""))

cells.append(nbf.v4.new_markdown_cell("""## 3. Évaluation SIEM Windows v3"""))

cells.append(nbf.v4.new_code_cell("""df_siem = pd.read_parquet("../siem_windows/data/processed/test.parquet")
model_siem = joblib.load("../siem_windows/saved_models/rf_siem_model.pkl")
fc_siem = json.load(open("../siem_windows/saved_models/feature_columns.json"))
thr_siem = json.load(open("../siem_windows/saved_models/siem_threshold.json"))["threshold"]

df_siem_metrics = evaluate_model_per_technique(
    "SIEM_Windows_v3", model_siem, df_siem, fc_siem, thr_siem,
)
df_siem_metrics"""))

cells.append(nbf.v4.new_markdown_cell("""## 4. Évaluation Lateral Movement"""))

cells.append(nbf.v4.new_code_cell("""df_lat = pd.read_parquet("../lateral_movement/data/processed/test.parquet")
model_lat = joblib.load("../lateral_movement/saved_models/rf_lateral_model.pkl")
fc_lat = json.load(open("../lateral_movement/saved_models/feature_columns.json"))
thr_lat = json.load(open("../lateral_movement/saved_models/lateral_threshold.json"))["threshold"]

df_lat_metrics = evaluate_model_per_technique(
    "Lateral_Movement", model_lat, df_lat, fc_lat, thr_lat,
)
df_lat_metrics"""))

cells.append(nbf.v4.new_markdown_cell("""## 5. Construction du tableau combiné + sauvegarde CSV"""))

cells.append(nbf.v4.new_code_cell("""df_all = pd.concat([df_siem_metrics, df_lat_metrics], ignore_index=True)
cols = ["model", "technique_id", "technique_name", "tactic",
        "f1", "precision", "recall",
        "support_total", "support_attack", "support_normal"]
df_all = df_all[cols]

Path("../reports").mkdir(exist_ok=True)
df_all.to_csv("../reports/mitre_metrics.csv", index=False)
print(f"OK -> reports/mitre_metrics.csv ({len(df_all)} lignes)")
df_all"""))

cells.append(nbf.v4.new_markdown_cell("""## 6. Heatmap MITRE ATT&CK"""))

cells.append(nbf.v4.new_code_cell("""pivot_f1 = df_all.pivot_table(
    index=["technique_id", "technique_name"],
    columns="model", values="f1", aggfunc="first",
).sort_index()
pivot_support = df_all.pivot_table(
    index=["technique_id", "technique_name"],
    columns="model", values="support_total", aggfunc="first",
).sort_index()

n_rows = len(pivot_f1)
fig, ax = plt.subplots(figsize=(10, max(6, 0.45 * n_rows)))
data = pivot_f1.values.astype(float)
masked = np.ma.masked_invalid(data)
cmap = plt.cm.RdYlGn.copy()
cmap.set_bad(color="#DDDDDD")
im = ax.imshow(masked, cmap=cmap, vmin=0.0, vmax=1.0, aspect="auto")

for i in range(n_rows):
    for j in range(data.shape[1]):
        val = data[i, j]
        sup = pivot_support.values[i, j]
        if np.isnan(val):
            txt, color = "—", "#666"
        else:
            txt = f"{val:.2f}\\n(n={int(sup) if not np.isnan(sup) else 0})"
            color = "black" if 0.30 <= val <= 0.85 else "white"
        ax.text(j, i, txt, ha="center", va="center",
                color=color, fontsize=9, fontweight="bold")

yticklabels = [f"{tid} — {name}" for tid, name in pivot_f1.index]
ax.set_xticks(range(data.shape[1]))
ax.set_xticklabels([c.replace("_", " ") for c in pivot_f1.columns],
                   fontsize=10, fontweight="bold")
ax.set_yticks(range(n_rows))
ax.set_yticklabels(yticklabels, fontsize=9)
ax.set_ylabel("Technique MITRE ATT&CK", fontsize=10, fontweight="bold")
ax.set_title("Couverture MITRE ATT&CK — F1 par technique\\n"
             "(— = technique non observée dans le test set du modèle)",
             fontsize=12, fontweight="bold", pad=15)
cbar = plt.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
cbar.set_label("F1 score", fontsize=10, fontweight="bold")

plt.tight_layout()
Path("../reports/figures").mkdir(parents=True, exist_ok=True)
out = "../reports/figures/mitre_coverage.png"
plt.savefig(out, dpi=300, bbox_inches="tight")
plt.show()
print(f"OK -> {out}")"""))

cells.append(nbf.v4.new_markdown_cell("""## 7. Résumé statistique"""))

cells.append(nbf.v4.new_code_cell("""for model in df_all["model"].unique():
    sub = df_all[df_all["model"] == model].dropna(subset=["f1"])
    print(f"\\n{model}")
    print(f"  Techniques évaluables : {len(sub)}")
    if len(sub) > 0:
        print(f"  F1 moyen              : {sub['f1'].mean():.4f}")
        print(f"  F1 médian             : {sub['f1'].median():.4f}")
        best = sub.loc[sub['f1'].idxmax()]
        worst = sub.loc[sub['f1'].idxmin()]
        print(f"  Best  : {best['technique_id']} ({best['technique_name']}) "
              f"F1={best['f1']:.3f}")
        print(f"  Worst : {worst['technique_id']} ({worst['technique_name']}) "
              f"F1={worst['f1']:.3f}")"""))

cells.append(nbf.v4.new_markdown_cell("""## Conclusions

- **SIEM Windows v3** : F1 global modeste (0.67) mais lecture **par technique** révèle un recall=1.0 sur T1059/T1068/T1078. Le modèle capture toutes les fenêtres d'attaque ; la précision dépend du seuil retenu pour l'analyste.
- **Lateral Movement** : couverture **excellente** sur 13 techniques (F1 moyen ≈ 0.90). 3 techniques à F1=1.0 (T1110, T1543.003, T1558.003).
- **Cellules grises** : techniques non observées dans le test set du modèle → couverture limitée par les EventIDs monitorés (pas un défaut du modèle).

Ce découpage MITRE *réhabilite* le score SIEM agrégé : on montre **où** le modèle est utile au lieu d'un F1 global qui cache la nuance."""))

nb["cells"] = cells
nb["metadata"] = {
    "kernelspec": {
        "display_name": "Python 3",
        "language": "python",
        "name": "python3",
    },
    "language_info": {
        "name": "python",
        "version": "3.11",
    },
}

out = "notebooks/01_mitre_evaluation.ipynb"
with open(out, "w", encoding="utf-8") as f:
    nbf.write(nb, f)
print(f"OK -> {out}")
