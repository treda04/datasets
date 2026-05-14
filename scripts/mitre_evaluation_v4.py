"""MITRE coverage v4 — SIEM (LightGBM v4) + Lateral inchangé."""
import json
import warnings
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

warnings.filterwarnings("ignore")
RANDOM_STATE = 42
np.random.seed(RANDOM_STATE)

# Re-use mapping
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.orchestrator.mitre_mapping import EVENT_TO_TECHNIQUE

# Add Sysmon mapping enrichi pour v4
EVENT_TO_TECHNIQUE_V4 = dict(EVENT_TO_TECHNIQUE)
EVENT_TO_TECHNIQUE_V4.update({
    # NOUVEAUX EventIDs Sysmon monitorés en v4
    5447: ("T1562",     "Impair Defenses (WFP)",         "Defense Evasion"),
    5154: ("T1071",     "Application Layer Protocol",    "Command and Control"),
    5156: ("T1071",     "Application Layer Protocol",    "Command and Control"),
    5158: ("T1071",     "Application Layer Protocol",    "Command and Control"),
    800:  ("T1059.001", "PowerShell",                    "Execution"),
    4656: ("T1106",     "Native API",                    "Execution"),
    4658: ("T1106",     "Native API",                    "Execution"),
    4663: ("T1083",     "File and Directory Discovery",  "Discovery"),
    4703: ("T1134",     "Access Token Manipulation",     "Privilege Escalation"),
})
TID_TO_INFO = {tid: (tid, name, tactic)
               for eid, (tid, name, tactic) in EVENT_TO_TECHNIQUE_V4.items()}


def techniques_in_window(row, fcols):
    techs = set()
    for col in fcols:
        if col.startswith("cnt_"):
            try:
                eid = int(col[4:])
            except ValueError:
                continue
            if eid in EVENT_TO_TECHNIQUE_V4 and row[col] > 0:
                techs.add(EVENT_TO_TECHNIQUE_V4[eid][0])
    return techs


def evaluate(model_name, model, df, fc, thr):
    X = df[fc].fillna(0).values
    y = df["label"].values
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= thr).astype(int)
    techs_per_win = [techniques_in_window(df.iloc[i], fc) for i in range(len(df))]
    all_techs = sorted({t for s in techs_per_win for t in s})

    rows = []
    for tech in all_techs:
        mask = np.array([tech in s for s in techs_per_win])
        n_tot = int(mask.sum())
        n_atk = int((mask & (y == 1)).sum())
        n_nrm = int((mask & (y == 0)).sum())
        if n_tot == 0 or n_atk == 0:
            rows.append({"technique_id": tech,
                          "technique_name": TID_TO_INFO.get(tech, ("", "", ""))[1],
                          "tactic": TID_TO_INFO.get(tech, ("", "", ""))[2],
                          "support_total": n_tot, "support_attack": n_atk,
                          "support_normal": n_nrm,
                          "precision": np.nan, "recall": np.nan, "f1": np.nan})
            continue
        p, r, f, _ = precision_recall_fscore_support(
            y[mask], pred[mask], pos_label=1, average="binary", zero_division=0,
        )
        rows.append({"technique_id": tech,
                      "technique_name": TID_TO_INFO.get(tech, ("", "", ""))[1],
                      "tactic": TID_TO_INFO.get(tech, ("", "", ""))[2],
                      "support_total": n_tot, "support_attack": n_atk,
                      "support_normal": n_nrm,
                      "precision": round(float(p), 4),
                      "recall": round(float(r), 4),
                      "f1": round(float(f), 4)})
    df = pd.DataFrame(rows)
    df["model"] = model_name
    return df


def main():
    print("=== MITRE COVERAGE v4 ===\n")
    # SIEM v4 (LightGBM)
    df_siem = pd.read_parquet("siem_windows/data/processed_v4/test.parquet")
    model_siem = joblib.load("siem_windows/saved_models_v4/rf_siem_model.pkl")
    fc_siem = json.load(open("siem_windows/saved_models_v4/feature_columns.json"))
    thr_siem = json.load(open("siem_windows/saved_models_v4/siem_threshold.json"))["threshold"]
    df_siem_m = evaluate("SIEM_v4_LightGBM", model_siem, df_siem, fc_siem, thr_siem)
    print(f"SIEM v4 : {len(df_siem_m)} techniques | seuil={thr_siem:.3f}")

    # Lateral inchangé
    df_lat = pd.read_parquet("lateral_movement/data/processed/test.parquet")
    model_lat = joblib.load("lateral_movement/saved_models/rf_lateral_model.pkl")
    fc_lat = json.load(open("lateral_movement/saved_models/feature_columns.json"))
    thr_lat = json.load(open("lateral_movement/saved_models/lateral_threshold.json"))["threshold"]
    df_lat_m = evaluate("Lateral_Movement", model_lat, df_lat, fc_lat, thr_lat)
    print(f"Lateral : {len(df_lat_m)} techniques | seuil={thr_lat:.3f}")

    df_all = pd.concat([df_siem_m, df_lat_m], ignore_index=True)
    cols = ["model", "technique_id", "technique_name", "tactic",
            "f1", "precision", "recall",
            "support_total", "support_attack", "support_normal"]
    df_all = df_all[cols]
    Path("reports").mkdir(exist_ok=True)
    df_all.to_csv("reports/mitre_metrics_v4.csv", index=False)
    print(f"\nOK -> reports/mitre_metrics_v4.csv ({len(df_all)} lignes)")

    # Heatmap
    pivot_f1 = df_all.pivot_table(index=["technique_id", "technique_name"],
                                    columns="model", values="f1", aggfunc="first").sort_index()
    pivot_sup = df_all.pivot_table(index=["technique_id", "technique_name"],
                                     columns="model", values="support_total", aggfunc="first").sort_index()

    n = len(pivot_f1)
    fig, ax = plt.subplots(figsize=(10, max(6, 0.45 * n)))
    data = pivot_f1.values.astype(float)
    masked = np.ma.masked_invalid(data)
    cmap = plt.cm.RdYlGn.copy()
    cmap.set_bad(color="#DDDDDD")
    im = ax.imshow(masked, cmap=cmap, vmin=0, vmax=1, aspect="auto")

    for i in range(n):
        for j in range(data.shape[1]):
            v = data[i, j]; s = pivot_sup.values[i, j]
            if np.isnan(v):
                ax.text(j, i, "—", ha="center", va="center", color="#666", fontsize=9)
            else:
                txt = f"{v:.2f}\n(n={int(s) if not np.isnan(s) else 0})"
                color = "black" if 0.30 <= v <= 0.85 else "white"
                ax.text(j, i, txt, ha="center", va="center", color=color,
                        fontsize=9, fontweight="bold")
    yt = [f"{tid} — {name}" for tid, name in pivot_f1.index]
    ax.set_xticks(range(data.shape[1]))
    ax.set_xticklabels([c.replace("_", " ") for c in pivot_f1.columns],
                        fontsize=10, fontweight="bold")
    ax.set_yticks(range(n)); ax.set_yticklabels(yt, fontsize=9)
    ax.set_ylabel("Technique MITRE ATT&CK", fontsize=10, fontweight="bold")
    ax.set_title("Couverture MITRE v4 — SIEM v4 (LightGBM) vs Lateral\n"
                 "(— = technique non observée dans le test set)",
                 fontsize=12, fontweight="bold", pad=15)
    plt.colorbar(im, ax=ax, fraction=0.04, pad=0.02).set_label("F1 score",
                                                                fontweight="bold")
    plt.tight_layout()
    out = "reports/figures/mitre_coverage_v4.png"
    plt.savefig(out, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"OK -> {out}")

    print("\n=== RÉSUMÉ v4 ===")
    for mdl in df_all["model"].unique():
        sub = df_all[df_all["model"] == mdl].dropna(subset=["f1"])
        print(f"\n{mdl}")
        print(f"  Techniques évaluables : {len(sub)}")
        if len(sub) > 0:
            print(f"  F1 moyen              : {sub['f1'].mean():.4f}")
            print(f"  F1 médian             : {sub['f1'].median():.4f}")
            best = sub.loc[sub['f1'].idxmax()]
            worst = sub.loc[sub['f1'].idxmin()]
            print(f"  Best  : {best['technique_id']} ({best['technique_name']}) F1={best['f1']:.3f}")
            print(f"  Worst : {worst['technique_id']} ({worst['technique_name']}) F1={worst['f1']:.3f}")


if __name__ == "__main__":
    main()
