"""
Lateral Movement — Évaluation enrichie + analyse par technique
===============================================================
Calcule la performance par technique de mouvement latéral
(psexec vs psremoting vs wmi vs schtask vs mimikatz_zerologon)
pour identifier les forces / faiblesses du modèle.

Lancer depuis datasets/ :
    python lateral_movement/evaluation/generate_lateral_results.py
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

warnings.filterwarnings("ignore")

DATA_DIR = Path("lateral_movement/data/processed")
ARTIFACTS_DIR = Path("lateral_movement/saved_models")
RESULTS_DIR = Path("lateral_movement/results")


def main():
    print("=== ÉVALUATION ENRICHIE LATERAL MOVEMENT ===\n")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    model = joblib.load(ARTIFACTS_DIR / "rf_lateral_model.pkl")
    threshold = json.load(open(ARTIFACTS_DIR / "lateral_threshold.json"))["threshold"]
    feature_cols = json.load(open(ARTIFACTS_DIR / "feature_columns.json"))
    df_test = pd.read_parquet(DATA_DIR / "test.parquet")

    X = df_test[feature_cols].fillna(0).values
    y = df_test["label"].values
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= threshold).astype(int)
    df_test = df_test.copy()
    df_test["score"] = proba
    df_test["pred"] = pred

    # 1. Performance par TECHNIQUE
    print("[1/3] Performance par technique...")
    rows = []
    for tech in sorted(df_test["technique"].unique()):
        sub = df_test[df_test["technique"] == tech]
        if len(sub) == 0:
            continue
        if sub["label"].iloc[0] == 1:
            tpr = float((sub["pred"] == 1).mean())
            rows.append({"technique": tech, "type": "POSITIVE",
                          "n": len(sub), "detection_rate": tpr,
                          "score_mean": float(sub["score"].mean())})
        else:
            tnr = float((sub["pred"] == 0).mean())
            rows.append({"technique": tech, "type": "NEGATIVE",
                          "n": len(sub), "detection_rate": 1 - tnr,  # = FP rate
                          "score_mean": float(sub["score"].mean())})
    df_perf = pd.DataFrame(rows).sort_values(["type", "detection_rate"], ascending=[True, False])
    df_perf.to_csv(RESULTS_DIR / "performance_by_technique.csv", index=False)
    print(df_perf.to_string(index=False))

    # 2. Bar chart par technique
    print("\n[2/3] Bar chart...")
    df_pos = df_perf[df_perf["type"] == "POSITIVE"]
    df_neg = df_perf[df_perf["type"] == "NEGATIVE"]
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    axes[0].barh(df_pos["technique"], df_pos["detection_rate"], color="darkred")
    axes[0].set_xlim(0, 1); axes[0].invert_yaxis()
    axes[0].set_xlabel("Detection rate (TPR)"); axes[0].set_title("Détection par technique LATERAL")
    axes[0].axvline(0.8, color="green", linestyle="--", alpha=0.5, label="Seuil cible 80%")
    axes[0].legend()

    axes[1].barh(df_neg["technique"], df_neg["detection_rate"], color="orange")
    axes[1].set_xlim(0, 1); axes[1].invert_yaxis()
    axes[1].set_xlabel("Faux positif rate (FPR)")
    axes[1].set_title("Faux positifs par technique NEG")
    axes[1].axvline(0.05, color="green", linestyle="--", alpha=0.5, label="Seuil cible 5%")
    axes[1].legend()
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "performance_by_technique.png", dpi=110)
    plt.close(fig)

    # 3. Distribution des scores
    print("\n[3/3] Distribution des scores...")
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(proba[y == 0], bins=40, alpha=0.6, label="Normal", color="green")
    ax.hist(proba[y == 1], bins=40, alpha=0.6, label="Lateral", color="red")
    ax.axvline(threshold, color="black", linestyle="--", label=f"Seuil = {threshold:.3f}")
    ax.set_xlabel("Score ML"); ax.set_ylabel("Nombre de fenêtres")
    ax.set_title("Distribution des scores Lateral Movement")
    ax.legend()
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "score_distribution.png", dpi=110)
    plt.close(fig)

    # HTML rapide
    html = f"""<html><head><title>Lateral Movement — Results</title></head><body>
<h1>Lateral Movement — Rapport</h1>
<p>Modèle entraîné sur Atomic Red Team, split GroupShuffleSplit par technique.</p>
<p>Seuil calibré : <b>{threshold:.3f}</b></p>
<h2>Métriques globales</h2>
<pre>{open(RESULTS_DIR / 'metrics.json').read()}</pre>
<h2>Plots</h2>
<img src="confusion_matrix.png" width="500"><br>
<img src="roc_curve.png" width="500"> <img src="pr_curve.png" width="500"><br>
<img src="feature_importance.png" width="700"><br>
<img src="score_distribution.png" width="700"><br>
<img src="performance_by_technique.png" width="900"><br>
<h2>Performance par technique</h2><pre>{df_perf.to_string(index=False)}</pre>
</body></html>"""
    (RESULTS_DIR / "index.html").write_text(html, encoding="utf-8")

    print(f"\n[OK] Rapport HTML : {RESULTS_DIR / 'index.html'}")


if __name__ == "__main__":
    main()
