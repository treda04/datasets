"""
SIEM Windows — Génération du rapport d'évaluation enrichi
==========================================================
Lit le modèle entraîné + les données test, produit :
  - rapport HTML léger avec tous les graphiques
  - distribution des scores par host
  - timeline des alertes (visualisation temporelle)
  - exemples top-K de vrais positifs et faux positifs

Lancer depuis datasets/ :
    python siem_windows/evaluation/generate_siem_results.py
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
from datetime import datetime, timezone

warnings.filterwarnings("ignore")

DATA_DIR = Path("siem_windows/data/processed")
ARTIFACTS_DIR = Path("siem_windows/saved_models")
RESULTS_DIR = Path("siem_windows/results")


def main():
    print("=== ÉVALUATION ENRICHIE — SIEM WINDOWS ===\n")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    model = joblib.load(ARTIFACTS_DIR / "rf_siem_model.pkl")
    feature_cols = json.load(open(ARTIFACTS_DIR / "feature_columns.json"))
    threshold = json.load(open(ARTIFACTS_DIR / "siem_threshold.json"))["threshold"]
    df_test = pd.read_parquet(DATA_DIR / "test.parquet")

    X = df_test[feature_cols].values
    y = df_test["label"].values
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= threshold).astype(int)
    df_test = df_test.copy()
    df_test["score"] = proba
    df_test["pred"] = pred

    # 1. Distribution des scores par classe
    print("[1/4] Distribution des scores...")
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(proba[y == 0], bins=40, alpha=0.6, label="Normal", color="green")
    ax.hist(proba[y == 1], bins=40, alpha=0.6, label="Attaque", color="red")
    ax.axvline(threshold, color="black", linestyle="--",
               label=f"Seuil = {threshold:.3f}")
    ax.set_xlabel("Score ML"); ax.set_ylabel("Nombre de fenêtres")
    ax.set_title("Distribution des scores SIEM Windows")
    ax.legend()
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "score_distribution.png", dpi=110)
    plt.close(fig)

    # 2. Score moyen par host
    print("[2/4] Scores par host...")
    by_host = df_test.groupby("host").agg(
        n_windows=("score", "size"),
        score_mean=("score", "mean"),
        score_max=("score", "max"),
        n_alerts=("pred", "sum"),
        n_true_attacks=("label", "sum"),
    ).sort_values("score_max", ascending=False)
    by_host.to_csv(RESULTS_DIR / "scores_by_host.csv")
    print(by_host.to_string())

    # 3. Timeline des alertes
    print("\n[3/4] Timeline des alertes...")
    fig, ax = plt.subplots(figsize=(12, 5))
    for host, group in df_test.groupby("host"):
        ts = pd.to_datetime(group["window_start_ts"], unit="s", utc=True)
        ax.plot(ts, group["score"], marker=".", linestyle="-", alpha=0.6, label=host)
    ax.axhline(threshold, color="black", linestyle="--",
               label=f"Seuil = {threshold:.3f}")
    ax.set_xlabel("Temps (UTC)"); ax.set_ylabel("Score ML")
    ax.set_title("Timeline des scores SIEM Windows par host")
    ax.legend(loc="upper left", fontsize=8)
    fig.autofmt_xdate()
    fig.tight_layout(); fig.savefig(RESULTS_DIR / "timeline.png", dpi=110)
    plt.close(fig)

    # 4. Top vrais positifs et faux positifs
    print("[4/4] Top exemples (TP, FP)...")
    df_tp = df_test[(df_test.label == 1) & (df_test.pred == 1)].nlargest(5, "score")
    df_fp = df_test[(df_test.label == 0) & (df_test.pred == 1)].nlargest(5, "score")

    examples = {
        "top_5_true_positives": df_tp[
            ["host", "window_start_ts", "score", "total_events"]
        ].to_dict("records"),
        "top_5_false_positives": df_fp[
            ["host", "window_start_ts", "score", "total_events"]
        ].to_dict("records"),
    }
    # Convertir timestamp unix en ISO
    for k in examples:
        for e in examples[k]:
            e["window_start_iso"] = datetime.fromtimestamp(
                e.pop("window_start_ts"), tz=timezone.utc
            ).isoformat()
    with open(RESULTS_DIR / "top_examples.json", "w") as f:
        json.dump(examples, f, indent=2)

    print(f"\nVrais positifs (Top 5) :\n{df_tp[['host','score','total_events']].to_string()}")
    print(f"\nFaux positifs (Top 5) :\n{df_fp[['host','score','total_events']].to_string()}")

    # Index HTML rapide
    html = f"""<html><head><title>SIEM Windows — Results</title></head><body>
<h1>SIEM Windows — Rapport d'évaluation</h1>
<p>Modèle entraîné sur APT29 day1, évalué sur day2 (split temporel).</p>
<p>Seuil calibré : <b>{threshold:.3f}</b></p>
<h2>Métriques</h2>
<pre>{open(RESULTS_DIR / 'metrics.json').read()}</pre>
<h2>Plots</h2>
<img src="confusion_matrix.png" width="500"><br>
<img src="roc_curve.png" width="500"> <img src="pr_curve.png" width="500"><br>
<img src="feature_importance.png" width="700"><br>
<img src="score_distribution.png" width="700"><br>
<img src="timeline.png" width="900"><br>
<h2>Scores par host</h2><pre>{by_host.to_string()}</pre>
</body></html>"""
    (RESULTS_DIR / "index.html").write_text(html, encoding="utf-8")

    print(f"\n[OK] Rapport HTML : {RESULTS_DIR / 'index.html'}")


if __name__ == "__main__":
    main()
