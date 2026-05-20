"""Étape 1/3 du pipeline CIC-IDS-2017 — Preprocessing.

Charge le CSV, échantillonne stratifié, nettoie (drop Destination Port, clip,
remplace Inf), splitte en train/test stratifié, applique StandardScaler.

Usage :
    python pipeline/preprocess.py

Sorties :
    data/processed/X_train.npy / X_test.npy   (arrays NumPy denses)
    data/processed/y_train.csv / y_test.csv   (label string)
    data/processed/scaler.pkl                 StandardScaler fitté
    data/processed/feature_names.json
    data/processed/manifest.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (  # noqa: E402
    LABEL_COLUMN, PROCESSED_DIR, RANDOM_STATE, SAMPLE_CAP_PER_CLASS, TEST_SIZE,
    clean_dataset, load_dataset, stratified_sample,
)


def main() -> None:
    print("=" * 60)
    print("ÉTAPE 1/3 — Preprocessing CIC-IDS-2017")
    print("=" * 60)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Load ---
    df = load_dataset()

    # --- 2. Nettoyage (drop port + clip + déduplication) ---
    # IMPORTANT : la déduplication doit se faire AVANT le sampling
    # pour éviter le leakage train/test via doublons.
    df = clean_dataset(df)

    # --- 3. Sampling stratifié sur données dédupliquées ---
    df = stratified_sample(df, cap_per_class=SAMPLE_CAP_PER_CLASS)

    # --- 3. Split stratifié ---
    X_df = df.drop(columns=[LABEL_COLUMN])
    y = df[LABEL_COLUMN].values
    feature_names = X_df.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X_df.values, y,
        test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y,
    )
    print(f"[split] train={len(y_train):,} test={len(y_test):,}")

    # --- 4. StandardScaler ---
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    print(f"[scaler] X_train shape={X_train_s.shape}, X_test shape={X_test_s.shape}")

    # --- 5. Sauvegarde ---
    np.save(PROCESSED_DIR / "X_train.npy", X_train_s)
    np.save(PROCESSED_DIR / "X_test.npy", X_test_s)
    np.save(PROCESSED_DIR / "y_train.npy", y_train)
    np.save(PROCESSED_DIR / "y_test.npy", y_test)
    joblib.dump(scaler, PROCESSED_DIR / "scaler.pkl")
    (PROCESSED_DIR / "feature_names.json").write_text(
        json.dumps(feature_names, indent=2), encoding="utf-8",
    )

    manifest = {
        "random_state": RANDOM_STATE,
        "sample_cap_per_class": SAMPLE_CAP_PER_CLASS,
        "test_size": TEST_SIZE,
        "n_total_sample": int(len(df)),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "n_features": int(X_train.shape[1]),
        "feature_names_dropped": ["Destination Port"],
    }
    (PROCESSED_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\nArtefacts dans {PROCESSED_DIR}/ :")
    for f in sorted(PROCESSED_DIR.iterdir()):
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
