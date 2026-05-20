"""Étape 1/3 du pipeline : stream raw -> features -> split -> scaler -> sauvegarde.

Usage :
    python pipeline/preprocess.py

Produit :
    data/processed/X_train.npy, X_test.npy
    data/processed/y_train.npy, y_test.npy
    data/processed/scaler.pkl
    data/processed/feature_names.json
    data/processed/train.parquet, test.parquet
    data/processed/manifest_preprocess.json
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (  # noqa: E402
    DROP_COLS, LABEL_STRATEGY, MIN_EVENTS_PER_WINDOW, PROCESSED_DIR,
    WINDOW_RULE, build_windows, load_raw_to_dataframe,
)


def main():
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    t0 = datetime.now(timezone.utc)
    print(f"[preprocess] start utc={t0.isoformat()}")

    print("[preprocess] 1/5  Streaming Day 1 + Day 2 ...")
    df = load_raw_to_dataframe()
    print(f"[preprocess]      events={len(df):,}")

    print("[preprocess] 2/5  Fenêtrage + features + labels ...")
    win_df = build_windows(df)
    print(f"[preprocess]      windows total = {len(win_df)}")
    print(f"[preprocess]      label_v1 dist = {win_df['label_v1'].value_counts().to_dict()}")
    print(f"[preprocess]      label_v2 dist = {win_df['label_v2'].value_counts().to_dict()}")

    label_col = LABEL_STRATEGY
    feature_cols = [c for c in win_df.columns if c not in DROP_COLS]
    print(f"[preprocess]      label_col={label_col} | features={len(feature_cols)}")

    print("[preprocess] 3/5  Split temporel Day1/Day2 ...")
    train_df = win_df[win_df["day"] == "day1"].reset_index(drop=True)
    test_df = win_df[win_df["day"] == "day2"].reset_index(drop=True)
    print(f"[preprocess]      train={len(train_df)} (positives={train_df[label_col].sum()})")
    print(f"[preprocess]      test ={len(test_df)} (positives={test_df[label_col].sum()})")

    X_train = train_df[feature_cols].fillna(0).values.astype(float)
    y_train = train_df[label_col].values.astype(int)
    X_test = test_df[feature_cols].fillna(0).values.astype(float)
    y_test = test_df[label_col].values.astype(int)

    print("[preprocess] 4/5  StandardScaler fit train only ...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    print("[preprocess] 5/5  Sauvegardes ...")
    np.save(PROCESSED_DIR / "X_train.npy", X_train_s)
    np.save(PROCESSED_DIR / "X_test.npy", X_test_s)
    np.save(PROCESSED_DIR / "y_train.npy", y_train)
    np.save(PROCESSED_DIR / "y_test.npy", y_test)
    joblib.dump(scaler, PROCESSED_DIR / "scaler.pkl")

    (PROCESSED_DIR / "feature_names.json").write_text(
        json.dumps(feature_cols), encoding="utf-8"
    )

    # Garde aussi les parquets pour traçabilité (Hostname/window/technique visibles)
    train_df.to_parquet(PROCESSED_DIR / "train.parquet", index=False)
    test_df.to_parquet(PROCESSED_DIR / "test.parquet", index=False)

    t1 = datetime.now(timezone.utc)
    manifest = {
        "generated_utc": t1.isoformat(),
        "duration_s": (t1 - t0).total_seconds(),
        "window_rule": WINDOW_RULE,
        "min_events_per_window": MIN_EVENTS_PER_WINDOW,
        "label_strategy": label_col,
        "n_features": len(feature_cols),
        "feature_names": feature_cols,
        "n_train": int(len(train_df)),
        "n_test": int(len(test_df)),
        "n_train_positive": int(train_df[label_col].sum()),
        "n_test_positive": int(test_df[label_col].sum()),
        "shape_X_train": list(X_train_s.shape),
        "shape_X_test": list(X_test_s.shape),
    }
    (PROCESSED_DIR / "manifest_preprocess.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"[preprocess] OK ({(t1-t0).total_seconds():.0f}s)")
    print(f"             X_train={X_train_s.shape} | X_test={X_test_s.shape}")


if __name__ == "__main__":
    main()
