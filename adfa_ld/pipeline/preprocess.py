"""Étape 1/3 du pipeline ADFA-LD — Preprocessing.

Charge le dataset, le nettoie, le splitte en train/test groupé par scénario,
vectorise en n-grammes (1 à 3) et sauvegarde les artefacts dans data/processed/.

Usage :
    python pipeline/preprocess.py

Sorties :
    data/processed/X_train.npz       matrice creuse 4154 × 1500
    data/processed/X_test.npz        matrice creuse 1797 × 1500
    data/processed/y_train.csv       label + scenario + family + filename
    data/processed/y_test.csv        idem
    data/processed/vectorizer.pkl    CountVectorizer fitté
    data/processed/manifest.json     seed, tailles, paramètres
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import scipy.sparse as sp
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import GroupShuffleSplit

# Permet d'exécuter ce fichier directement (`python pipeline/preprocess.py`)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (  # noqa: E402
    MAX_FEATURES, MIN_DF, NGRAM_RANGE, PROCESSED_DIR, RANDOM_STATE, TEST_SIZE,
    clean_dataset, load_dataset,
)


def main() -> None:
    print("=" * 60)
    print("ÉTAPE 1/3 — Preprocessing")
    print("=" * 60)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    # --- 1. Charger + nettoyer ---
    df = load_dataset()
    df = clean_dataset(df)

    # --- 2. Split groupé par scénario (anti-leakage) ---
    splitter = GroupShuffleSplit(
        n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE,
    )
    train_idx, test_idx = next(
        splitter.split(df["sequence"].values, df["label"].values,
                       groups=df["scenario"].values)
    )

    df_train = df.iloc[train_idx].reset_index(drop=True)
    df_test = df.iloc[test_idx].reset_index(drop=True)

    overlap = set(df_train["scenario"]) & set(df_test["scenario"])
    assert len(overlap) == 0, f"LEAKAGE : {len(overlap)} scénarios partagés"

    print(f"[split] train={len(df_train)} (attaques={(df_train.label==1).sum()})")
    print(f"[split] test ={len(df_test)}  (attaques={(df_test.label==1).sum()})")
    print(f"[split] overlap scénarios = 0  OK")

    # --- 3. Vectorisation (fit train, transform test) ---
    vectorizer = CountVectorizer(
        analyzer="word",
        ngram_range=NGRAM_RANGE,
        max_features=MAX_FEATURES,
        min_df=MIN_DF,
        token_pattern=r"\d+",
    )
    X_train = vectorizer.fit_transform(df_train["sequence"].values)
    X_test = vectorizer.transform(df_test["sequence"].values)

    feature_names = vectorizer.get_feature_names_out()
    n_uni = sum(1 for f in feature_names if len(f.split()) == 1)
    n_bi = sum(1 for f in feature_names if len(f.split()) == 2)
    n_tri = sum(1 for f in feature_names if len(f.split()) == 3)
    print(f"[vectorize] X_train={X_train.shape}, X_test={X_test.shape}")
    print(f"[vectorize] uni={n_uni}, bi={n_bi}, tri={n_tri}")

    # --- 4. Sauvegarde ---
    sp.save_npz(PROCESSED_DIR / "X_train.npz", X_train)
    sp.save_npz(PROCESSED_DIR / "X_test.npz", X_test)

    df_train[["filename", "label", "family", "scenario"]].to_csv(
        PROCESSED_DIR / "y_train.csv", index=False,
    )
    df_test[["filename", "label", "family", "scenario"]].to_csv(
        PROCESSED_DIR / "y_test.csv", index=False,
    )

    joblib.dump(vectorizer, PROCESSED_DIR / "vectorizer.pkl")

    manifest = {
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "n_train": int(len(df_train)),
        "n_test": int(len(df_test)),
        "n_train_normal": int((df_train.label == 0).sum()),
        "n_train_attack": int((df_train.label == 1).sum()),
        "n_test_normal": int((df_test.label == 0).sum()),
        "n_test_attack": int((df_test.label == 1).sum()),
        "vectorizer": {
            "ngram_range": list(NGRAM_RANGE),
            "max_features": MAX_FEATURES,
            "min_df": MIN_DF,
            "n_features_actual": int(X_train.shape[1]),
            "composition": {"unigrammes": n_uni, "bigrammes": n_bi, "trigrammes": n_tri},
        },
    }
    (PROCESSED_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8",
    )

    print(f"\nArtefacts écrits dans {PROCESSED_DIR}/ :")
    for f in sorted(PROCESSED_DIR.iterdir()):
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
