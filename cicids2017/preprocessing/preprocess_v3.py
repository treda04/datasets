"""
═══════════════════════════════════════════════════════════════════════
CIC-IDS-2017 Preprocessing v3 — Échantillonnage stratifié + Rééquilibrage hybride
═══════════════════════════════════════════════════════════════════════
Améliorations vs v2 :
  - Échantillonnage STRATIFIÉ sur le dataset COMPLET (pas seulement
    les 500k premières lignes)
  - Garantit la couverture des 7 classes (DoS, DDoS, Bots inclus)
  - Stratégie hybride RandomUnderSampler + SMOTE modéré
    (au lieu de SMOTE brutal qui explose la mémoire)
  - Normal Traffic ramené à 50k, classes minoritaires portées à 5k
  - Justification : He & Garcia (2009) "Learning from Imbalanced Data"
═══════════════════════════════════════════════════════════════════════
"""

import hashlib
import json
import os
import time
import warnings
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════
INPUT_FILE = Path("cicids2017/data/cicids2017.csv")
OUTPUT_DIR = Path("cicids2017/data/processed_v3")
ARTIFACTS_DIR = Path("cicids2017/saved_models")
TARGET_COL = "Attack Type"
SAMPLE_SIZE = 500_000  # même volume que v2 pour comparabilité
RANDOM_STATE = 42

# Stratégie de rééquilibrage
NORMAL_UNDERSAMPLE_SIZE = 50_000     # Normal Traffic ramené à ce nombre
MINORITY_SMOTE_TARGET = 5_000        # Classes minoritaires portées à ce nombre

# Features identifiantes à supprimer (root cause du F1=1.00)
LEAKY_FEATURES = [
    "Destination Port",
    "Source Port",
    "Destination IP",
    "Source IP",
    "Flow ID",
    "Timestamp",
]


def md5_of_file(path: Path, chunk_mb: int = 8) -> str:
    """Calcule le hash MD5 d'un fichier pour la traçabilité."""
    h = hashlib.md5()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_mb * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main():
    print("=" * 70)
    print("🔧 PIPELINE PREPROCESSING CIC-IDS-2017 v3")
    print("   Échantillonnage stratifié + Rééquilibrage hybride")
    print("=" * 70)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # ─── 1. CHARGEMENT COMPLET du dataset (chunked pour mémoire) ───
    print(f"\n[1/8] Chargement complet de {INPUT_FILE}...")
    t0 = time.time()
    chunks = []
    chunk_size = 100_000
    for i, chunk in enumerate(pd.read_csv(INPUT_FILE, chunksize=chunk_size), 1):
        chunks.append(chunk)
        if i % 5 == 0:
            print(f"      ... {i*chunk_size:,} lignes lues")
    df = pd.concat(chunks, ignore_index=True)
    df.columns = df.columns.str.strip()
    print(f"      ✅ {len(df):,} lignes chargées en {time.time()-t0:.1f}s")

    # ─── 2. Distribution initiale ───
    print(f"\n[2/8] Distribution initiale des classes :")
    print("-" * 70)
    class_counts = df[TARGET_COL].value_counts()
    for cls, count in class_counts.items():
        pct = count/len(df)*100
        print(f"      {cls:<25s} {count:>10,} ({pct:>6.2f}%)")

    # ─── 3. Nettoyage : NaN, Inf, colonnes constantes ───
    print(f"\n[3/8] Nettoyage : NaN, Inf, colonnes constantes...")
    initial_size = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    print(f"      Lignes supprimées (NaN/Inf) : {initial_size - len(df):,}")

    constant_cols = [c for c in df.columns if df[c].nunique() == 1]
    df = df.drop(columns=constant_cols)
    print(f"      Colonnes constantes supprimées : {len(constant_cols)}")
    print(f"      Shape après nettoyage : {df.shape}")

    # ─── 4. ÉCHANTILLONNAGE STRATIFIÉ ───
    print(f"\n[4/8] Échantillonnage stratifié à {SAMPLE_SIZE:,} lignes...")

    sampled_dfs = []
    for cls in df[TARGET_COL].unique():
        cls_df = df[df[TARGET_COL] == cls]
        n_cls = len(cls_df)
        # Proportion cible
        target_n = int(SAMPLE_SIZE * (n_cls / len(df)))
        # Minimum 100 échantillons par classe pour permettre le ML
        target_n = max(target_n, min(100, n_cls))
        # Maximum : tout ce qui existe
        target_n = min(target_n, n_cls)
        sampled = cls_df.sample(n=target_n, random_state=RANDOM_STATE)
        sampled_dfs.append(sampled)
        print(f"      {cls:<25s} {n_cls:>10,} → {len(sampled):>8,}")

    df = pd.concat(sampled_dfs, ignore_index=True).sample(
        frac=1, random_state=RANDOM_STATE
    ).reset_index(drop=True)
    print(f"\n      ✅ Dataset échantillonné : {len(df):,} lignes")

    # Vérification : toutes les classes présentes
    print(f"\n      Distribution APRÈS échantillonnage :")
    for cls, count in df[TARGET_COL].value_counts().items():
        pct = count/len(df)*100
        print(f"      {cls:<25s} {count:>10,} ({pct:>6.2f}%)")

    # ─── 5. Split stratifié 80/20 ───
    print(f"\n[5/8] Split stratifié 80/20...")
    df_train, df_test = train_test_split(
        df, test_size=0.2,
        stratify=df[TARGET_COL],
        random_state=RANDOM_STATE
    )
    print(f"      Train : {len(df_train):,}  |  Test : {len(df_test):,}")

    # ─── 6. Suppression leaky features ───
    print(f"\n[6/8] Suppression des leaky features...")
    cols_to_drop = [c for c in LEAKY_FEATURES if c in df_train.columns]
    df_train = df_train.drop(columns=cols_to_drop)
    df_test = df_test.drop(columns=cols_to_drop)
    print(f"      Supprimées : {cols_to_drop}")

    # ─── 7. X / y + encoding ───
    print(f"\n[7/8] Séparation X/y + encodage labels...")
    X_train = df_train.drop(columns=[TARGET_COL])
    y_train_str = df_train[TARGET_COL]
    X_test = df_test.drop(columns=[TARGET_COL])
    y_test_str = df_test[TARGET_COL]

    encoder = LabelEncoder()
    y_train = encoder.fit_transform(y_train_str)
    y_test = encoder.transform(y_test_str)
    print(f"      Classes ({len(encoder.classes_)}) : {list(encoder.classes_)}")

    # ─── 8. UNDERSAMPLING + SMOTE modéré (stratégie hybride) ───
    print(f"\n[8/8] Rééquilibrage hybride (Undersampling + SMOTE)...")
    print(f"      Avant rééquilibrage : {X_train.shape}")

    print(f"\n      Distribution AVANT rééquilibrage :")
    for cls_id, count in sorted(Counter(y_train).items()):
        cls_name = encoder.classes_[cls_id]
        print(f"        {cls_name:<25s} {count:>8,}")

    # ÉTAPE 8a : Undersampling de Normal Traffic
    normal_class_id = list(encoder.classes_).index("Normal Traffic")
    undersampling_strategy = {normal_class_id: NORMAL_UNDERSAMPLE_SIZE}

    print(f"\n      [a] Undersampling Normal Traffic → {NORMAL_UNDERSAMPLE_SIZE:,} échantillons")
    rus = RandomUnderSampler(
        sampling_strategy=undersampling_strategy,
        random_state=RANDOM_STATE
    )
    X_train_under, y_train_under = rus.fit_resample(X_train, y_train)
    print(f"          Après undersampling : {X_train_under.shape}")

    # ÉTAPE 8b : SMOTE modéré sur les classes minoritaires
    print(f"\n      [b] SMOTE modéré sur les classes minoritaires → {MINORITY_SMOTE_TARGET:,} chacune")
    smote_strategy = {}
    for cls_id, count in Counter(y_train_under).items():
        if cls_id != normal_class_id and count < MINORITY_SMOTE_TARGET:
            smote_strategy[cls_id] = MINORITY_SMOTE_TARGET

    if smote_strategy:
        smote = SMOTE(
            sampling_strategy=smote_strategy,
            random_state=RANDOM_STATE,
            k_neighbors=3
        )
        X_train_balanced, y_train_balanced = smote.fit_resample(X_train_under, y_train_under)
    else:
        X_train_balanced = X_train_under
        y_train_balanced = y_train_under

    print(f"          Après SMOTE : {X_train_balanced.shape}")

    print(f"\n      Distribution APRÈS rééquilibrage :")
    for cls_id, count in sorted(Counter(y_train_balanced).items()):
        cls_name = encoder.classes_[cls_id]
        print(f"        {cls_name:<25s} {count:>8,}")

    # ─── 9. StandardScaler ───
    print(f"\n      StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_balanced)
    X_test_scaled = scaler.transform(X_test)

    feature_columns = list(X_train.columns)

    # ─── 10. Sauvegarde ───
    print(f"\n      Sauvegarde des fichiers...")

    pd.DataFrame(X_train_scaled, columns=feature_columns).to_csv(
        OUTPUT_DIR / "X_train.csv", index=False
    )
    pd.DataFrame(X_test_scaled, columns=feature_columns).to_csv(
        OUTPUT_DIR / "X_test.csv", index=False
    )
    pd.Series(y_train_balanced, name="label").to_csv(OUTPUT_DIR / "y_train.csv", index=False)
    pd.Series(y_test, name="label").to_csv(OUTPUT_DIR / "y_test.csv", index=False)

    joblib.dump(scaler, ARTIFACTS_DIR / "cicids_scaler_v3.pkl")
    joblib.dump(encoder, ARTIFACTS_DIR / "cicids_label_encoder_v3.pkl")
    with open(ARTIFACTS_DIR / "feature_columns_v3.json", "w") as f:
        json.dump(feature_columns, f, indent=2)

    manifest = {
        "version": 3,
        "input_file": str(INPUT_FILE),
        "input_md5": md5_of_file(INPUT_FILE) if INPUT_FILE.exists() else None,
        "sampling_method": "stratified_proportional",
        "rebalancing_method": "RandomUnderSampler + SMOTE modéré",
        "normal_class_size_after_undersampling": NORMAL_UNDERSAMPLE_SIZE,
        "minority_target_size_after_smote": MINORITY_SMOTE_TARGET,
        "sample_size": SAMPLE_SIZE,
        "leaky_features_dropped": cols_to_drop,
        "constant_columns_dropped": constant_cols,
        "n_classes": len(encoder.classes_),
        "classes": list(encoder.classes_),
        "n_features": len(feature_columns),
        "n_train_final": int(X_train_balanced.shape[0]),
        "n_test": int(X_test.shape[0]),
        "random_state": RANDOM_STATE,
    }
    with open(OUTPUT_DIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    total_time = time.time() - t0
    print(f"\n      Données → {OUTPUT_DIR}")
    print(f"      Artefacts → {ARTIFACTS_DIR}")
    print(f"\n[✅] Preprocessing v3 terminé en {total_time:.1f}s")
    print("=" * 70)


if __name__ == "__main__":
    main()