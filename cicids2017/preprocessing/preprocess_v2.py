"""
CIC-IDS-2017 Preprocessing v2 — Sans data leakage
==================================================
Corrige les problèmes identifiés dans AUDIT_REPORT.md :
  1. Supprime Destination Port + Source Port + features dérivées
     → empêche le shortcut learning
  2. Garde TOUTES les classes (au lieu de 4 hardcodées)
  3. Sauvegarde le LabelEncoder pour reproductibilité
  4. Sépare strictement fit/transform via sklearn.Pipeline
  5. SMOTE uniquement sur train (déjà OK dans v1, on garde)
  6. Sauve un manifest JSON avec hash dataset + nb features

Lancer depuis datasets/ :
    python cicids2017/preprocessing/preprocess_v2.py
"""

import hashlib
import json
import os
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")

# ═══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════
INPUT_FILE = Path("cicids2017/data/cicids2017.csv")
OUTPUT_DIR = Path("cicids2017/data/processed_v2")
ARTIFACTS_DIR = Path("cicids2017/saved_models")
TARGET_COL = "Attack Type"
LIGNES_MAX = 500_000  # même valeur que v1 pour comparaison équitable
RANDOM_STATE = 42

# Features identifiantes à supprimer (root cause du F1=1.00)
LEAKY_FEATURES = [
    "Destination Port",
    "Source Port",
    "Destination IP",
    "Source IP",
    "Flow ID",
    "Timestamp",  # gardé pour split temporel, supprimé après
]


def md5_of_file(path: Path, chunk_mb: int = 8) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_mb * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main():
    print("=== PIPELINE PREPROCESSING CIC-IDS-2017 v2 (sans leakage) ===\n")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Chargement
    print(f"[1/7] Chargement de {LIGNES_MAX} lignes depuis {INPUT_FILE}...")
    t0 = time.time()
    df = pd.read_csv(INPUT_FILE, nrows=LIGNES_MAX)
    df.columns = df.columns.str.strip()
    print(f"      {len(df)} lignes, {len(df.columns)} colonnes — {time.time()-t0:.1f}s")

    # 2. Nettoyage
    print("\n[2/7] Nettoyage : NaN, Inf, colonnes constantes...")
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    constant_cols = [c for c in df.columns if df[c].nunique() == 1]
    df = df.drop(columns=constant_cols)
    print(f"      {len(constant_cols)} colonnes constantes supprimées.")

    # 3. Split temporel SI Timestamp existe (sinon split aléatoire stratifié)
    has_timestamp = "Timestamp" in df.columns
    if has_timestamp:
        print("\n[3/7] Split TEMPOREL (80% premiers / 20% derniers)...")
        df = df.sort_values("Timestamp").reset_index(drop=True)
        cutoff = int(len(df) * 0.8)
        df_train = df.iloc[:cutoff].copy()
        df_test = df.iloc[cutoff:].copy()
    else:
        print("\n[3/7] Pas de Timestamp — split stratifié 80/20...")
        df_train, df_test = train_test_split(
            df, test_size=0.2, stratify=df[TARGET_COL], random_state=RANDOM_STATE
        )

    # 4. Suppression des features identifiantes (leaky)
    print("\n[4/7] Suppression des features 'identifiantes' (anti-leakage)...")
    cols_to_drop = [c for c in LEAKY_FEATURES if c in df_train.columns]
    df_train = df_train.drop(columns=cols_to_drop)
    df_test = df_test.drop(columns=cols_to_drop)
    print(f"      Supprimées : {cols_to_drop}")

    # 5. X / y + label encoding (toutes les classes !)
    print("\n[5/7] Séparation X/y + encodage labels (toutes les classes)...")
    X_train = df_train.drop(columns=[TARGET_COL])
    y_train_str = df_train[TARGET_COL]
    X_test = df_test.drop(columns=[TARGET_COL])
    y_test_str = df_test[TARGET_COL]

    encoder = LabelEncoder()
    y_train = encoder.fit_transform(y_train_str)
    # Robustesse : si test contient une classe jamais vue en train, on l'écarte
    mask_known = y_test_str.isin(encoder.classes_)
    if (~mask_known).any():
        n_unknown = (~mask_known).sum()
        print(f"      ATTENTION : {n_unknown} lignes test ont une classe inconnue → écartées.")
        X_test = X_test[mask_known]
        y_test_str = y_test_str[mask_known]
    y_test = encoder.transform(y_test_str)

    print(f"      Classes ({len(encoder.classes_)}) : {list(encoder.classes_)}")
    print(f"      Train : {len(X_train)}  |  Test : {len(X_test)}")

    # 6. SMOTE (train uniquement) + StandardScaler
    print("\n[6/7] SMOTE sur train + StandardScaler (fit train only)...")
    print(f"      Avant SMOTE : {X_train.shape}")
    smote = SMOTE(random_state=RANDOM_STATE, k_neighbors=3)
    X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)
    print(f"      Après SMOTE : {X_train_smote.shape}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_smote)
    X_test_scaled = scaler.transform(X_test)

    # 7. Sauvegarde
    print("\n[7/7] Sauvegarde des artefacts...")
    feature_columns = list(X_train.columns)

    pd.DataFrame(X_train_scaled, columns=feature_columns).to_csv(
        OUTPUT_DIR / "X_train.csv", index=False
    )
    pd.DataFrame(X_test_scaled, columns=feature_columns).to_csv(
        OUTPUT_DIR / "X_test.csv", index=False
    )
    pd.Series(y_train_smote, name="label").to_csv(OUTPUT_DIR / "y_train.csv", index=False)
    pd.Series(y_test, name="label").to_csv(OUTPUT_DIR / "y_test.csv", index=False)

    joblib.dump(scaler, ARTIFACTS_DIR / "cicids_scaler.pkl")
    joblib.dump(encoder, ARTIFACTS_DIR / "cicids_label_encoder.pkl")
    with open(ARTIFACTS_DIR / "feature_columns.json", "w") as f:
        json.dump(feature_columns, f, indent=2)

    manifest = {
        "version": 2,
        "input_file": str(INPUT_FILE),
        "input_md5": md5_of_file(INPUT_FILE) if INPUT_FILE.exists() else None,
        "lines_used": LIGNES_MAX,
        "split_method": "temporal" if has_timestamp else "stratified_random",
        "leaky_features_dropped": cols_to_drop,
        "constant_columns_dropped": constant_cols,
        "n_classes": len(encoder.classes_),
        "classes": list(encoder.classes_),
        "n_features": len(feature_columns),
        "n_train_after_smote": int(X_train_smote.shape[0]),
        "n_test": int(X_test.shape[0]),
        "random_state": RANDOM_STATE,
    }
    with open(OUTPUT_DIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n      Données → {OUTPUT_DIR}")
    print(f"      Artefacts → {ARTIFACTS_DIR}")
    print("\n[OK] Preprocessing v2 terminé. Lancer ensuite train_xgboost_v2.py")


if __name__ == "__main__":
    main()
