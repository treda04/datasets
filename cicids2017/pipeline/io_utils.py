"""Utilitaires partagés du pipeline CIC-IDS-2017.

Factorise les fonctions et constantes communes aux 3 scripts.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


# --- Chemins canoniques ---

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # cicids2017/
DATA_CSV = PROJECT_ROOT / "data" / "cicids2017.csv"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "saved_models" / "v1_final"
RESULTS_DIR = PROJECT_ROOT / "results" / "final"


# --- Constantes du pipeline (figées en Phase 2) ---

RANDOM_STATE = 42
TEST_SIZE = 0.3

# Colonnes à supprimer (anti shortcut-learning)
LEAKAGE_COLUMNS = ["Destination Port"]

# Colonnes à clipper à zéro (artefacts CICFlowMeter)
NEGATIVE_TO_ZERO_COLUMNS = ["Flow Bytes/s", "Flow Packets/s"]

# Sampling stratifié par classe (cap pour limiter le temps d'entraînement)
SAMPLE_CAP_PER_CLASS = 100_000

# Random Forest
RF_N_ESTIMATORS = 200
RF_MAX_DEPTH = 25
RF_MIN_SAMPLES_LEAF = 5
RF_CLASS_WEIGHT = "balanced"

# CV
CV_FOLDS = 5

LABEL_COLUMN = "Attack Type"


def load_dataset(verbose: bool = True) -> pd.DataFrame:
    """Charge le CSV complet (2.5M lignes)."""
    if not DATA_CSV.exists():
        raise FileNotFoundError(f"CSV introuvable : {DATA_CSV}")
    df = pd.read_csv(DATA_CSV)
    if verbose:
        print(f"[load_dataset] {len(df):,} lignes, {df.shape[1]} colonnes")
        print(f"[load_dataset] Mémoire : {df.memory_usage(deep=True).sum() / 1e6:.1f} MB")
    return df


def stratified_sample(df: pd.DataFrame, cap_per_class: int = SAMPLE_CAP_PER_CLASS,
                      verbose: bool = True) -> pd.DataFrame:
    """Échantillonnage stratifié avec plafond par classe.

    Garde toutes les lignes des classes minoritaires ; sous-échantillonne les
    classes majoritaires pour accélérer l'entraînement sans perdre les rares.
    """
    samples = []
    for cls in df[LABEL_COLUMN].unique():
        sub = df[df[LABEL_COLUMN] == cls]
        n = min(cap_per_class, len(sub))
        samples.append(sub.sample(n=n, random_state=RANDOM_STATE))
    df_s = pd.concat(samples).reset_index(drop=True)
    if verbose:
        print(f"[stratified_sample] {len(df):,} -> {len(df_s):,}")
        print(df_s[LABEL_COLUMN].value_counts().to_string())
    return df_s


def clean_dataset(df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
    """Applique les règles de nettoyage validées en Phase 1 + audit.

    Étapes (ordre important) :
    1. Supprime les colonnes de leakage (Destination Port)
    2. Remplace Inf et NaN par 0
    3. Clippe les colonnes avec valeurs négatives aberrantes
    4. **Déduplique** APRES drop+clip pour éliminer le leakage train/test
       (l'audit du 2026-05-19 a montré 23.5% de lignes test identiques à
       des lignes train à cause des doublons générés par drop Destination
       Port — voir AUDIT_RAPPORT.md).
    """
    df_c = df.copy()
    n_before = len(df_c)

    n_dropped_cols = 0
    for col in LEAKAGE_COLUMNS:
        if col in df_c.columns:
            df_c = df_c.drop(columns=[col])
            n_dropped_cols += 1

    num_cols = df_c.select_dtypes(include=[np.number]).columns
    n_inf = int(np.isinf(df_c[num_cols]).sum().sum())
    df_c[num_cols] = df_c[num_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

    n_clipped = 0
    for col in NEGATIVE_TO_ZERO_COLUMNS:
        if col in df_c.columns:
            n_neg = int((df_c[col] < 0).sum())
            df_c[col] = df_c[col].clip(lower=0)
            n_clipped += n_neg

    # 4. Déduplication APRES drop+clip — étape critique anti-leakage
    df_c = df_c.drop_duplicates().reset_index(drop=True)
    n_dedup = n_before - len(df_c)

    if verbose:
        print(f"[clean_dataset] Colonnes supprimées (leakage) : {n_dropped_cols}")
        print(f"[clean_dataset] Inf remplacés : {n_inf}")
        print(f"[clean_dataset] Valeurs négatives clippées : {n_clipped}")
        print(f"[clean_dataset] Doublons retirés : {n_dedup:,} "
              f"({n_dedup/n_before*100:.1f}%)")
        print(f"[clean_dataset] Shape final : {df_c.shape}")
    return df_c
