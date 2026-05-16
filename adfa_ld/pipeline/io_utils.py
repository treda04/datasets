"""Utilitaires partagés du pipeline ADFA-LD.

Factorise les fonctions communes à preprocess.py / train.py / evaluate.py :
- Chargement d'un fichier de syscalls (avec validation)
- Chargement du dataset complet en DataFrame
- Constantes de chemins
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd


# --- Chemins canoniques (relatifs à la racine adfa_ld/) ---

PROJECT_ROOT = Path(__file__).resolve().parent.parent  # adfa_ld/
DATA_DIR = PROJECT_ROOT / "data" / "ADFA-LD"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "saved_models" / "v2_final"
RESULTS_DIR = PROJECT_ROOT / "results" / "final"

TRAINING_DIR = DATA_DIR / "Training_Data_Master"
VALIDATION_DIR = DATA_DIR / "Validation_Data_Master"
ATTACK_DIR = DATA_DIR / "Attack_Data_Master"

# --- Constantes du pipeline (figées via v2) ---

RANDOM_STATE = 42
TEST_SIZE = 0.3
NGRAM_RANGE = (1, 3)
MAX_FEATURES = 1500
MIN_DF = 2
MIN_SEQUENCE_LENGTH = 10
DECISION_THRESHOLD = 0.40

# Random Forest
RF_N_ESTIMATORS = 200
RF_MAX_DEPTH = 20
RF_MIN_SAMPLES_LEAF = 2

# Calibration
CALIB_METHOD = "isotonic"
CALIB_CV = 5

# CV
CV_FOLDS = 5


def load_syscall_file(path: Path) -> tuple[str, int, bool]:
    """Lit un fichier de trace et retourne (sequence_str, length, valid).

    - sequence_str : tokens normalisés séparés par un espace
    - length : nombre de tokens
    - valid : True si tous les tokens sont des entiers
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return "", 0, False
    if not text:
        return "", 0, True
    tokens = text.split()
    valid = all(t.isdigit() for t in tokens)
    return " ".join(tokens), len(tokens), valid


def load_dataset(verbose: bool = True) -> pd.DataFrame:
    """Charge l'intégralité du dataset ADFA-LD en DataFrame.

    Colonnes :
        filename, label (0/1), family, scenario, sequence, length, valid

    - Chaque fichier normal a son propre scenario unique (= ``normal_<stem>``)
      ⇒ ne sera pas groupé avec les autres normaux par GroupShuffleSplit.
    - Les fichiers d'attaque héritent du nom du scénario parent
      (``Adduser_1``, ``Hydra_FTP_5``...) ⇒ groupés ensemble pour anti-leakage.
    """
    if not DATA_DIR.exists():
        raise FileNotFoundError(f"Dataset introuvable : {DATA_DIR}")

    rows = []

    for path in sorted(TRAINING_DIR.glob("*.txt")):
        seq, length, valid = load_syscall_file(path)
        rows.append({
            "filename": path.name, "label": 0, "family": "normal",
            "scenario": f"normal_{path.stem}", "sequence": seq,
            "length": length, "valid": valid,
        })

    for path in sorted(VALIDATION_DIR.glob("*.txt")):
        seq, length, valid = load_syscall_file(path)
        rows.append({
            "filename": path.name, "label": 0, "family": "normal",
            "scenario": f"normal_{path.stem}", "sequence": seq,
            "length": length, "valid": valid,
        })

    for scenario_dir in sorted(ATTACK_DIR.iterdir()):
        if not scenario_dir.is_dir():
            continue
        scenario_name = scenario_dir.name
        family = re.sub(r"_\d+$", "", scenario_name)
        for path in sorted(scenario_dir.glob("*.txt")):
            seq, length, valid = load_syscall_file(path)
            rows.append({
                "filename": path.name, "label": 1, "family": family,
                "scenario": scenario_name, "sequence": seq,
                "length": length, "valid": valid,
            })

    df = pd.DataFrame(rows)
    if verbose:
        print(f"[load_dataset] {len(df)} fichiers chargés "
              f"(normaux={(df.label==0).sum()}, attaques={(df.label==1).sum()})")
    return df


def clean_dataset(df: pd.DataFrame, verbose: bool = True) -> pd.DataFrame:
    """Applique les règles de nettoyage validées en Phase 1.

    - Rejette les fichiers de longueur < MIN_SEQUENCE_LENGTH
    - Rejette les fichiers avec tokens non entiers
    """
    before = len(df)
    df_clean = df[(df.length >= MIN_SEQUENCE_LENGTH) & df.valid].reset_index(drop=True)
    after = len(df_clean)
    if verbose:
        print(f"[clean_dataset] {before} -> {after} "
              f"({before - after} rejetés)")
    return df_clean
