"""
ADFA-LD Preprocessing v2 — Sans data leakage
=============================================
Corrige :
  1. CountVectorizer fit sur train ONLY (au lieu de tout le dataset)
  2. Sauve le mapping fichier → famille d'attaque pour GroupShuffleSplit
     en aval (chaque famille = 1 groupe → pas de fuite inter-session)
  3. Sauve le vectorizer en .pkl
  4. Format compressé .npz (plus rapide que CSV pour matrice 500-D)

Lancer depuis datasets/ :
    python adfa_ld/preprocessing/preprocess_adfa_v2.py
"""

import json
import os
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy.sparse
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import GroupShuffleSplit

warnings.filterwarnings("ignore")

NORMAL_DIR = Path("adfa_ld/data/ADFA-LD/Training_Data_Master/")
ATTACK_DIR = Path("adfa_ld/data/ADFA-LD/Attack_Data_Master/")
OUTPUT_DIR = Path("adfa_ld/data/processed_v2")
ARTIFACTS_DIR = Path("adfa_ld/saved_models")
RANDOM_STATE = 42
N_FEATURES = 500
NGRAM_RANGE = (3, 3)


def load_normal(directory: Path, n_buckets: int = 10):
    """Données saines : 1 fichier = 1 séquence.

    On répartit en n_buckets pseudo-groupes pour que GroupShuffleSplit
    puisse mettre des normaux à la fois en train ET en test.
    """
    seqs, labels, groups, files = [], [], [], []
    sorted_files = [f for f in sorted(directory.iterdir()) if f.suffix == ".txt"]
    for idx, f in enumerate(sorted_files):
        seqs.append(f.read_text().strip())
        labels.append(0)
        groups.append(f"normal_{idx % n_buckets:02d}")
        files.append(f.name)
    return seqs, labels, groups, files


def load_attacks(directory: Path):
    """Attaques : 1 fichier = 1 séquence, groupe = nom du sous-dossier (famille)."""
    seqs, labels, groups, files = [], [], [], []
    for family_dir in sorted(directory.iterdir()):
        if not family_dir.is_dir():
            continue
        family = family_dir.name  # ex: Hydra_FTP, Meterpreter, Web_Shell, ...
        for f in family_dir.rglob("*.txt"):
            seqs.append(f.read_text().strip())
            labels.append(1)
            groups.append(family)
            files.append(f"{family}/{f.name}")
    return seqs, labels, groups, files


def main():
    print("=== PREPROCESSING ADFA-LD v2 (no leakage) ===\n")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Chargement
    print("[1/5] Lecture des fichiers...")
    n_seqs, n_labels, n_groups, n_files = load_normal(NORMAL_DIR)
    a_seqs, a_labels, a_groups, a_files = load_attacks(ATTACK_DIR)
    seqs = n_seqs + a_seqs
    labels = np.array(n_labels + a_labels)
    groups = np.array(n_groups + a_groups)
    files = n_files + a_files
    print(f"      Normaux : {len(n_seqs)}  |  Attaques : {len(a_seqs)}")
    print(f"      Familles d'attaques : {sorted(set(a_groups))}")

    # 2. GroupShuffleSplit par famille (chaque famille reste entièrement train OU test)
    print("\n[2/5] GroupShuffleSplit par famille (anti-fuite inter-session)...")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_STATE)
    train_idx, test_idx = next(gss.split(seqs, labels, groups))

    train_seqs = [seqs[i] for i in train_idx]
    test_seqs = [seqs[i] for i in test_idx]
    y_train = labels[train_idx]
    y_test = labels[test_idx]
    g_train = groups[train_idx]
    g_test = groups[test_idx]

    # Sanity check : groupes train et test disjoints
    overlap = set(g_train) & set(g_test)
    if overlap:
        print(f"      [WARNING] Groupes overlap : {overlap}")
    else:
        print("      [OK] Groupes train et test disjoints.")
    print(f"      Train groupes : {sorted(set(g_train))}")
    print(f"      Test  groupes : {sorted(set(g_test))}")

    # 3. Vectorizer FIT sur train SEULEMENT
    print(f"\n[3/5] CountVectorizer fit_transform sur TRAIN seulement "
          f"(ngram={NGRAM_RANGE}, max_features={N_FEATURES})...")
    vectorizer = CountVectorizer(ngram_range=NGRAM_RANGE, max_features=N_FEATURES)
    X_train = vectorizer.fit_transform(train_seqs)  # fit + transform
    X_test = vectorizer.transform(test_seqs)        # transform only
    feature_names = list(vectorizer.get_feature_names_out())
    print(f"      X_train : {X_train.shape}  |  X_test : {X_test.shape}")

    # 4. Sauvegarde
    print("\n[4/5] Sauvegarde matrices sparses + métadonnées...")
    scipy.sparse.save_npz(OUTPUT_DIR / "X_train.npz", X_train)
    scipy.sparse.save_npz(OUTPUT_DIR / "X_test.npz", X_test)
    np.save(OUTPUT_DIR / "y_train.npy", y_train)
    np.save(OUTPUT_DIR / "y_test.npy", y_test)
    np.save(OUTPUT_DIR / "g_train.npy", g_train)
    np.save(OUTPUT_DIR / "g_test.npy", g_test)

    joblib.dump(vectorizer, ARTIFACTS_DIR / "adfa_vectorizer.pkl")
    with open(ARTIFACTS_DIR / "feature_columns.json", "w") as f:
        json.dump(feature_names, f, indent=2)

    # 5. Manifest
    print("\n[5/5] Écriture manifest.json...")
    manifest = {
        "version": 2,
        "n_normal": len(n_seqs),
        "n_attack": len(a_seqs),
        "attack_families": sorted(set(a_groups)),
        "ngram_range": list(NGRAM_RANGE),
        "n_features": int(X_train.shape[1]),
        "n_train": int(X_train.shape[0]),
        "n_test": int(X_test.shape[0]),
        "split_method": "GroupShuffleSplit_by_attack_family",
        "random_state": RANDOM_STATE,
        "train_groups": sorted(set(g_train.tolist())),
        "test_groups": sorted(set(g_test.tolist())),
    }
    with open(OUTPUT_DIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n      Données → {OUTPUT_DIR}/")
    print(f"      Artefacts → {ARTIFACTS_DIR}/")
    print("\n[OK] Preprocessing v2 terminé. Lancer ensuite train_adfa_v2.py")


if __name__ == "__main__":
    main()
