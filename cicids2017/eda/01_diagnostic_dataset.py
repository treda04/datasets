"""
═══════════════════════════════════════════════════════════════════════
PROJET PFE SOC Router — Diagnostic du dataset CIC-IDS-2017
Auteur : Mohamed Reda Taous
Objectif : Vérifier la composition réelle du dataset avant ML
═══════════════════════════════════════════════════════════════════════
"""

import pandas as pd
import numpy as np
from pathlib import Path

INPUT_FILE = Path("cicids2017/data/cicids2017.csv")
LIGNES_MAX = 500_000
TARGET_COL = "Attack Type"

print("=" * 70)
print("🔬 DIAGNOSTIC DU DATASET CIC-IDS-2017")
print("=" * 70)

# 1. Taille totale du fichier
print(f"\n📂 Fichier : {INPUT_FILE}")
if not INPUT_FILE.exists():
    print(f"❌ Fichier introuvable !")
    exit()

size_mb = INPUT_FILE.stat().st_size / (1024*1024)
print(f"   Taille : {size_mb:.1f} MB")

# 2. Compter le nombre total de lignes (sans tout charger)
print("\n🔢 Comptage du nombre total de lignes...")
with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
    total_lines = sum(1 for _ in f) - 1  # -1 pour le header
print(f"   Total lignes : {total_lines:,}")
print(f"   Lignes utilisées (LIGNES_MAX) : {LIGNES_MAX:,}")
print(f"   Pourcentage utilisé : {LIGNES_MAX/total_lines*100:.1f}%")

# 3. Charger les 500k premières lignes (comme dans preprocess_v2)
print(f"\n📥 Chargement des {LIGNES_MAX:,} premières lignes...")
df_partial = pd.read_csv(INPUT_FILE, nrows=LIGNES_MAX)
df_partial.columns = df_partial.columns.str.strip()
print(f"   Shape : {df_partial.shape}")

# 4. Distribution des classes dans ce qu'on utilise
print(f"\n🏷️  DISTRIBUTION DES CLASSES (sur {LIGNES_MAX:,} lignes) :")
print("-" * 70)
class_counts_partial = df_partial[TARGET_COL].value_counts()
total_partial = len(df_partial)
for cls, count in class_counts_partial.items():
    pct = count/total_partial*100
    bar = '█' * int(pct/2)
    print(f"   {cls:<25s} {count:>10,} ({pct:>6.2f}%) {bar}")

# 5. Sample du dataset complet (pour comparer)
print(f"\n📥 Échantillonnage du dataset COMPLET pour comparaison...")
# On lit un échantillon réparti dans tout le fichier
# Pour éviter de charger 2.8M lignes, on prend 1 ligne sur N
skip_step = max(1, total_lines // 500_000)
print(f"   Stratégie : 1 ligne tous les {skip_step} (échantillon réparti)")

skip_rows = [i for i in range(1, total_lines+1) if i % skip_step != 0]
try:
    df_full_sample = pd.read_csv(INPUT_FILE, skiprows=skip_rows)
    df_full_sample.columns = df_full_sample.columns.str.strip()
    print(f"   Échantillon shape : {df_full_sample.shape}")
    
    print(f"\n🏷️  DISTRIBUTION DES CLASSES (échantillon réparti du dataset COMPLET) :")
    print("-" * 70)
    class_counts_full = df_full_sample[TARGET_COL].value_counts()
    total_full = len(df_full_sample)
    for cls, count in class_counts_full.items():
        pct = count/total_full*100
        bar = '█' * int(pct/2)
        print(f"   {cls:<25s} {count:>10,} ({pct:>6.2f}%) {bar}")
    
    # 6. CLASSES MANQUANTES dans les 500k premières lignes
    classes_in_partial = set(class_counts_partial.index)
    classes_in_full = set(class_counts_full.index)
    classes_missing = classes_in_full - classes_in_partial
    
    print(f"\n⚠️  CLASSES MANQUANTES dans les 500k premières lignes :")
    print("-" * 70)
    if classes_missing:
        for cls in classes_missing:
            n = class_counts_full[cls]
            pct = n/total_full*100
            print(f"   ❌ {cls:<25s} ({n:,} lignes au total, soit {pct:.2f}% du dataset)")
        print(f"\n   🚩 Tu rates {len(classes_missing)} classe(s) sur {len(classes_in_full)} !")
    else:
        print(f"   ✅ Aucune classe manquante. Les 500k lignes couvrent toutes les classes.")
    
except Exception as e:
    print(f"   ⚠️  Erreur lors de l'échantillonnage : {e}")

# 7. Conclusion
print("\n" + "=" * 70)
print("📊 SYNTHÈSE")
print("=" * 70)
print(f"   Dataset total              : {total_lines:,} lignes")
print(f"   Dataset utilisé pour ML    : {LIGNES_MAX:,} lignes ({LIGNES_MAX/total_lines*100:.1f}%)")
print(f"   Nombre de classes utilisées : {len(class_counts_partial)}")
print(f"   Classes manquantes         : {len(classes_missing) if 'classes_missing' in dir() else 'N/A'}")
print("\n✅ Diagnostic terminé.")
print("=" * 70)