import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
import warnings

warnings.filterwarnings('ignore')

print("=== 🚀 DÉMARRAGE DU PIPELINE DE PREPROCESSING (CIC-IDS-2017) ===\n")

# --- 1. CONFIGURATION ---
INPUT_FILE = 'cicids2017/data/cicids2017.csv'
OUTPUT_DIR = 'cicids2017/data/'
TARGET_COL = 'Attack Type'  # Adapté suite à notre EDA !
# On limite à 500k lignes pour le développement (pour éviter les Memory Errors)
# Une fois que tout marchera, tu pourras enlever cette limite pour le PFE final.
LIGNES_MAX = 500000 

# --- 2. CHARGEMENT ET NETTOYAGE DE BASE ---
print(f"📥 1. Chargement de {LIGNES_MAX} lignes depuis {INPUT_FILE}...")
df = pd.read_csv(INPUT_FILE, nrows=LIGNES_MAX)

# Nettoyage des espaces dans les noms de colonnes
df.columns = df.columns.str.strip()

# Suppression des colonnes mortes (Zero Variance) trouvées lors de l'EDA
constant_cols = [col for col in df.columns if df[col].nunique() == 1]
df.drop(columns=constant_cols, inplace=True)
print(f"🧹 {len(constant_cols)} colonnes constantes supprimées.")

# --- 3. SÉPARATION DES DONNÉES (X et y) ---
print("\n✂️ 2. Séparation des caractéristiques (X) et de la cible (y)...")
X = df.drop(columns=[TARGET_COL])
y = df[TARGET_COL]

# Encodage de la cible (Transformer les noms d'attaques en numéros : 0, 1, 2...)
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)
print(f"🏷️ Classes détectées : {encoder.classes_}")

# --- 4. TRAIN / TEST SPLIT ---
# CRITIQUE : Toujours séparer AVANT de faire le SMOTE pour ne pas tricher (Data Leakage)
print("\n🔀 3. Découpage en Train (80%) et Test (20%)...")
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)

# --- 5. ÉQUILIBRAGE AVEC SMOTE ---
print("\n⚖️ 4. Application de SMOTE sur les données d'entraînement...")
print(f"📊 Avant SMOTE -> Taille de X_train : {X_train.shape}")
smote = SMOTE(random_state=42)
X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)
print(f"📈 Après SMOTE -> Taille de X_train équilibré : {X_train_smote.shape}")

# --- 6. MISE À L'ÉCHELLE (SCALING) ---
print("\n📏 5. Normalisation des données (StandardScaler)...")
scaler = StandardScaler()
# L'IA apprend l'échelle uniquement sur les données d'entraînement (fit_transform)
X_train_scaled = scaler.fit_transform(X_train_smote)
# Elle l'applique bêtement sur les données de test (transform)
X_test_scaled = scaler.transform(X_test)

# --- 7. SAUVEGARDE DES RÉSULTATS ---
print("\n💾 6. Sauvegarde des fichiers pré-traités pour l'entraînement...")

# Reconversion en DataFrame pour la sauvegarde
df_X_train = pd.DataFrame(X_train_scaled, columns=X.columns)
df_X_test = pd.DataFrame(X_test_scaled, columns=X.columns)

df_X_train.to_csv(os.path.join(OUTPUT_DIR, 'X_train_processed.csv'), index=False)
df_X_test.to_csv(os.path.join(OUTPUT_DIR, 'X_test_processed.csv'), index=False)
pd.Series(y_train_smote).to_csv(os.path.join(OUTPUT_DIR, 'y_train_processed.csv'), index=False)
pd.Series(y_test).to_csv(os.path.join(OUTPUT_DIR, 'y_test_processed.csv'), index=False)

print("\n✅ PIPELINE TERMINÉ AVEC SUCCÈS ! Les données sont prêtes pour XGBoost.")