import os
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
import warnings

warnings.filterwarnings('ignore')

print("=== 🛠️ PREPROCESSING : ADFA-LD (APPELS SYSTÈME) ===\n")

# --- 1. CONFIGURATION DES CHEMINS ---
# N'oublie pas le sous-dossier ADFA-LD qu'on a découvert !
NORMAL_DIR = 'adfa_ld/data/ADFA-LD/Training_Data_Master/'
ATTACK_DIR = 'adfa_ld/data/ADFA-LD/Attack_Data_Master/'
OUTPUT_DIR = 'adfa_ld/data/'

def load_data(directory, label, is_attack=False):
    """Lit les fichiers textes et retourne une liste de séquences"""
    sequences = []
    labels = []
    
    if is_attack:
        # Les attaques sont dans des sous-dossiers (Adduser, Hydra, etc.)
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.txt'):
                    with open(os.path.join(root, file), 'r') as f:
                        sequences.append(f.read().strip())
                    labels.append(label)
    else:
        # Les données normales sont directement dans le dossier
        for file in os.listdir(directory):
            if file.endswith('.txt'):
                with open(os.path.join(directory, file), 'r') as f:
                    sequences.append(f.read().strip())
                labels.append(label)
                
    return sequences, labels

# --- 2. CHARGEMENT DES FICHIERS ---
print("📥 1. Lecture des milliers de fichiers textes...")
normal_seqs, normal_labels = load_data(NORMAL_DIR, label=0, is_attack=False)
attack_seqs, attack_labels = load_data(ATTACK_DIR, label=1, is_attack=True)

all_sequences = normal_seqs + attack_seqs
all_labels = normal_labels + attack_labels

print(f"✅ {len(normal_seqs)} processus Normaux et {len(attack_seqs)} processus Malveillants chargés.")

# --- 3. EXTRACTION NLP (N-GRAMS) ---
print("\n🧬 2. Transformation des séquences en Trigrammes (Blocs de 3)...")
# On utilise CountVectorizer comme si on analysait des tweets ou des emails
# On limite aux 500 trigrammes les plus fréquents pour ne pas faire exploser la RAM
vectorizer = CountVectorizer(ngram_range=(3, 3), max_features=500)

X = vectorizer.fit_transform(all_sequences)

# --- 4. CRÉATION DU DATASET FINAL ---
print("📊 3. Construction du tableau pour l'IA...")
# On récupère le nom des colonnes (les séquences ex: "11 4 3")
feature_names = vectorizer.get_feature_names_out()

df = pd.DataFrame(X.toarray(), columns=feature_names)
df['is_threat'] = all_labels

# --- 5. SAUVEGARDE ---
output_path = os.path.join(OUTPUT_DIR, 'adfa_processed.csv')
df.to_csv(output_path, index=False)

print(f"\n💾 4. Fichier sauvegardé : {output_path}")
print(f"📏 Dimensions finales : {df.shape[0]} lignes et {df.shape[1]} colonnes (signatures comportementales).")
print("🚀 Prêt pour l'entraînement du dernier modèle !")