import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import time
import warnings

warnings.filterwarnings('ignore')

print("=== 🧠 ENTRAÎNEMENT DU MODÈLE ADFA-LD (BOSS FINAL) ===\n")

# --- 1. CONFIGURATION ---
DATA_PATH = 'adfa_ld/data/adfa_processed.csv'
MODEL_DIR = 'adfa_ld/models/'

# --- 2. CHARGEMENT ET PRÉPARATION ---
print("📥 1. Chargement de la matrice comportementale...")
df = pd.read_csv(DATA_PATH)

X = df.drop(columns=['is_threat'])
y = df['is_threat']

# 80% pour apprendre les signatures, 20% pour le test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"📊 Entraînement sur {len(X_train)} processus, et test sur {len(X_test)} processus.")

# --- 3. CRÉATION DU MODÈLE ---
print("\n🌲 2. Déploiement de l'IA (Random Forest)...")
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)

print("🏋️‍♂️ 3. Début de l'apprentissage des appels système...")
start_time = time.time()
model.fit(X_train, y_train)
print(f"✅ Apprentissage terminé avec succès en {round(time.time() - start_time, 2)}s !")

# --- 4. ÉVALUATION (L'EXAMEN FINAL) ---
print("\n🎯 4. L'Examen Final...")
y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
print(f"\n🏆 PRÉCISION GLOBALE (Accuracy) : {acc * 100:.2f}%")

print("\n📊 Rapport de Classification :")
classes_names = ['Processus Sain (0)', 'Rootkit/Malware (1)']
print(classification_report(y_test, y_pred, target_names=classes_names))

# --- 5. SAUVEGARDE ---
print("\n💾 5. Sauvegarde du Cerveau Comportemental...")
os.makedirs(MODEL_DIR, exist_ok=True)
model_path = os.path.join(MODEL_DIR, 'rf_adfa_model.pkl')
joblib.dump(model, model_path)

print(f"✅ Modèle sauvegardé ! Chemin : {model_path}")
print("🚀 L'ARCHITECTURE COMPLÈTE DU SOC EST DÉSORMAIS EN LIGNE !")