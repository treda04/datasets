import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os
import time
import warnings

warnings.filterwarnings('ignore')

print("=== 🧠 ENTRAÎNEMENT DU MODÈLE XGBOOST (SOC LAYER 1) ===\n")

# --- 1. CONFIGURATION DES CHEMINS ---
# Le script sera lancé depuis la racine, on pointe vers le dossier data
DATA_DIR = 'cicids2017/data/'
MODEL_DIR = 'cicids2017/models/'

# --- 2. CHARGEMENT DES DONNÉES ---
print("📥 1. Chargement des données pré-traitées (Cela peut prendre quelques secondes)...")
start_time = time.time()

# On charge les 4 fichiers créés par ton script précédent
X_train = pd.read_csv(os.path.join(DATA_DIR, 'X_train_processed.csv'))
y_train = pd.read_csv(os.path.join(DATA_DIR, 'y_train_processed.csv')).values.ravel()

X_test = pd.read_csv(os.path.join(DATA_DIR, 'X_test_processed.csv'))
y_test = pd.read_csv(os.path.join(DATA_DIR, 'y_test_processed.csv')).values.ravel()

print(f"✅ Données chargées ! ({len(X_train)} lignes pour l'entraînement) en {round(time.time() - start_time, 2)}s.")

# --- 3. CRÉATION DU MODÈLE ---
print("\n⚙️ 2. Initialisation de l'algorithme XGBoost...")
model = xgb.XGBClassifier(
    n_estimators=100,          # Nombre d'arbres de décision
    max_depth=6,               # Profondeur de chaque arbre
    learning_rate=0.1,         # Vitesse d'apprentissage
    n_jobs=-1,                 # -1 = Utiliser TOUS les cœurs de ton processeur Kali
    tree_method='hist',        # Ultra-rapide pour les datasets > 1 Million de lignes
    random_state=42
)

# --- 4. ENTRAÎNEMENT (TRAINING) ---
print("\n🏋️‍♂️ 3. Début de l'entraînement... (Laisse la machine travailler)")
start_train = time.time()

model.fit(X_train, y_train)

print(f"✅ Entraînement terminé avec succès en {round(time.time() - start_train, 2)}s !")

# --- 5. ÉVALUATION (TESTING) ---
print("\n🎯 4. Évaluation du modèle sur les données de test...")
y_pred = model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
print(f"\n🏆 PRÉCISION GLOBALE (Accuracy) : {acc * 100:.2f}%")

print("\n📊 Rapport de Classification détaillé par type d'attaque :")
# Noms des classes récupérés lors du preprocessing
classes_names = ['Brute Force', 'Normal Traffic', 'Port Scanning', 'Web Attacks']
print(classification_report(y_test, y_pred, target_names=classes_names))

# --- 6. SAUVEGARDE DU CERVEAU ---
print("\n💾 5. Sauvegarde du modèle d'Intelligence Artificielle...")
if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

model_path = os.path.join(MODEL_DIR, 'xgb_model.pkl')
joblib.dump(model, model_path)
print(f"✅ Modèle sauvegardé avec succès dans : {model_path}")
print("🚀 LE PILIER RÉSEAU EST OPÉRATIONNEL !")