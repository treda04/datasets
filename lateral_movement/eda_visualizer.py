import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

# Chemins
DATA_FILE = Path("lateral_movement/data/processed_v2/train.parquet")
EDA_OUT_DIR = Path("lateral_movement/results_v2/eda")

def main():
    print("=== 🔍 Lancement de l'EDA Visuelle (Lateral Movement) ===")
    EDA_OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Chargement des données
    try:
        df = pd.read_parquet(DATA_FILE)
        print(f"✅ Données chargées : {df.shape[0]} fenêtres.")
    except Exception as e:
        print(f"❌ Erreur de lecture : {e}")
        return

    # Remplacement des labels pour l'affichage
    df['Classe'] = df['label'].map({0: 'Normal (Bruit)', 1: 'Lateral Movement (Attaque)'})

    sns.set_theme(style="whitegrid")

    # --- GRAPHIQUE 1 : Preuve de l'Identité (Entropie) ---
    print("📊 Génération du Boxplot d'Entropie...")
    plt.figure(figsize=(8, 6))
    sns.boxplot(data=df, x='Classe', y='entropy_target_users', palette="Set2")
    plt.title("Preuve n°1 : Diversité des cibles (Entropie de Shannon)", fontsize=14, fontweight='bold')
    plt.ylabel("Entropie (Cibles uniques scannées)")
    plt.xlabel("")
    plt.tight_layout()
    plt.savefig(EDA_OUT_DIR / "eda_entropy_targets.png", dpi=150)
    plt.close()

    # --- GRAPHIQUE 2 : Preuve des EventIDs (Télémétrie Sysmon/Windows) ---
    print("📊 Génération du comparatif des EventIDs critiques...")
    # On sélectionne quelques scores d'EventIDs cruciaux que tu as isolés
    cols_to_plot = ['priv_object_score', 'smb_share_score', 'logon_failure_ratio']
    
    # On calcule la moyenne pour le trafic Normal vs Lateral
    df_melted = df.melt(id_vars=['Classe'], value_vars=cols_to_plot, 
                        var_name='Feature Cyber', value_name='Valeur Moyenne')
    
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df_melted, x='Feature Cyber', y='Valeur Moyenne', hue='Classe', palette="Set1", errorbar=None)
    plt.title("Preuve n°2 : Fréquence des EventIDs suspects", fontsize=14, fontweight='bold')
    plt.xticks(ticks=[0, 1, 2], labels=['Privileged Object (4674)', 'SMB Share (5145)', 'Ratio d\'Échecs Logon'])
    plt.ylabel("Fréquence / Ratio par fenêtre")
    plt.xlabel("")
    plt.tight_layout()
    plt.savefig(EDA_OUT_DIR / "eda_critical_events.png", dpi=150)
    plt.close()

    print(f"✅ Terminé ! Les graphiques sont sauvegardés dans : {EDA_OUT_DIR}")

if __name__ == "__main__":
    main()