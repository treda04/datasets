import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

# Chemins
DATA_FILE = Path("siem_windows/data/processed_v4/train.parquet")
EDA_OUT_DIR = Path("siem_windows/results_v4/eda")

def main():
    print("=== 🔍 Lancement de l'EDA Visuelle (SIEM Windows APT29) ===")
    EDA_OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Chargement des données
    try:
        df = pd.read_parquet(DATA_FILE)
        print(f"✅ Données chargées : {df.shape[0]} fenêtres.")
    except Exception as e:
        print(f"❌ Erreur de lecture : {e}")
        return

    # Renommer les classes pour de beaux graphiques
    df['Classe'] = df['label'].map({0: 'Normal (Bruit de fond)', 1: 'Attaque (APT29)'})
    sns.set_theme(style="whitegrid")

    # --- GRAPHIQUE 1 : Le défi de l'Imbalance ---
    print("📊 Génération du graphique de déséquilibre des classes...")
    plt.figure(figsize=(7, 5))
    ax = sns.countplot(data=df, x='Classe', palette=['#3498db', '#e74c3c'])
    plt.title("Preuve n°1 : Le défi du SIEM (Déséquilibre Massif)", fontsize=14, fontweight='bold')
    plt.ylabel("Nombre de fenêtres de temps")
    plt.xlabel("")
    
    # Ajouter les valeurs sur les barres
    for p in ax.patches:
        ax.annotate(f'{int(p.get_height())}', (p.get_x() + p.get_width() / 2., p.get_height()),
                    ha='center', va='bottom', fontsize=12, fontweight='bold')
        
    plt.tight_layout()
    plt.savefig(EDA_OUT_DIR / "eda_class_imbalance.png", dpi=150)
    plt.close()

    # --- GRAPHIQUE 2 : La Signature MITRE ATT&CK de l'APT29 ---
    print("📊 Génération de l'empreinte comportementale MITRE...")
    # On sélectionne les catégories phares que tu as codées dans ton preprocess v4
    cols_to_plot = ['registry_mod_score', 'powershell_score', 'wfp_network_score', 'credential_dump_score']
    labels = ['Modif. Registre', 'PowerShell', 'Réseau WFP', 'Dumping Identifiants']
    
    df_melted = df.melt(id_vars=['Classe'], value_vars=cols_to_plot, 
                        var_name='Tactique MITRE', value_name='Score Moyen')
    
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df_melted, x='Tactique MITRE', y='Score Moyen', hue='Classe', 
                palette=['#3498db', '#e74c3c'], errorbar=None)
    plt.title("Preuve n°2 : Empreinte comportementale de l'APT29", fontsize=14, fontweight='bold')
    plt.xticks(ticks=range(len(labels)), labels=labels, fontsize=11)
    plt.ylabel("Intensité moyenne par fenêtre")
    plt.xlabel("")
    plt.legend(title='Type de Trafic')
    plt.tight_layout()
    plt.savefig(EDA_OUT_DIR / "eda_mitre_signature.png", dpi=150)
    plt.close()

    print(f"✅ Terminé ! Les graphiques sont sauvegardés dans : {EDA_OUT_DIR}")

if __name__ == "__main__":
    main()