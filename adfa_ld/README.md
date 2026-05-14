# adfa_ld/ — Modèle 1 : Détection Syscalls Linux (ADFA-LD)

## Rôle
Détection d'anomalies comportementales au niveau OS Linux via des séquences
d'appels système (syscalls). Détecte : rootkits, Meterpreter, Hydra, WebShell, Adduser.

## Données
- **Source :** ADFA-LD Dataset (UNSW Canberra)
- **Format :** Fichiers .txt — une séquence de syscall IDs par processus
- **Volume :** ~5 995 fichiers (Training_Data_Master + Attack_Data_Master)
- **Attaques couvertes :** Adduser, Hydra, Meterpreter, Java_Meterpreter, Web_Shell

## Structure
```
adfa_ld/
├── data/
│   ├── ADFA-LD/
│   │   ├── Training_Data_Master/   ← Processus normaux (labels=0)
│   │   ├── Attack_Data_Master/     ← Processus malveillants (labels=1)
│   │   └── Validation_Data_Master/ ← Données de validation
│   ├── adfa_processed.csv          ← Matrice trigrammes (500 features)
│   ├── ADFA-LD+Syscall+List.txt    ← Référence des 341 syscalls Linux
│   └── ADFA-LD.zip
├── eda/
│   └── eda_adfa.ipynb              ← Analyse exploratoire des séquences
├── preprocessing/
│   └── preprocess_adfa.py          ← Conversion séquences → trigrammes N-gram
├── models/
│   ├── train_adfa.py               ← Entraînement Random Forest
│   └── rf_adfa_model.pkl           ← Modèle entraîné
├── results/
│   └── generate_adfa_results.py    ← Matrice confusion + feature importance
└── README.md
```

## Choix Méthodologiques

### Représentation N-gram (trigrammes)
Chaque séquence de syscalls est transformée en trigrammes (groupes de 3 appels
consécutifs). Ex : `[open, read, close]` → trigramme `"open read close"`.
On conserve les 500 trigrammes les plus fréquents.

**Justification :** Les malwares ont des patterns d'appels système caractéristiques.
Un trigramme capture le contexte local d'exécution sans nécessiter de RNN.

### Random Forest (200 arbres)
Robuste au bruit, interprétable via feature_importance, rapide à l'inférence.

## Problèmes Identifiés (Audit Phase 1)
| Problème | Gravité | Statut |
|----------|---------|--------|
| Split aléatoire (random_state=42) — risque de fuite inter-session | MODÉRÉE | À corriger |
| Vectorizer fit sur tout le dataset avant split | FAIBLE | À corriger |
| Pas de courbe ROC ni calibration de seuil | FAIBLE | À ajouter |

## Résultats Actuels
- Accuracy : ~96% | F1 : ~0.96 | FPR : ~5%
- Score crédible mais méthodologie à renforcer

## Lancer le Pipeline
```bash
# Depuis datasets/
python adfa_ld/preprocessing/preprocess_adfa.py
python adfa_ld/models/train_adfa.py
python adfa_ld/results/generate_adfa_results.py
```
