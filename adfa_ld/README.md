# ADFA-LD — Détection d'intrusions par syscalls (HIDS)

Modèle de Machine Learning classifiant des traces d'appels système Linux comme **normales** ou **attaque**, basé sur le dataset public **ADFA-LD** (UNSW Sydney, 2012).

## Résumé

- **Tâche** : classification binaire (Normal vs Attaque)
- **Approche** : n-grammes de syscalls (1 à 3) + Random Forest calibré + seuil de décision optimisé F2
- **Modèle retenu** : v2, seuil 0.40

### Métriques finales (test set, 1 797 fichiers)

| Métrique | Valeur | Cible |
|---|---|---|
| **Recall** | **0.9099** | ≥ 0.90 ✅ |
| **F2-score** | **0.8908** | — |
| F1-score | 0.8635 | ≥ 0.95 ⚠️ |
| AUC-ROC | 0.9852 | ≥ 0.97 ✅ |
| Precision | 0.8217 | — |
| Taux faux positifs | 2.9% | < 5% ✅ |
| Gap CV-Test F1 | 0.0354 | < 0.10 ✅ |

**Recall par famille d'attaque :**
- Adduser, Java_Meterpreter : **100%**
- Hydra_FTP : 99% — Hydra_SSH : 90% — Meterpreter : 89%
- Web_Shell : 44% *(limitation structurelle de l'approche n-gram, documentée)*

## Structure du projet

```
adfa_ld/
├── README.md                          ← Vue d'ensemble (ce fichier)
├── PLAN.md                            ← Plan général du travail
├── AVANCEMENT.md                      ← Journal détaillé des 3 phases
├── EXPLICATION_DATA.md                ← Documentation A→Z des données
├── EXPLICATION_MODELS.md              ← Documentation A→Z des modèles
│
├── data/
│   ├── ADFA-LD/                       ← Données brutes (ne pas modifier)
│   │   ├── Training_Data_Master/        833 fichiers normaux
│   │   ├── Validation_Data_Master/      4 372 fichiers normaux
│   │   └── Attack_Data_Master/          60 dossiers / 746 fichiers d'attaque
│   ├── ADFA-LD+Syscall+List.txt
│   └── processed/                     ← Créé par preprocess.py
│       ├── X_train.npz / X_test.npz
│       ├── y_train.csv  / y_test.csv
│       ├── vectorizer.pkl
│       └── manifest.json
│
├── notebooks/                         ← Exploration interactive
│   ├── 01_eda.ipynb                   ← Phase 1 — EDA
│   ├── 02_modeling.ipynb              ← Phase 2 — Prototype v1 (figé, référence)
│   └── 03_modeling_v2.ipynb           ← Phase 2 bis — Modèle v2 retenu
│
├── pipeline/                          ← Phase 3 — Scripts production reproductibles
│   ├── io_utils.py                    ← Module partagé (chargement, constantes)
│   ├── preprocess.py                  ← Étape 1/3 — load + clean + split + vectorize
│   ├── train.py                       ← Étape 2/3 — RF + calibration + tuning seuil
│   └── evaluate.py                    ← Étape 3/3 — métriques + figures
│
├── saved_models/
│   ├── v2_final/                      ← Modèle production (sortie du pipeline)
│   │   ├── model.pkl
│   │   ├── manifest.json              ← seuil 0.40, hyperparams, métriques CV
│   │   └── threshold_scan.csv
│   ├── rf_adfa.pkl + ...              ← Modèle v1 (notebook 02, référence)
│   └── rf_adfa_v2.pkl + ...           ← Modèle v2 (notebook 03, référence)
│
└── results/
    ├── eda/                           ← Figures Phase 1
    ├── modeling/                      ← Résultats notebook v1
    ├── modeling_v2/                   ← Résultats notebook v2
    └── final/                         ← Résultats pipeline production
        ├── metrics.json
        ├── classification_report.txt
        ├── confusion_matrix.png
        ├── roc_pr_curves.png
        ├── per_attack_family.{csv,png}
        └── feature_importance.{csv,png}
```

## Reproduction des résultats

### Prérequis
- Python 3.11+
- Packages : `scikit-learn`, `numpy`, `pandas`, `scipy`, `matplotlib`, `seaborn`, `joblib`

### Pipeline production (3 commandes)

```bash
# Depuis le dossier adfa_ld/
python pipeline/preprocess.py     # Charge ADFA-LD, nettoie, splitte, vectorise
python pipeline/train.py          # Entraîne RF + calibration, choisit le seuil
python pipeline/evaluate.py       # Évalue le test, génère métriques + figures
```

Tous les artefacts sont produits dans :
- `data/processed/` (matrices + vectorizer)
- `saved_models/v2_final/` (modèle + manifest)
- `results/final/` (métriques + 4 figures)

### Notebooks (exploration interactive)

```bash
jupyter notebook notebooks/01_eda.ipynb           # Phase 1 — EDA
jupyter notebook notebooks/02_modeling.ipynb      # Phase 2 — v1
jupyter notebook notebooks/03_modeling_v2.ipynb   # Phase 2 bis — v2
```

## Hyperparamètres clés

| Composant | Valeur |
|---|---|
| Vectorizer | `CountVectorizer(ngram_range=(1,3), max_features=1500, min_df=2)` |
| Modèle | `RandomForestClassifier(n_estimators=200, max_depth=20, min_samples_leaf=2, class_weight='balanced')` |
| Calibration | `CalibratedClassifierCV(method='isotonic', cv=5)` |
| Split | `GroupShuffleSplit(test_size=0.3, random_state=42)` groupé par scénario |
| Seuil de décision | **0.40** (optimisé par F2 sur CV train) |

## Choix méthodologiques

1. **Split groupé par scénario** (`GroupShuffleSplit`) → anti-leakage rigoureux
2. **N-grammes (1-3)** → capture fréquences, paires et séquences courtes
3. **Random Forest calibré** → robuste, interprétable, probabilités fiables
4. **`class_weight='balanced'`** → gère le déséquilibre 7:1
5. **Seuil F2-optimisé** → favorise le recall (critère IDS)
6. **Évaluation test une seule fois** → pas d'overfitting indirect

Détails complets : voir [`EXPLICATION_MODELS.md`](EXPLICATION_MODELS.md).

## Limites assumées

- **Web_Shell** détecté à 44% — limitation structurelle de l'approche n-gram (signature noyée dans le trafic Apache normal)
- **Dataset 2012** : kernel Linux 2.6, x86 32-bit → ne couvre pas les syscalls modernes (eBPF, io_uring)
- **6 familles d'attaque seulement** : pas de zero-day par construction (modèle supervisé)
