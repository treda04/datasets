# cicids2017/ — Modèle 2 : Détection Flux Réseau (CIC-IDS-2017)

## Rôle
Détection d'attaques réseau (DDoS, Brute Force, Port Scanning, Web Attacks)
à partir de flux réseau bidirectionnels extraits de captures PCAP.

## Données
- **Source :** Canadian Institute for Cybersecurity (UNB)
- **Format :** CSV — 80+ features de flux réseau (durée, octets, paquets, flags TCP...)
- **Volume :** ~500 000 lignes chargées (dataset complet > 2M lignes)
- **Classes :** Brute Force, Normal Traffic, Port Scanning, Web Attacks

## Structure
```
cicids2017/
├── data/
│   ├── cicids2017.csv              ← Dataset original
│   ├── X_train_processed.csv       ← Features train après SMOTE + scaling
│   ├── X_test_processed.csv        ← Features test
│   ├── y_train_processed.csv       ← Labels train
│   └── y_test_processed.csv        ← Labels test
├── eda/
│   └── eda_analysis.ipynb          ← Analyse exploratoire + distributions
├── preprocessing/
│   └── preprocess.py               ← Nettoyage, SMOTE, StandardScaler
├── models/
│   ├── train_xgboost.py            ← Entraînement XGBoost
│   └── xgb_model.pkl               ← Modèle entraîné
├── results/
│   └── generate_results.py         ← Matrice confusion + feature importance
└── README.md
```

## Choix Méthodologiques

### XGBoost
Algorithme de gradient boosting, optimal pour les données tabulaires
déséquilibrées. Gère naturellement les features manquantes.

### SMOTE (avant split → CORRIGÉ : après split)
Le SMOTE est appliqué UNIQUEMENT sur X_train pour éviter le leakage.
Les données synthétiques ne doivent jamais contaminer le test set.

## Problèmes Identifiés (Audit Phase 1) — CRITIQUES
| Problème | Gravité | Description |
|----------|---------|-------------|
| Shortcut Learning sur `Destination Port` | CRITIQUE | Le modèle détecte le port, pas le comportement |
| Classes hardcodées (4 au lieu de 14) | MODÉRÉE | Mapping non documenté |
| Pas de courbe ROC ni PR curve | FAIBLE | Métriques incomplètes |

**Le F1=1.00 est artificiel.** Preuve : lancer `model.feature_importances_`
→ `Destination Port` apparaîtra avec un score > 0.5.

**Correction recommandée :** Supprimer `Destination Port`, `Source Port` du feature set.

## Résultats Actuels
- Accuracy : ~100% | F1 : ~1.00 ← SUSPECT
- À reconstruire après suppression des features identifiantes

## Lancer le Pipeline
```bash
# Depuis datasets/
python cicids2017/preprocessing/preprocess.py
python cicids2017/models/train_xgboost.py
python cicids2017/results/generate_results.py
```
