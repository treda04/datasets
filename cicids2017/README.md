# CIC-IDS-2017 — Détection d'attaques réseau (NIDS)

Modèle de Machine Learning multi-classes (7 classes) classifiant des **flux réseau** comme normaux ou attaque (DoS, DDoS, Port Scanning, Brute Force, Web Attacks, Bots), basé sur le dataset public **CIC-IDS-2017** (Canadian Institute for Cybersecurity, UNB).

---

## ✅ État du projet — 100% terminé + audité

| Phase | Statut | Date | Livrables |
|---|---|---|---|
| **Phase 0** — Documentation initiale | ✅ | 2026-05-19 | `EXPLICATION_DATA.md`, `PLAN.md`, `AVANCEMENT.md` |
| **Phase 1** — EDA | ✅ | 2026-05-19 | `notebooks/01_eda.ipynb` + `results/eda/` |
| **Phase 2** — Modeling | ✅ | 2026-05-19 | `notebooks/02_modeling.ipynb` + `results/modeling/` |
| **Phase 3** — Pipeline production | ✅ | 2026-05-19 | `pipeline/` + `saved_models/v1_final/` + `results/final/` |
| **Documentation finale** | ✅ | 2026-05-19 | `EXPLICATION_MODELS.md` (A→Z + analyse + avis) |
| **🔍 Audit critique + correction** | ✅ | 2026-05-19 | [`AUDIT_RAPPORT.md`](AUDIT_RAPPORT.md) — leakage corrigé |

⚠️ **Important :** un audit a révélé un leakage train↔test de 23.5% à cause des doublons générés par la suppression de `Destination Port`. Le pipeline a été corrigé (déduplication ajoutée) et toutes les métriques ci-dessous reflètent les **vrais chiffres post-audit**. Voir [`AUDIT_RAPPORT.md`](AUDIT_RAPPORT.md) pour le détail.

---

## 📊 Résultats finaux (sur test set, 94 406 flux — APRÈS audit)

| Métrique | Valeur | Cible | Statut |
|---|---|---|---|
| **F1 macro** | **0.9671** | ≥ 0.85 | ✅ |
| **Recall macro** | **0.9920** | — | ✅ |
| **AUC OVR macro** | **0.9998** | ≥ 0.95 | ✅ |
| Precision macro | 0.9498 | — | — |
| F1 weighted | 0.9962 | — | — |
| **Gap CV-Test F1** | **0.0015** | < 0.10 | ✅ |
| Max feature importance | ~0.08 | < 0.20 | ✅ |
| F1 min par classe | 0.8141 (Bots) | ≥ 0.80 | ✅ |
| **Leakage train↔test** | **0.004%** | < 1% | ✅ |

**Performance par classe (post-audit) :**
- DDoS : F1 = 0.9997 ⭐
- Brute Force, DoS : F1 = 0.998
- Normal Traffic : F1 = 0.994
- Port Scanning : F1 = 0.985 (était 0.999 gonflé par leakage)
- Web Attacks : F1 = 0.982
- **Bots** : F1 = 0.814 (recall 99.1% mais precision 69% — limite inhérente)

---

## 🗺️ CARTE DU PROJET — où trouver chaque chose

### Documentation (à lire dans cet ordre)

| Fichier | Rôle | Pour quoi ? |
|---|---|---|
| [`README.md`](README.md) | **Carte du projet** (ce fichier) | Vue d'ensemble + accès rapide |
| [`PLAN.md`](PLAN.md) | Stratégie en 3 phases | Comprendre la démarche |
| [`EXPLICATION_DATA.md`](EXPLICATION_DATA.md) | **A→Z des données** | Format CSV, 7 classes, piège du `Destination Port` |
| [`EXPLICATION_MODELS.md`](EXPLICATION_MODELS.md) | **A→Z du modèle** | Hyperparamètres, métriques, résultats, mon avis |
| [`AVANCEMENT.md`](AVANCEMENT.md) | **Journal de bord** | Chronologie complète, décisions, résultats par phase |
| [`AUDIT_RAPPORT.md`](AUDIT_RAPPORT.md) | **🔍 Audit critique** | Découverte du leakage, correction appliquée, vrais chiffres |

### Données

```
data/
├── cicids2017.csv                     ← Données brutes (2 520 751 lignes, ~580 MB)
└── processed/                         ← Créé par pipeline/preprocess.py (gitignored)
    ├── X_train.npy, X_test.npy        Arrays NumPy après nettoyage + scaling
    ├── y_train.npy, y_test.npy        Labels
    ├── scaler.pkl                     StandardScaler fitté
    ├── feature_names.json             51 features finales
    └── manifest.json                  Paramètres du split
```

### EDA — Phase 1

```
notebooks/01_eda.ipynb                 ← Notebook EDA interactif
results/eda/
├── eda_summary.json                   Toutes les stats chiffrées
├── class_distribution.png             Bar + Pie chart des 7 classes
├── feature_distributions.png          Boxplots Flow Duration / Packets par classe
├── port_vs_class_heatmap.png          PREUVE VISUELLE du shortcut Destination Port
└── correlation_heatmap.png            Multi-colinéarité entre les 51 features
```

**Pourquoi ces choix ?**
- Notebook interactif pour explorer visuellement (pas de scripts pour l'EDA)
- JSON sommaire pour figer les chiffres et faciliter la doc
- Heatmap port↔classe = preuve visuelle de la décision "supprimer Destination Port"

### Modeling (prototype) — Phase 2

```
notebooks/02_modeling.ipynb            ← Notebook modeling complet
results/modeling/
├── metrics.json                       Toutes les métriques chiffrées
├── classification_report.txt          Format sklearn
├── confusion_matrix.png               7×7, version compte + version normalisée
├── per_class_metrics.png              Precision/Recall/F1 par classe (bar chart)
├── per_class_metrics.csv              Idem en CSV
├── feature_importance.png             Top 30 features par importance
└── feature_importance.csv             Les 51 features triées
saved_models/                          (notebooks)
├── rf_notebook.pkl                    Modèle du notebook (référence)
└── scaler_notebook.pkl                Scaler du notebook
```

**Pourquoi ces choix ?**
- Notebook = prototype itératif → on figeait l'approche avant Phase 3
- Sample stratifié 100k/classe = vitesse d'itération sans perdre les classes rares
- Métriques **macro** = traitement équitable des 7 classes malgré le déséquilibre

### Production (pipeline reproductible) — Phase 3

```
pipeline/                              ← Scripts production
├── io_utils.py                        Module partagé (constantes, chargement, nettoyage)
├── preprocess.py                      Étape 1/3 : load + sample + clean + split + scaler
├── train.py                           Étape 2/3 : RF + CV stratifiée + fit final
└── evaluate.py                        Étape 3/3 : métriques + 3 figures

saved_models/v1_final/                 ← Modèle production
├── model.pkl                          RandomForest entraîné (~plusieurs MB)
└── manifest.json                      Hyperparamètres + métriques CV

results/final/                         ← Résultats production
├── metrics.json                       Toutes les métriques de test
├── classification_report.txt
├── confusion_matrix.png               Identique au notebook (parité bit-à-bit)
├── per_class_metrics.png
├── per_class_metrics.csv
├── feature_importance.png
└── feature_importance.csv
```

**Pourquoi ces choix ?**
- Scripts modulaires → reproductibilité bout-en-bout en 3 commandes
- Module partagé `io_utils.py` → évite la duplication de code
- Parité **bit-à-bit** avec notebook (même `random_state=42` partout)

---

## 🚀 Reproduction des résultats

```bash
# Depuis cicids2017/
python pipeline/preprocess.py     # ~30 s — nettoyage + split + scaler
python pipeline/train.py          # ~5-7 min — RF + CV stratifiée + fit final
python pipeline/evaluate.py       # ~15 s — métriques + figures
```

→ Produit tous les artefacts dans `data/processed/`, `saved_models/v1_final/`, `results/final/`.

---

## 🔧 Décisions techniques majeures (résumé)

| Décision | Pourquoi |
|---|---|
| **Drop `Destination Port`** | Shortcut prouvé : 4 familles d'attaque sur 7 utilisent un port exclusif (DoS=80, Web=80, Brute=21/22) → un modèle naïf apprend le port, pas le comportement |
| **Déduplication après drop port** | L'audit du 2026-05-19 a révélé que le drop port créait 11.5% de doublons (Port Scanning passait de 90k à 1.9k uniques) → leakage train↔test de 23.5%. Le `drop_duplicates()` post-clean élimine ce biais. Voir [`AUDIT_RAPPORT.md`](AUDIT_RAPPORT.md) |
| **Sample stratifié cap 100k/classe** | Garde 100% des classes rares (Bots 1437, Web 2143) tout en réduisant Normal ; déséquilibre passe de 1075:1 à 70:1 |
| **`class_weight='balanced'`** | Erreur sur Bots pondérée 282× plus que sur Normal → force le modèle à prendre les classes rares au sérieux |
| **Métriques macro** (pas weighted) | Donne même poids à Bots qu'à Normal ; sinon Normal écrase tout |
| **Random Forest** (pas XGBoost) | Performance dépasse les cibles, donc inutile d'aller plus complexe |
| **StandardScaler** | Bonne pratique sklearn ; pas indispensable pour RF mais utile si on teste un autre modèle plus tard |
| **`StratifiedKFold` pour CV** | Garantit que chaque fold a toutes les 7 classes (sinon CV impossible) |
| **Pipeline modulaire** (3 scripts + io_utils) | Reproductibilité + lisibilité + évite la duplication |
| **Random_state=42** partout | Reproductibilité bit-à-bit |

Détail complet : voir [`EXPLICATION_MODELS.md`](EXPLICATION_MODELS.md).

---

## 📈 Données (vérifié sur le CSV)

| Indicateur | Valeur |
|---|---|
| Lignes totales | 2 520 751 |
| Colonnes | 53 (52 features + 1 label) |
| Mémoire | ~1.2 GB |
| Valeurs manquantes | 0 |
| Valeurs infinies | 0 |
| Features constantes | 0 |

### Distribution des classes

| Classe | Lignes | % | Ratio vs Normal |
|---|---|---|---|
| Normal Traffic | 2 095 057 | 83.11% | 1:1 |
| DoS | 193 745 | 7.69% | 11:1 |
| DDoS | 128 014 | 5.08% | 16:1 |
| Port Scanning | 90 694 | 3.60% | 23:1 |
| Brute Force | 9 150 | 0.36% | 229:1 |
| Web Attacks | 2 143 | 0.085% | 977:1 |
| Bots | 1 948 | 0.077% | **1 075:1** |

➡️ Détail dans [`EXPLICATION_DATA.md`](EXPLICATION_DATA.md).

---

## ⚠️ Limites assumées

- **Bots precision = 71%** (234 Normal → Bots) — recall 99.5% mais bruit en alerte, à documenter en soutenance
- **Dataset 2017** — ne couvre pas les attaques modernes (encrypted C2, DGA récents)
- **6 familles seulement** — pas de zéro-day par construction (apprentissage supervisé)
- **16% du dataset utilisé** (404k sur 2.5M) — choix délibéré pour la vitesse ; performance probablement similaire sur full

---

## 📅 Chronologie

| Date | Événement |
|---|---|
| 2026-05-19 | **Phase 0** : analyse CSV + 4 fichiers de doc rédigés |
| 2026-05-19 | **Phase 1** : `01_eda.ipynb` exécuté → 5 figures + JSON sommaire |
| 2026-05-19 | **Phase 2** : `02_modeling.ipynb` exécuté → F1 macro 0.9720 |
| 2026-05-19 | **Phase 3** : pipeline `preprocess.py`/`train.py`/`evaluate.py` exécutés → parité bit-à-bit |
| 2026-05-19 | **Doc finale** : `EXPLICATION_MODELS.md` rédigé (A→Z + analyse + avis) |

Détail dans [`AVANCEMENT.md`](AVANCEMENT.md).
