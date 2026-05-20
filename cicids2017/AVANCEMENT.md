# AVANCEMENT — Modèle CIC-IDS-2017

Journal de bord complet. Toutes les phases du [PLAN.md](PLAN.md) sont terminées.

---

## Vue d'ensemble

| Phase | Statut | Date | Livrables |
|---|---|---|---|
| **Phase 0 — Documentation initiale** | ✅ Terminée | 2026-05-19 | `EXPLICATION_DATA.md`, `PLAN.md`, `AVANCEMENT.md` |
| **Phase 1 — Exploration (EDA)** | ✅ Terminée | 2026-05-19 | `01_eda.ipynb` + 4 figures + `eda_summary.json` |
| **Phase 2 — Prototype modeling** | ✅ Terminée | 2026-05-19 | `02_modeling.ipynb` + métriques + 3 figures |
| **Phase 3 — Production scripts** | ✅ Terminée | 2026-05-19 | `pipeline/` (4 fichiers) + `saved_models/v1_final/` + `results/final/` |
| **Documentation finale** | ✅ Terminée | 2026-05-19 | `EXPLICATION_MODELS.md` |
| **🔍 Audit critique + correction** | ✅ Terminée | 2026-05-19 | `AUDIT_RAPPORT.md` + pipeline corrigé + métriques honnêtes |

**Légende :** 🟡 En cours · ✅ Terminé · ⏳ À faire · ❌ Bloqué

---

## ✅ Phase 0 — Documentation initiale

**Statut :** Terminée
**Date :** 2026-05-19

### A. Travail effectué
1. Lecture des README existants (génériques, peu informatifs)
2. Analyse Python complète du CSV `cicids2017.csv` (2.5M lignes)
3. Tests isolés de leakage sur `Destination Port` et `Flow Duration`
4. Rédaction de la documentation initiale (3 fichiers MD)

### B. Résultats clés de l'analyse
- **2 520 751 lignes**, 53 colonnes, 0 NaN, 0 Inf, 0 features constantes
- **Déséquilibre extrême 1 075:1** (Normal vs Bots)
- **Shortcut Destination Port confirmé** par test isolé :
  - Destination Port SEUL : 71.6% accuracy
  - 5 features comportementales SANS port : 97.9% accuracy
- **Anomalie identifiée** : 78 valeurs négatives dans `Flow Bytes/s`

### C. Décisions méthodologiques validées
| # | Décision | Justification |
|---|---|---|
| 1 | Supprimer `Destination Port` | Shortcut prouvé |
| 2 | Clipper `Flow Bytes/s` < 0 à 0 | Artefact CICFlowMeter |
| 3 | Split stratifié (pas groupé) | Flux indépendants |
| 4 | StandardScaler sur train uniquement | Standard sklearn |
| 5 | `class_weight='balanced'` (pas SMOTE) | Plus simple, suffisant |
| 6 | Métriques macro | Poids égal aux 7 classes |
| 7 | Random Forest baseline | Approche progressive |

---

## ✅ Phase 1 — Exploration (EDA)

**Statut :** Terminée
**Date :** 2026-05-19
**Notebook :** `notebooks/01_eda.ipynb`

### A. Travail effectué

Notebook EDA en 8 sections :
1. Setup
2. Chargement (2.5M lignes)
3. Distribution des classes (bar log-scale + pie)
4. Anomalies & nettoyage (NaN, Inf, négatifs)
5. Stats par classe (Flow Duration, Total Fwd Packets, etc.)
6. **Test du shortcut Destination Port** (heatmap port↔classe + RF isolé)
7. Corrélations entre features (heatmap)
8. Sauvegarde du résumé EDA en JSON

### B. Résultats clés

#### Distribution
- Normal Traffic : 2 095 057 (83.11%)
- DoS, DDoS, Port Scanning : ~412 453 (16.4% cumul)
- Brute Force, Web Attacks, Bots : 13 241 (0.5% cumul)

#### Anomalies
| Anomalie | Compte | Action |
|---|---|---|
| NaN | 0 | rien |
| Inf | 0 | (sécurité quand même) |
| `Flow Bytes/s` < 0 | 78 | clip à 0 |
| Features constantes | 0 | rien |

#### Shortcut Destination Port (preuve visuelle)
| Classe | Ports distincts | Lecture |
|---|---|---|
| Web Attacks | 1 (port 80) | 100% leakage |
| DoS | 1 (port 80) | 100% leakage |
| DDoS | 4 (essentiellement 80) | quasi 100% leakage |
| Brute Force | 3 (21, 22, 80) | fort leakage |
| Bots | 702 | dispersé OK |
| Port Scanning | 1 000 | dispersé OK |
| Normal Traffic | 53 788 | dispersé OK |

#### Multi-colinéarité
15 paires de features avec |corr| > 0.95 (ex : `Average Packet Size` ↔ `Packet Length Mean` = 0.999). RF gère naturellement → on garde tout.

### C. Artefacts produits
- 📄 `results/eda/eda_summary.json` — toutes les stats chiffrées
- 🖼️ `results/eda/class_distribution.png` — bar log + pie
- 🖼️ `results/eda/feature_distributions.png` — boxplots par classe
- 🖼️ `results/eda/port_vs_class_heatmap.png` — preuve visuelle leakage
- 🖼️ `results/eda/correlation_heatmap.png` — multi-colinéarité

### D. Décisions confirmées
1. ✅ Supprimer `Destination Port` (shortcut prouvé visuellement)
2. ✅ Clipper `Flow Bytes/s` < 0 à 0
3. ✅ Remplacer Inf éventuels par 0
4. ✅ Garder les 15 paires corrélées (RF gère)

---

## ✅ Phase 2 — Prototype modeling

**Statut :** Terminée
**Date :** 2026-05-19
**Notebook :** `notebooks/02_modeling.ipynb`

### A. Pipeline exécuté

| Étape | Méthode |
|---|---|
| 1. Chargement | `pd.read_csv` (2.5M lignes) |
| 2. Sampling | Cap 100k par classe → 403 935 lignes |
| 3. Nettoyage | Drop Destination Port + clip + replace Inf |
| 4. Split | 70/30 stratifié → train 282 754, test 121 181 |
| 5. Scaling | StandardScaler fit train, transform test |
| 6. CV | StratifiedKFold 5-fold sur train |
| 7. Fit | Random Forest balanced sur tout le train |
| 8. Eval | Une seule passe sur test |

### B. Hyperparamètres figés

```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=25,
    min_samples_leaf=5,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
)
```

### C. Résultats CV (sur train, 282 754 lignes)

```
F1 macro : mean=0.9704  std=0.0019
folds : [0.9707, 0.9692, 0.974, 0.9684, 0.9698]
```

→ Très stable, std=0.002.

### D. Résultats test (121 181 lignes — une seule passe)

| Métrique | Valeur |
|---|---|
| F1 macro | **0.9720** |
| F1 weighted | 0.9969 |
| Precision macro | 0.9556 |
| Recall macro | 0.9950 |
| AUC OVR macro | 0.9999 |
| Gap CV-Test F1 | 0.0015 |
| Max feature importance | 0.0773 |

### E. Métriques par classe

| Classe | n_test | TP | FN | FP | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| DDoS | 30 000 | 29 988 | 12 | 6 | 0.9998 | 0.9996 | 0.9997 |
| Port Scanning | 27 208 | 27 188 | 20 | 12 | 0.9996 | 0.9993 | 0.9994 |
| Brute Force | 2 745 | 2 740 | 5 | 2 | 0.9993 | 0.9982 | 0.9987 |
| DoS | 30 000 | 29 945 | 55 | 46 | 0.9985 | 0.9982 | 0.9983 |
| Normal Traffic | 30 000 | 29 714 | 286 | 79 | 0.9973 | 0.9905 | 0.9939 |
| Web Attacks | 643 | 633 | 10 | 12 | 0.9814 | 0.9844 | 0.9829 |
| **Bots** | 585 | 582 | 3 | **234** | **0.7132** | 0.9949 | **0.8308** |

**Lecture :**
- 6 classes sur 7 ont F1 ≥ 0.98 ✅
- Bots : recall 99.5% (on rate quasi rien) mais precision 71% (234 Normal classés Bots à tort)
- Compromis acceptable pour un IDS

### F. Checklist anti-overfitting/shortcut

**12/12 critères validés** :
1. ✅ Destination Port supprimé
2. ✅ Scaler fit train uniquement
3. ✅ Split stratifié 70/30
4. ✅ Test évalué une seule fois
5. ✅ CV 5-fold stratifiée
6. ✅ Gap CV-Test < 0.10 (0.0015)
7. ✅ Régularisation RF
8. ✅ Max importance < 0.20 (0.0773)
9. ✅ F1 min par classe ≥ 0.80 (0.8308)
10. ✅ Recall min par classe ≥ 0.80 (0.9844)
11. ✅ class_weight='balanced'
12. ✅ random_state=42

### G. Artefacts produits
- 📄 `results/modeling/metrics.json`
- 📄 `results/modeling/classification_report.txt`
- 📄 `results/modeling/per_class_metrics.csv`
- 📄 `results/modeling/feature_importance.csv` (51 features)
- 🖼️ `results/modeling/confusion_matrix.png` (compte + normalisée)
- 🖼️ `results/modeling/per_class_metrics.png`
- 🖼️ `results/modeling/feature_importance.png`
- 📦 `saved_models/rf_notebook.pkl` (référence)
- 📦 `saved_models/scaler_notebook.pkl`

---

## ✅ Phase 3 — Production scripts

**Statut :** Terminée
**Date :** 2026-05-19
**Localisation :** `pipeline/`

### A. Architecture

```
pipeline/
├── __init__.py
├── io_utils.py        ← Module partagé (constantes, chargement, nettoyage)
├── preprocess.py      ← Étape 1/3 : load + sample + clean + split + scaler
├── train.py           ← Étape 2/3 : CV + fit RF final
└── evaluate.py        ← Étape 3/3 : prédictions + métriques + figures
```

### B. Exécution séquentielle réussie

```bash
$ python pipeline/preprocess.py     # ~30 s
[stratified_sample] 2,520,751 -> 403,935
[clean_dataset] Colonnes supprimées : 1 (Destination Port)
[clean_dataset] Inf remplacés : 0
[clean_dataset] Valeurs négatives clippées : 5
[split] train=282,754 test=121,181

$ python pipeline/train.py          # ~5-7 min
[cv] F1 macro : mean=0.9704  std=0.0019
[fit] modèle final entraîné

$ python pipeline/evaluate.py       # ~15 s
F1 macro     : 0.9720
F1 weighted  : 0.9969
Precision M  : 0.9556
Recall    M  : 0.9950
AUC OVR macro: 1.0000
Gap CV-Test  : 0.0015
```

### C. Parité bit-à-bit avec notebook v2

| Métrique | Notebook 02 | Pipeline final | Δ |
|---|---|---|---|
| F1 macro | 0.9720 | 0.9720 | 0 ✅ |
| F1 weighted | 0.9969 | 0.9969 | 0 ✅ |
| AUC OVR | 0.9999 | 0.9999 | 0 ✅ |
| Gap CV-Test | 0.0015 | 0.0015 | 0 ✅ |
| Recall par classe | identiques | identiques | 0 ✅ |

→ Reproductibilité totale via `random_state=42`.

### D. Artefacts produits

```
data/processed/                   (créé par preprocess.py — gitignored)
├── X_train.npy / X_test.npy
├── y_train.npy / y_test.npy
├── scaler.pkl
├── feature_names.json
└── manifest.json

saved_models/v1_final/            (créé par train.py)
├── model.pkl
└── manifest.json

results/final/                    (créé par evaluate.py)
├── metrics.json
├── classification_report.txt
├── confusion_matrix.png
├── per_class_metrics.{csv,png}
└── feature_importance.{csv,png}
```

---

## ✅ Documentation finale

**Statut :** Terminée
**Date :** 2026-05-19

### Fichier : [`EXPLICATION_MODELS.md`](EXPLICATION_MODELS.md)

13 sections :
1. Le problème en une phrase
2. Vue d'ensemble du pipeline
3. Étape A — Échantillonnage stratifié
4. Étape B — Nettoyage (drop port, clip, Inf)
5. Étape C — Split train/test stratifié
6. Étape D — StandardScaler
7. Étape E — Random Forest balanced
8. Cross-validation : à quoi ça sert
9. Les métriques : définitions complètes
10. Résultats détaillés
11. Gestion du déséquilibre 1075:1
12. Anti-overfitting & anti-shortcut
13. Limites, déductions, mon avis

Inclut **mon avis honnête** et **3 phrases pour la soutenance**.

---

## 🔍 Audit critique (2026-05-19)

**Découverte :** un audit post-livraison a révélé un leakage train↔test de **23.5%** causé par les doublons générés par la suppression de `Destination Port` (Port Scanning passait de 90k à 1.9k lignes uniques sans le port).

**Correction appliquée :**
- Ajout de `df.drop_duplicates()` dans `clean_dataset` (io_utils.py)
- Inversion de l'ordre : clean **avant** sample (preprocess.py)

**Pipeline ré-exécuté** avec les corrections, métriques honnêtes désormais.

**Détail complet :** voir [`AUDIT_RAPPORT.md`](AUDIT_RAPPORT.md).

---

## 📊 Métriques finales — APRÈS AUDIT (officielles)

| Métrique | Cible PLAN | Avant audit (gonflé) | **APRÈS audit (réel)** | Statut |
|---|---|---|---|---|
| F1 macro (test) | ≥ 0.85 | 0.9720 | **0.9671** | ✅ +0.12 |
| F1 min par classe | ≥ 0.80 | 0.8308 | **0.8141** | ✅ |
| Recall min par classe | ≥ 0.80 | 0.9844 | **0.9796** | ✅ |
| AUC OVR macro | ≥ 0.95 | 0.9999 | **0.9998** | ✅ +0.05 |
| Gap CV-Test F1 macro | < 0.10 | 0.0015 | **0.0015** | ✅ |
| Max feature importance | < 0.20 | 0.0773 | ~0.08 | ✅ |
| `Destination Port` supprimé | OUI | OUI | **OUI** | ✅ |
| **Leakage train↔test** | < 1% | ❌ 23.5% | **✅ 0.004%** | ✅ |
| Pipeline reproductible | OUI | OUI | **OUI** | ✅ |

**Tous les critères de succès du PLAN sont validés — désormais avec des chiffres honnêtes.**

---

## 🎯 Travail global — terminé

| Livrable | Localisation | Lignes |
|---|---|---|
| Documentation données | `EXPLICATION_DATA.md` | ~500 |
| Documentation modèle | `EXPLICATION_MODELS.md` | ~700 |
| Plan de travail | `PLAN.md` | ~300 |
| Carte du projet | `README.md` | ~250 |
| Journal de bord | `AVANCEMENT.md` (ce fichier) | ~350 |
| Notebook EDA | `notebooks/01_eda.ipynb` | exécuté ✅ |
| Notebook Modeling | `notebooks/02_modeling.ipynb` | exécuté ✅ |
| Module partagé | `pipeline/io_utils.py` | ~120 |
| Script preprocess | `pipeline/preprocess.py` | ~80 |
| Script train | `pipeline/train.py` | ~80 |
| Script evaluate | `pipeline/evaluate.py` | ~140 |
| Modèle final | `saved_models/v1_final/model.pkl` | ✅ |
| Résultats finaux | `results/final/` | 7 fichiers |

---

*Dernière mise à jour : 2026-05-19 (fin du projet CIC-IDS-2017, toutes phases terminées)*
