# PLAN — Modèle ADFA-LD

**Objectif:** Construire un classifieur binaire **simple, fiable et reproductible** qui distingue les traces de syscalls **normales** des traces d'**attaques** sur Linux.

**Pré-requis:** Avoir lu [`EXPLICATION_DATA.md`](EXPLICATION_DATA.md) pour comprendre le format des données.

---

## 1. RÉSUMÉ DES DONNÉES (depuis EXPLICATION_DATA.md)

| Classe | Fichiers | Source |
|---|---|---|
| **Normal (label=0)** | 5 205 | `Training_Data_Master/` (833) + `Validation_Data_Master/` (4 372) |
| **Attaque (label=1)** | 746 | `Attack_Data_Master/` — 60 scénarios, 6 familles |
| **TOTAL** | **5 951** | (vérifié dans la Phase 1) |

**Format:** chaque fichier = séquence d'IDs de syscalls i386 séparés par espaces.

**Signal clé identifié:** `poll(168)` et `clock_gettime(265)` dominent les attaques ; `read/write/open/close` dominent les programmes normaux.

**Risque #1 à anticiper:** **leakage par scénario** — un même scénario d'attaque (ex: `Adduser_1`) contient plusieurs fichiers (un par PID). Si deux fichiers du même scénario se retrouvent un en train et un en test, le modèle "apprend par cœur" → métriques gonflées.

**Ratio:** ~7:1 normal/attaque → géré par `class_weight='balanced'`.

---

## 2. PIPELINE EN 5 ÉTAPES

```
1. CHARGER      → Lire tous les fichiers, attribuer label + scénario
2. NETTOYER     → Filtrer fichiers vides / trop courts / malformés
3. SPLITTER     → Train (70%) / Test (30%), stratifié + GROUPÉ par scénario
4. VECTORISER   → CountVectorizer trigrammes (max_features=500, min_df=2)
5. ENTRAINER    → Random Forest calibré, CV 5-fold, évaluation sur test
```

**Une seule passe.** Pas de val set séparé (la CV 5-fold sur train suffit pour tuner et détecter l'overfitting). Plus simple, plus de données pour le modèle.

---

## 3. DÉTAIL DES ÉTAPES

### Étape 1 — CHARGER

```python
# Pseudo-code de l'idée
for fichier in Training_Data_Master/*.txt + Validation_Data_Master/*.txt:
    sample = (contenu, label=0, scenario="normal")

for dossier in Attack_Data_Master/* :          # ex: Adduser_1, Hydra_FTP_3...
    for fichier in dossier/*.txt:
        sample = (contenu, label=1, scenario=nom_du_dossier)
```

➡️ Sortie: un DataFrame `df` avec colonnes `sequence` (str), `label` (0/1), `scenario` (str).

### Étape 2 — NETTOYER

Règles à appliquer:
1. Supprimer les fichiers vides (0 syscall)
2. Supprimer les séquences `< 10` syscalls (pas assez pour générer des trigrammes utiles)
3. Vérifier que tous les tokens sont des entiers (sinon rejeter)

➡️ Documenter le nombre de fichiers rejetés dans `results/cleaning_report.json`.

### Étape 3 — SPLITTER (le point CRITIQUE)

**Règle absolue:** un scénario entier reste dans le même split.

```python
from sklearn.model_selection import GroupShuffleSplit

splitter = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
train_idx, test_idx = next(splitter.split(X, y, groups=df['scenario']))
```

**Pourquoi `groups=scenario` ?**
- Les 5 205 fichiers normaux ont tous `scenario="normal"` → ils sont **tous ensemble** dans train ou test ? **NON** → ce serait absurde.
- ✅ Solution : on traite chaque fichier normal comme **son propre groupe** (`scenario="normal_UTD-0001"`, etc.). Comme ça :
  - Les normaux sont splittés aléatoirement (chaque fichier = son groupe → split standard)
  - Les attaques restent groupées par scénario (`Adduser_1` → tous ensemble)

```python
# Approche correcte
df['group'] = df.apply(
    lambda r: r['scenario'] if r['label']==1 else f"normal_{r['filename']}",
    axis=1
)
splitter = GroupShuffleSplit(test_size=0.3, random_state=42)
train_idx, test_idx = next(splitter.split(df, df['label'], groups=df['group']))
```

➡️ Cibles approximatives:
- Train: ~4 250 fichiers (~70% normal + 42 scénarios d'attaque)
- Test: ~1 825 fichiers (~30% normal + 18 scénarios d'attaque)

### Étape 4 — VECTORISER

```python
from sklearn.feature_extraction.text import CountVectorizer

vectorizer = CountVectorizer(
    analyzer='word',
    ngram_range=(3, 3),       # trigrammes
    max_features=500,         # 500 trigrammes les plus fréquents
    min_df=2                  # doit apparaître dans au moins 2 fichiers
)

X_train_vec = vectorizer.fit_transform(X_train)   # fit + transform sur train
X_test_vec  = vectorizer.transform(X_test)        # JUSTE transform sur test
```

⚠️ **Fit sur train uniquement.** Jamais sur test.

### Étape 5 — ENTRAINER

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import cross_val_score

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=2,
    class_weight='balanced',   # gère le déséquilibre 6:1
    random_state=42,
    n_jobs=-1
)

# Cross-validation sur train pour détecter l'overfitting
cv_scores = cross_val_score(rf, X_train_vec, y_train, cv=5, scoring='f1')
# → on doit avoir mean ± std raisonnables

# Calibration des probabilités
model = CalibratedClassifierCV(rf, method='isotonic', cv=5)
model.fit(X_train_vec, y_train)

# Évaluation FINALE sur test (une seule fois)
y_pred = model.predict(X_test_vec)
y_proba = model.predict_proba(X_test_vec)[:, 1]
```

**Métriques à produire:**
- F1, AUC-ROC, precision, recall (sur test)
- Matrice de confusion
- Performance **par famille d'attaque** (Adduser, Hydra_FTP, etc.)
- Feature importance (top 30 trigrammes)

---

## 4. ANTI-OVERFITTING — CHECKLIST

| # | Mesure | Comment vérifier |
|---|---|---|
| 1 | Vectorizer fit sur train seulement | Le code montre `fit_transform(X_train)` puis `transform(X_test)` |
| 2 | Split GROUPÉ par scénario | `GroupShuffleSplit` avec `groups=df['group']` |
| 3 | Test set vu une seule fois | Pas de boucle de tuning sur les métriques de test |
| 4 | CV 5-fold sur train | Calcul de `mean ± std` du F1 |
| 5 | Gap CV-test < 0.10 | `abs(f1_cv_mean - f1_test) < 0.10` |
| 6 | Régularisation RF | `max_depth=20`, `min_samples_leaf=2` |
| 7 | Pas de feature dominante | `max(feature_importance) < 0.20` |
| 8 | Performance équilibrée par famille | F1 par famille d'attaque ≥ 0.80 |
| 9 | Déséquilibre géré | `class_weight='balanced'` |
| 10 | Reproductibilité | `random_state=42` partout |

---

## 5. STRUCTURE DES FICHIERS

```
adfa_ld/
├── README.md                       Vue d'ensemble (à mettre à jour à la fin)
├── PLAN.md                         ← CE FICHIER
├── EXPLICATION_DATA.md             Comprendre les données
│
├── data/
│   ├── ADFA-LD/                    Données brutes (ne pas toucher)
│   ├── ADFA-LD+Syscall+List.txt
│   └── processed/                  ← Créé par preprocess.py
│       ├── X_train.npz             matrice sparse (CountVectorizer output)
│       ├── X_test.npz
│       ├── y_train.csv             labels + scénarios
│       ├── y_test.csv
│       └── manifest.json           seed, tailles, nb features
│
├── notebooks/                      ← Exploration interactive
│   ├── 01_eda.ipynb                Exploration des données, viz, stats
│   └── 02_modeling.ipynb           Prototype : preprocess + train + eval
│
├── pipeline/                       ← Scripts de production (reproductibles)
│   ├── preprocess.py               Étapes 1-4 (charge, nettoie, split, vectorise)
│   ├── train.py                    Étape 5 (training RF + calibration)
│   └── evaluate.py                 Métriques + figures finales
│
├── saved_models/                   ← Créé par train.py
│   ├── rf_adfa.pkl                 modèle calibré
│   ├── vectorizer.pkl              CountVectorizer fitted
│   └── manifest.json               version, hyperparams, date
│
└── results/                        ← Créé par evaluate.py
    ├── metrics.json                F1, AUC, precision, recall
    ├── classification_report.txt
    ├── confusion_matrix.png
    ├── roc_curve.png
    ├── pr_curve.png
    ├── feature_importance.png + .csv
    └── per_attack_family.csv + .png
```

---

## 6. ORDRE DE TRAVAIL

### Phase 1 — Exploration (1 séance)
1. Créer `notebooks/01_eda.ipynb`
2. Charger tous les fichiers, calculer stats réelles
3. Visualiser distributions (longueurs, top syscalls, équilibre)
4. Détecter anomalies (fichiers vides, malformés)
5. Décider règles de nettoyage finales

### Phase 2 — Prototype modeling (1 séance)
6. Créer `notebooks/02_modeling.ipynb`
7. Implémenter le pipeline complet en interactif
8. Tester le split groupé (vérifier qu'aucun scénario chevauche)
9. Lancer CV 5-fold, vérifier les métriques
10. Valider la checklist anti-overfitting

### Phase 3 — Production (1 séance)
11. Extraire le code en 3 scripts : `pipeline/preprocess.py`, `pipeline/train.py`, `pipeline/evaluate.py`
12. Lancer en séquence :
    ```bash
    python adfa_ld/pipeline/preprocess.py
    python adfa_ld/pipeline/train.py
    python adfa_ld/pipeline/evaluate.py
    ```
13. Vérifier que les sorties `saved_models/` et `results/` sont complètes
14. Mettre à jour `README.md` avec les métriques finales + instructions

---

## 7. CRITÈRES DE SUCCÈS

✅ F1 ≥ 0.95 sur test set
✅ AUC ≥ 0.97
✅ Recall ≥ 0.90 (on préfère détecter plus d'attaques)
✅ Gap CV-test < 0.10
✅ Aucune feature avec importance > 0.20
✅ Aucune famille d'attaque avec F1 < 0.80
✅ Pipeline reproductible (3 scripts qui tournent sans erreur)
✅ README.md à jour

---

## 8. PHILOSOPHIE

1. **Données comprises avant tout code** → on a déjà fait ça avec EXPLICATION_DATA.md
2. **Une seule version de chaque chose** — pas de v1/v2/v3
3. **Notebook pour explorer, script pour reproduire**
4. **Test set sacré** — vu une seule fois à la fin
5. **Simple > complexe** — Random Forest suffit, pas besoin de stacking ou Deep Learning
6. **Reproductibilité** — `random_state=42` partout, `manifest.json` documente chaque artefact

---

## 9. PROCHAINE ÉTAPE

**Créer `notebooks/01_eda.ipynb`** pour explorer les données et valider les choix de nettoyage avant de passer au modeling.
