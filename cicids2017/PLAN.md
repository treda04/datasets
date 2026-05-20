# PLAN — Modèle CIC-IDS-2017

**Objectif :** construire un classifieur **multi-classes** (7 classes) qui distingue le trafic réseau **normal** des **6 familles d'attaque** (DoS, DDoS, Port Scanning, Brute Force, Web Attacks, Bots), de manière **reproductible, sans shortcut learning, et bien évalué sur les classes minoritaires**.

**Pré-requis :** avoir lu [`EXPLICATION_DATA.md`](EXPLICATION_DATA.md).

**Méthodologie :** identique à ADFA-LD — découper en 3 phases, ne jamais toucher le test set avant la fin, vérifier l'absence de shortcut/leakage à chaque étape.

---

## 1. RÉSUMÉ DES DONNÉES (depuis EXPLICATION_DATA.md)

| Classe | Lignes | % |
|---|---|---|
| Normal Traffic | 2 095 057 | 83.11% |
| DoS | 193 745 | 7.69% |
| DDoS | 128 014 | 5.08% |
| Port Scanning | 90 694 | 3.60% |
| Brute Force | 9 150 | 0.36% |
| Web Attacks | 2 143 | 0.085% |
| Bots | 1 948 | 0.077% |
| **TOTAL** | **2 520 751** | **100%** |

**Format :** 53 colonnes (52 features numériques + 1 label `Attack Type`), pas de NaN, pas de Inf.

**Déséquilibre extrême :** 1 075:1 entre Normal et Bots → géré par `class_weight='balanced'` + métriques **macro** + recall par classe.

**Piège #1 (CRITIQUE) :** **shortcut learning sur `Destination Port`** — DoS, DDoS, Web Attacks utilisent quasi-exclusivement le port 80 ; Brute Force utilise ports 21/22 ; un modèle naïf apprend les ports au lieu du comportement. **Solution : supprimer la colonne `Destination Port` avant entraînement.**

**Piège #2 :** valeurs aberrantes — `Flow Bytes/s` a un min de -261 millions (artefact CICFlowMeter). Clip à zéro ou nettoyage.

---

## 2. PIPELINE EN 5 ÉTAPES

```
1. CHARGER         → pd.read_csv (2.5M lignes, ~1.2 GB en RAM)
2. NETTOYER        → supprimer Destination Port, clip valeurs aberrantes
3. SPLITTER        → train (70%) / test (30%), stratifié par Attack Type
4. (PAS DE VECTOR) → données déjà tabulaires, juste StandardScaler
5. ENTRAINER       → Random Forest / XGBoost calibré, CV stratifiée 5-fold
```

**Pas de notion de "scénario" comme ADFA** : chaque ligne CIC-IDS est un flux **indépendant** (5-tuple différent), donc un split aléatoire stratifié suffit.

**Pas de SMOTE par défaut** : on commence avec `class_weight='balanced'` (plus simple, suffisant en général). Si Bots/Web Attacks restent sous 0.70 de recall, on essaiera SMOTE (mais uniquement sur train, jamais sur test).

---

## 3. DÉTAIL DES ÉTAPES

### Étape 1 — CHARGER

```python
df = pd.read_csv('cicids2017/data/cicids2017.csv')
# 2 520 751 lignes, 53 colonnes, 0 NaN, 0 Inf
```

➡️ Sortie : un DataFrame `df` avec 52 features numériques + colonne `Attack Type`.

**Note mémoire :** 1.2 GB en RAM. Pour les étapes coûteuses (CV, tuning), on peut **sample stratifier** à 300k-500k lignes pour aller vite, puis ré-entraîner sur tout le dataset à la fin.

### Étape 2 — NETTOYER

Règles à appliquer :

1. **Supprimer `Destination Port`** (anti shortcut learning, voir §5 EXPLICATION_DATA.md)
2. **Clip ou supprimer** les valeurs négatives dans `Flow Bytes/s` (min observé : -261M)
3. **Clip ou supprimer** les valeurs `Inf` éventuelles (vérifier après calculs)
4. **Pas de suppression de lignes** (dataset déjà propre côté NaN)

➡️ Documenter le nombre de modifications dans `results/cleaning_report.json`.

### Étape 3 — SPLITTER

**Règle :** split aléatoire **stratifié par classe** pour garantir que chaque classe est représentée dans train ET test à la même proportion.

```python
from sklearn.model_selection import train_test_split

X = df.drop(columns=['Attack Type', 'Destination Port'])
y = df['Attack Type']

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.3,
    random_state=42,
    stratify=y,        # CRUCIAL : maintient la proportion 7-classes dans train ET test
)
```

**Cibles approximatives :**
- Train : ~1 764 525 lignes (toutes classes représentées)
- Test : ~756 226 lignes (toutes classes représentées)

➡️ Vérifier que Bots et Web Attacks sont présents dans test (~600 et ~640 lignes respectivement à 30%).

### Étape 4 — STANDARDISATION (StandardScaler)

```python
from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)   # fit + transform sur train
X_test_scaled  = scaler.transform(X_test)        # JUSTE transform sur test
```

⚠️ **Fit sur train uniquement.** Le scaling sur le test utilise les paramètres du train.

**Pour Random Forest, la scaling n'est PAS nécessaire** (les arbres sont invariants à l'échelle). Mais on le fait quand même par hygiène, et au cas où on testerait un autre modèle (SVM, NN) plus tard.

### Étape 5 — ENTRAÎNER

#### Option A — Random Forest (baseline)

```python
from sklearn.ensemble import RandomForestClassifier

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=25,                    # un peu plus profond qu'ADFA car plus de classes
    min_samples_leaf=5,              # un peu plus large car beaucoup de données
    class_weight='balanced',         # gère le déséquilibre 1075:1
    random_state=42,
    n_jobs=-1,
)
```

#### Option B — XGBoost (si Option A insuffisante sur Bots/Web)

```python
from xgboost import XGBClassifier

xgb = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    objective='multi:softprob',
    num_class=7,
    random_state=42,
    n_jobs=-1,
    tree_method='hist',              # rapide sur gros dataset
)
```

#### Calibration (Option facultative)

Pour avoir des probabilités fiables (utile si on doit les exporter vers le SIEM) :
```python
from sklearn.calibration import CalibratedClassifierCV
model = CalibratedClassifierCV(rf, method='isotonic', cv=5)
```

#### Cross-validation 5-fold stratifiée

```python
from sklearn.model_selection import cross_val_score, StratifiedKFold

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_f1_macro = cross_val_score(rf, X_train_scaled, y_train, cv=skf, scoring='f1_macro', n_jobs=-1)
# → mean ± std doit être raisonnable
```

#### Évaluation FINALE sur test (une seule fois)

```python
y_pred = model.predict(X_test_scaled)
y_proba = model.predict_proba(X_test_scaled)
```

**Métriques à produire :**
- **F1 macro** (cible principale ≥ 0.85)
- F1 par classe (cible ≥ 0.80 par classe, même Bots/Web)
- Recall par classe
- Matrice de confusion 7×7
- AUC OVR (One-vs-Rest)
- Feature importance (top 30)

---

## 4. ANTI-OVERFITTING & ANTI-SHORTCUT — CHECKLIST

| # | Mesure | Comment vérifier |
|---|---|---|
| 1 | `Destination Port` SUPPRIMÉ avant entraînement | Code montre `X.drop(columns=['Destination Port'])` |
| 2 | Scaler fit sur train seulement | `fit_transform(X_train)` puis `transform(X_test)` |
| 3 | Split stratifié | `train_test_split(..., stratify=y)` |
| 4 | Test set vu une seule fois | Pas de boucle de tuning sur métriques de test |
| 5 | CV 5-fold stratifiée sur train | Calcul de mean ± std du F1 macro |
| 6 | Gap CV-test F1 macro < 0.10 | `abs(f1_macro_cv - f1_macro_test) < 0.10` |
| 7 | Régularisation RF | `max_depth=25`, `min_samples_leaf=5` |
| 8 | Pas de feature dominante | `max(feature_importance) < 0.20` |
| 9 | F1 par classe ≥ 0.80 (Bots et Web inclus) | `min(f1_per_class) ≥ 0.80` |
| 10 | Déséquilibre géré | `class_weight='balanced'` |
| 11 | Reproductibilité | `random_state=42` partout |
| 12 | **Test anti-shortcut** | Entraîner un modèle "Destination Port seul" → ses F1 doit chuter drastiquement par classe quand on regarde les attaques *autres* que Web/DoS/DDoS |

---

## 5. STRUCTURE DES FICHIERS

```
cicids2017/
├── README.md                       Vue d'ensemble + métriques finales (mis à jour à la fin)
├── PLAN.md                         ← CE FICHIER
├── EXPLICATION_DATA.md             Comprendre les données
├── EXPLICATION_MODELS.md           (à créer en fin Phase 2) — détail du modèle retenu
├── AVANCEMENT.md                   Journal de bord des phases
│
├── data/
│   ├── cicids2017.csv              Données brutes (ne pas toucher)
│   └── processed/                  ← Créé par preprocess.py
│       ├── X_train.npz
│       ├── X_test.npz
│       ├── y_train.csv
│       ├── y_test.csv
│       ├── scaler.pkl
│       └── manifest.json
│
├── notebooks/                      ← Exploration interactive
│   ├── 01_eda.ipynb                Phase 1 — EDA
│   └── 02_modeling.ipynb           Phase 2 — Modèle complet
│
├── pipeline/                       ← Scripts production (Phase 3)
│   ├── io_utils.py                 utilitaires partagés
│   ├── preprocess.py               Étape 1-4 (charge, nettoie, split, scaler)
│   ├── train.py                    Étape 5 (training + calibration)
│   └── evaluate.py                 Métriques + figures finales
│
├── saved_models/
│   └── v1_final/                   ← Créé par train.py
│       ├── model.pkl
│       ├── scaler.pkl
│       └── manifest.json
│
└── results/
    ├── eda/                        ← Sortie notebook 01
    ├── modeling/                   ← Sortie notebook 02
    └── final/                      ← Sortie pipeline production
        ├── metrics.json
        ├── classification_report.txt
        ├── confusion_matrix.png    7×7
        ├── roc_curves.png          7 courbes OVR
        ├── feature_importance.png + .csv
        └── per_class_metrics.csv   F1, Precision, Recall par classe
```

---

## 6. ORDRE DE TRAVAIL

### Phase 1 — Exploration (1 séance)
1. Créer `notebooks/01_eda.ipynb`
2. Charger les 2.5M lignes, calculer stats réelles
3. Visualiser distributions par classe (histogrammes, boxplots)
4. **Confirmer le shortcut learning sur Destination Port** par un test isolé
5. Détecter autres anomalies (corrélations fortes entre features, valeurs aberrantes)
6. Décider règles de nettoyage finales

### Phase 2 — Prototype modeling (1-2 séances)
7. Créer `notebooks/02_modeling.ipynb`
8. Pipeline complet en interactif
9. Test sans `Destination Port` → mesurer le gap avec le baseline "avec port"
10. CV 5-fold stratifiée, vérifier les métriques par classe
11. Si F1 par classe trop bas → essayer XGBoost ou SMOTE (uniquement sur train)
12. Valider la checklist anti-overfitting

### Phase 3 — Production (1 séance)
13. Extraire le code en 3 scripts : `pipeline/preprocess.py`, `pipeline/train.py`, `pipeline/evaluate.py`
14. Lancer en séquence :
    ```bash
    python cicids2017/pipeline/preprocess.py
    python cicids2017/pipeline/train.py
    python cicids2017/pipeline/evaluate.py
    ```
15. Vérifier que les sorties `saved_models/` et `results/final/` sont complètes
16. Mettre à jour `README.md` avec les métriques finales + instructions
17. Créer `EXPLICATION_MODELS.md` (équivalent ADFA pour les modèles)

---

## 7. CRITÈRES DE SUCCÈS

✅ F1 macro ≥ 0.85 sur test set
✅ F1 par classe ≥ 0.80 (toutes les classes, Bots et Web inclus)
✅ AUC OVR moyen ≥ 0.95
✅ Gap CV-test F1 macro < 0.10
✅ Aucune feature avec importance > 0.20
✅ `Destination Port` non utilisé comme feature
✅ Pipeline reproductible (3 scripts qui tournent sans erreur)
✅ README.md à jour avec métriques

---

## 8. PHILOSOPHIE (identique ADFA)

1. **Données comprises avant tout code** → fait dans EXPLICATION_DATA.md
2. **Une seule version de chaque chose** — pas de v1/v2/v3 sauf si réelle amélioration documentée
3. **Notebook pour explorer, script pour reproduire**
4. **Test set sacré** — vu une seule fois à la fin
5. **Simple > complexe** — Random Forest avant XGBoost, XGBoost avant Deep Learning
6. **Reproductibilité** — `random_state=42` partout, `manifest.json` documente chaque artefact
7. **Honnêteté méthodologique** — si shortcut learning ou leakage détecté, on le **documente et le corrige**, on ne le cache pas

---

## 9. PROCHAINE ÉTAPE

**Créer `notebooks/01_eda.ipynb`** pour explorer les données et valider les choix de nettoyage avant de passer au modeling.
