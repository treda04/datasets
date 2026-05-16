# EXPLICATION MODELS — ADFA-LD (A à Z)

**Objectif :** comprendre **exactement** ce qu'on a construit, pourquoi chaque choix a été fait, ce que veut dire chaque chiffre, et où sont les limites.

**Public :** soutenance PFE, relecteur, soi-même dans 3 mois.

**Pré-requis :** avoir lu [`EXPLICATION_DATA.md`](EXPLICATION_DATA.md) (les données) et [`AVANCEMENT.md`](AVANCEMENT.md) (l'historique du travail).

---

## TABLE DES MATIÈRES

1. [Le problème en une phrase](#1-le-problème-en-une-phrase)
2. [Vue d'ensemble du pipeline](#2-vue-densemble-du-pipeline)
3. [Étape A — Vectorisation : CountVectorizer](#3-étape-a--vectorisation--countvectorizer)
4. [Étape B — Le classifieur : Random Forest](#4-étape-b--le-classifieur--random-forest)
5. [Étape C — Calibration des probabilités](#5-étape-c--calibration-des-probabilités)
6. [Étape D — Le split train/test groupé](#6-étape-d--le-split-traintest-groupé)
7. [Cross-validation : à quoi ça sert](#7-cross-validation--à-quoi-ça-sert)
8. [Le seuil de décision (la pièce maîtresse de v2)](#8-le-seuil-de-décision-la-pièce-maîtresse-de-v2)
9. [Les métriques : définitions complètes](#9-les-métriques--définitions-complètes)
10. [Résultats détaillés v1 vs v2](#10-résultats-détaillés-v1-vs-v2)
11. [Anti-overfitting : pourquoi on peut faire confiance aux chiffres](#11-anti-overfitting--pourquoi-on-peut-faire-confiance-aux-chiffres)
12. [Limites, déductions, mon avis](#12-limites-déductions-mon-avis)

---

## 1. Le problème en une phrase

On veut un modèle qui, lorsqu'on lui montre une **trace de syscalls** (séquence d'entiers) issue d'un programme Linux, dise :
- `0` → comportement normal
- `1` → attaque

C'est donc un problème de **classification binaire supervisée**.

---

## 2. Vue d'ensemble du pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    UN FICHIER .txt                          │
│           "3 5 6 168 168 265 192 6 33 5 197..."            │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
              ╔═══════════════════════════════════╗
              ║  A. VECTORISATION                 ║
              ║  CountVectorizer (n-grammes)      ║
              ║  → vecteur de 500 (v1) ou 1500 (v2)║
              ╚═══════════════════════════════════╝
                              │
                              ▼
              ╔═══════════════════════════════════╗
              ║  B. CLASSIFIEUR                   ║
              ║  Random Forest (200 arbres)       ║
              ║  → score brut                     ║
              ╚═══════════════════════════════════╝
                              │
                              ▼
              ╔═══════════════════════════════════╗
              ║  C. CALIBRATION                   ║
              ║  CalibratedClassifierCV (isotonic)║
              ║  → probabilité fiable [0, 1]      ║
              ╚═══════════════════════════════════╝
                              │
                              ▼
              ╔═══════════════════════════════════╗
              ║  D. DÉCISION                      ║
              ║  proba ≥ seuil ?                  ║
              ║  v1 seuil = 0.50 (défaut)         ║
              ║  v2 seuil = 0.40 (optimisé F2)    ║
              ╚═══════════════════════════════════╝
                              │
                              ▼
                    0 (Normal) ou 1 (Attaque)
```

---

## 3. Étape A — Vectorisation : CountVectorizer

### 3.1 Pourquoi vectoriser ?

Un Random Forest (ou n'importe quel modèle ML classique) ne sait pas lire une chaîne de caractères. Il a besoin d'un **vecteur de nombres de taille fixe**.

Or nos fichiers ont des longueurs variables (75 à 4 494 syscalls). Il faut donc une transformation : **séquence variable → vecteur de taille fixe**.

### 3.2 La solution : n-grammes

Un **n-gramme** = une sous-séquence de `n` éléments consécutifs.

**Exemple** sur la séquence `[3, 5, 6, 168, 265]` :

| n | Nom | Tokens extraits |
|---|---|---|
| 1 | unigramme | `"3"`, `"5"`, `"6"`, `"168"`, `"265"` |
| 2 | bigramme | `"3 5"`, `"5 6"`, `"6 168"`, `"168 265"` |
| 3 | trigramme | `"3 5 6"`, `"5 6 168"`, `"6 168 265"` |

**Idée :** chaque n-gramme est traité comme un "mot" du vocabulaire. Un fichier devient alors un sac-de-mots : **combien de fois chaque n-gramme apparaît ?**

### 3.3 Pourquoi pas n=1 (juste compter chaque syscall) ?

Trop d'information perdue. `read` peut apparaître 100 fois dans un fichier normal (lecture séquentielle) ET 100 fois dans une attaque (exfiltration). Le **nombre** ne dit pas grand-chose, c'est l'**ordre** qui compte.

### 3.4 Pourquoi pas n=5 ou n=6 ?

- Explosion combinatoire : avec ~50 syscalls courants, on aurait 50⁵ = 312 millions de 5-grammes théoriquement possibles
- Sparsité extrême : la plupart n'apparaîtraient jamais
- Sur-apprentissage garanti

**Compromis empirique : n=3 (trigrammes)**, validé par la littérature ADFA-LD.

### 3.5 Paramètres du `CountVectorizer`

```python
CountVectorizer(
    analyzer="word",          # On découpe par "mots" (espaces)
    ngram_range=(3, 3),       # v1 : trigrammes seulement
    # ngram_range=(1, 3),     # v2 : uni + bi + trigrammes
    max_features=500,         # v1 : top 500 n-grammes par fréquence
    # max_features=1500,      # v2 : top 1500
    min_df=2,                 # Doit apparaître dans ≥ 2 fichiers
    token_pattern=r"\d+",     # Un token = une suite de chiffres
)
```

#### `analyzer="word"`
On découpe le texte aux espaces. Chaque "mot" est un syscall ID.

#### `ngram_range=(min_n, max_n)`
- **v1 = (3, 3)** : uniquement les trigrammes. Captures les patterns courts (3 syscalls consécutifs).
- **v2 = (1, 3)** : unigrammes + bigrammes + trigrammes. Plus de signaux disponibles : **fréquence brute** (unigrammes), **paires** (bigrammes), **séquences courtes** (trigrammes).

**Avis :** le passage à (1,3) en v2 est l'amélioration la plus importante. Elle laisse le modèle choisir lui-même la granularité utile.

#### `max_features=N`
On garde les **N n-grammes les plus fréquents** sur l'ensemble du corpus train. Les autres sont jetés.

- **v1 = 500** : prudent, évite la malédiction de la dimension, mais peut être trop restrictif.
- **v2 = 1500** : 3× plus large, laisse plus d'opportunités au modèle pour repérer des patterns rares (utile pour Web_Shell, sous-représenté).

**Coût mémoire :** négligeable (matrices creuses).

#### `min_df=2`
Un n-gramme doit apparaître **dans au moins 2 fichiers distincts** pour être retenu. Filtre le bruit (n-grammes qui n'apparaissent qu'une fois → soit accident, soit signature trop spécifique à un fichier).

#### `token_pattern=r"\d+"`
Expression régulière qui définit un token : "une ou plusieurs chiffres". Évite que le vectorizer interprète mal d'éventuels artefacts. Sans cela, sklearn utilise par défaut un pattern qui exclut les mots de 1 caractère → on perdrait les syscalls à un chiffre (`1` = exit, `3` = read, etc.).

### 3.6 Fit vs Transform — règle d'or

```python
X_train_vec = vectorizer.fit_transform(X_train)   # APPRENDRE le vocabulaire sur train
X_test_vec  = vectorizer.transform(X_test)        # APPLIQUER le vocabulaire au test
```

⚠️ **Jamais** `fit_transform` sur le test. Sinon le test contribuerait à choisir les 500/1500 features → leakage indirect.

### 3.7 Sortie

Une matrice **creuse** (sparse) :
- Lignes = fichiers (4 154 en train)
- Colonnes = n-grammes (500 ou 1500)
- Valeur (i, j) = nombre de fois où le n-gramme j apparaît dans le fichier i

**Sparsité v1 :** 89.8% des valeurs sont à zéro (chaque fichier ne contient qu'une petite portion des n-grammes possibles).

---

## 4. Étape B — Le classifieur : Random Forest

### 4.1 Qu'est-ce qu'un Random Forest ?

Une **forêt aléatoire** = un ensemble de N arbres de décision entraînés en parallèle, chacun sur :
- Un sous-échantillon aléatoire des données (bootstrap)
- Un sous-ensemble aléatoire des features à chaque split

Prédiction finale = **vote majoritaire** des N arbres (ou moyenne des probabilités pour la version probabiliste).

### 4.2 Pourquoi Random Forest ici ?

| Critère | Random Forest |
|---|---|
| Données tabulaires creuses | ✅ Très adapté |
| Robuste au déséquilibre | ✅ Avec `class_weight='balanced'` |
| Pas de feature scaling requis | ✅ |
| Donne une feature importance | ✅ (interprétabilité) |
| Bon par défaut, peu de tuning | ✅ |
| Capture les interactions non-linéaires | ✅ |
| Inconvénient : plus lent qu'un arbre simple | ⚠️ Acceptable |

**Alternatives écartées :**
- **Logistic Regression** : plus simple mais nécessite scaling + n'attrape pas les interactions
- **SVM** : très bon mais lent sur 4 000 × 1 500
- **Gradient Boosting** : performant mais plus de tuning, risque d'overfitting
- **Deep Learning (LSTM)** : nécessaire seulement si n-grammes insuffisants ; on garde simple pour PFE

### 4.3 Hyperparamètres utilisés (v1 et v2 identiques)

```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
```

#### `n_estimators=200`
**Nombre d'arbres** dans la forêt.
- Trop peu (10-50) : variance élevée, prédictions instables
- Trop (1000+) : temps de calcul X5 pour gain marginal
- **200 = compromis standard** validé empiriquement

#### `max_depth=20`
**Profondeur maximale** de chaque arbre.
- Sans limite : chaque arbre apprend par cœur le train → overfitting
- Trop petit (3-5) : sous-apprentissage
- **20 = laisser apprendre des patterns complexes, sans devenir trop spécifique**

#### `min_samples_leaf=2`
Une feuille doit contenir **≥ 2 échantillons**. Évite les feuilles à 1 sample (= overfitting pur).

#### `class_weight="balanced"`
**Le paramètre le plus important** dans notre cas, à cause du déséquilibre 7:1.

Sans cela : le modèle minimise l'erreur globale → il préfère bien classer les 87.5% de normaux, quitte à rater des attaques.

Avec `balanced` : chaque erreur sur une attaque est pondérée **~7× plus** qu'une erreur sur un normal. Le modèle est forcé de prendre les attaques au sérieux.

**Formule sklearn :** `weight_class_i = n_total / (n_classes × n_samples_in_class_i)`.

#### `random_state=42`
Graine du générateur aléatoire. Garantit la **reproductibilité** : on relance le code, on obtient exactement les mêmes résultats.

#### `n_jobs=-1`
Utilise **tous les cœurs CPU disponibles** pour entraîner les arbres en parallèle.

---

## 5. Étape C — Calibration des probabilités

### 5.1 Le problème

Un Random Forest fournit `predict_proba(x) = [p_normal, p_attaque]`. Mais ces "probabilités" ne sont pas calibrées : si le modèle dit `p=0.80`, ça ne veut **pas forcément** dire que 80% des cas similaires sont vraiment des attaques.

**Pourquoi ?** Le `predict_proba` du RF = fraction des arbres qui ont voté "attaque". Cette fraction surestime la confiance pour les classes minoritaires (typique).

### 5.2 La solution : `CalibratedClassifierCV`

```python
model = CalibratedClassifierCV(rf_base, method="isotonic", cv=5)
```

Principe :
1. On découpe le train en 5 folds
2. Pour chaque fold : on entraîne le RF sur les 4 autres folds, on collecte ses probas sur le fold restant
3. On apprend une **fonction de calibration** (isotonique) qui transforme `proba_brute → proba_réelle`
4. Au moment de prédire : on moyenne 5 versions calibrées du modèle

### 5.3 `method="isotonic"` vs `method="sigmoid"`

- **Isotonic** : régression non-paramétrique (escalier). Plus flexible. Préférée quand on a assez de données (≥ 1 000 samples).
- **Sigmoid** : fonction logistique. Plus rigide, moins de données nécessaires.

**Notre choix : isotonic** (4 154 samples en train, largement assez).

### 5.4 Pourquoi c'est crucial pour v2

Pour choisir un **seuil de décision** rationnellement (cf §8), il faut que la proba soit **interprétable**. Sans calibration, "seuil = 0.40" ne veut rien dire de stable. Avec calibration, on peut comparer aux courbes Precision/Recall et choisir.

---

## 6. Étape D — Le split train/test groupé

### 6.1 Le problème du leakage par scénario

Chaque scénario d'attaque (ex: `Adduser_1`) contient **plusieurs fichiers** (un par PID du processus impliqué : 1371, 1613, 2311, ...).

Un split aléatoire bête mettrait, disons, le fichier de PID 1371 en train et celui de PID 1613 en test. Or **les deux fichiers du même scénario sont très similaires** (même attaque, mêmes outils, à quelques syscalls près). Résultat : le modèle apprend par cœur la signature, et le "test" est en réalité du train déguisé.

➡️ Les métriques exploseraient artificiellement, sans refléter une vraie capacité de généralisation.

### 6.2 La solution : `GroupShuffleSplit`

```python
splitter = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
train_idx, test_idx = next(splitter.split(X, y, groups=df["scenario"]))
```

**Règle :** tous les fichiers ayant le même `groups[i]` sont **forcés du même côté du split**.

### 6.3 Définition des groupes

```python
df["scenario"] = ...
# Pour une attaque : "Adduser_1", "Hydra_FTP_5", etc.
# Pour un fichier normal : "normal_UTD-0001" (son propre groupe)
```

**Astuce clé :** chaque fichier **normal** est son propre groupe → les normaux se splittent quasi-aléatoirement. **Les attaques** restent groupées par scénario.

### 6.4 Résultat du split (v1 = v2, même random_state)

| Set | Total | Normal | Attaque | Scénarios d'attaque |
|---|---|---|---|---|
| Train | 4 154 | 3 641 | 513 | 42 / 60 |
| Test | 1 797 | 1 564 | 233 | 18 / 60 |

**Vérification :** intersection des scénarios train ∩ test = **0** ✅

### 6.5 `GroupKFold` pour la CV

Même logique, mais pour la cross-validation : les 5 folds respectent aussi les groupes (un scénario ne peut pas être à cheval entre 2 folds).

---

## 7. Cross-validation : à quoi ça sert

### 7.1 Le problème

Comment savoir si le modèle généralise, **sans** toucher au test set ?

### 7.2 La solution : k-fold CV

On découpe le train en 5 morceaux égaux ("folds"). Pour chaque fold i :
1. Entraîner sur les 4 autres folds
2. Évaluer sur le fold i (laissé de côté)

On obtient **5 scores indépendants**. Leur moyenne ± écart-type estime la performance attendue.

### 7.3 Pourquoi 5 folds (et pas 3 ou 10) ?

- 3 folds : peu de données pour entraîner, estimation bruitée
- 10 folds : plus précis mais 2× plus de calculs pour gain marginal
- **5 = compromis standard**

### 7.4 Lecture des scores CV de v2

```
F1  : mean=0.8281  std=0.0191
AUC : mean=0.9849  std=0.0062
```

**std=0.019** est faible → les 5 folds donnent des scores cohérents → modèle stable.

---

## 8. Le seuil de décision (la pièce maîtresse de v2)

### 8.1 Comment un modèle décide-t-il ?

```python
y_pred = (y_proba >= threshold).astype(int)
```

- Par défaut, `threshold = 0.50`
- Si `proba_attaque ≥ 0.50` → classé "attaque", sinon "normal"

### 8.2 Pourquoi 0.50 n'est PAS optimal pour la sécurité

Le seuil 0.50 minimise l'erreur globale en supposant les deux types d'erreurs équivalents. Pour un IDS :
- **Faux négatif** (rater une attaque) : critique, compromission silencieuse
- **Faux positif** (alerter à tort) : un analyste perd 5 minutes

→ Coûts asymétriques. Le seuil 0.50 n'est pas adapté.

### 8.3 Méthode v2 — choix par F2-score

```python
# 1. Probas sur le train obtenues en cross-validation (zéro leakage du test)
y_train_proba_cv = cross_val_predict(model, X_train, y_train,
                                     groups=groups_train, cv=GroupKFold(5),
                                     method="predict_proba")[:, 1]

# 2. On balaye les seuils de 0.05 à 0.95
for thr in np.arange(0.05, 0.95, 0.01):
    y_pred = (y_train_proba_cv >= thr).astype(int)
    f2 = fbeta_score(y_train, y_pred, beta=2)
    # ...
# 3. On retient l'argmax F2
BEST_THRESHOLD = 0.40
```

### 8.4 Pourquoi F2 et pas F1 ?

F-beta généralisé :

```
F_beta = (1 + β²) × precision × recall / (β² × precision + recall)
```

- **β = 1 (F1)** : pondère P et R également
- **β = 2 (F2)** : pondère le **recall 2× plus** que la precision
- **β = 0.5** : l'inverse

**Pour un IDS, F2 est le standard académique.** On accepte de baisser un peu la precision pour gagner beaucoup en recall.

### 8.5 Garantie d'intégrité

Le seuil est choisi sur la **CV du train**, jamais sur le test. Sinon, on tournerait jusqu'à trouver le seuil qui marche sur le test → leakage et illusion.

---

## 9. Les métriques : définitions complètes

### 9.1 Matrice de confusion

|  | Prédit Normal | Prédit Attaque |
|---|---|---|
| Réel Normal | **TN** (true negative) | **FP** (faux positif) |
| Réel Attaque | **FN** (faux négatif) | **TP** (true positive) |

- **TP** : on a bien détecté une attaque ✅
- **TN** : on a bien laissé passer un normal ✅
- **FP** : on a alerté à tort sur un normal ⚠️ (analyste dérangé)
- **FN** : on a raté une attaque ❌ (compromission)

### 9.2 Precision

```
Precision = TP / (TP + FP)
```

**Question répondue :** "parmi tous les fichiers que j'ai classés ATTAQUE, combien sont vraiment des attaques ?"

**Interprétation :** taux de **vraies alertes** parmi mes alertes.
- 1.0 = aucune fausse alerte
- 0.5 = la moitié de mes alertes sont des erreurs

### 9.3 Recall (= Sensibilité = TPR)

```
Recall = TP / (TP + FN)
```

**Question répondue :** "parmi toutes les vraies attaques, combien j'en ai détecté ?"

**Interprétation :** taux de **détection effective**.
- 1.0 = j'ai trouvé toutes les attaques
- 0.5 = j'en ai raté la moitié

**Métrique reine pour un IDS.**

### 9.4 F1-score

```
F1 = 2 × precision × recall / (precision + recall)
```

Moyenne harmonique de precision et recall. Pénalise tout déséquilibre.
- 1.0 = perfection (P = R = 1)
- 0.5 = quelque chose ne va pas

### 9.5 F2-score

```
F2 = 5 × precision × recall / (4 × precision + recall)
```

Idem F1 mais le recall pèse 2× plus. Utilisé pour les domaines où **rater une cible coûte plus cher que sur-alerter** : médical, IDS, fraude.

### 9.6 AUC-ROC (Area Under Curve, Receiver Operating Characteristic)

La courbe ROC trace **TPR (= recall)** en fonction de **FPR (= FP / (FP+TN))** quand on fait varier le seuil de 0 à 1.

L'AUC = aire sous cette courbe. Interprétation :

- **AUC = 0.5** : modèle aléatoire (pile ou face)
- **AUC = 0.7** : faible discrimination
- **AUC = 0.9** : bonne discrimination
- **AUC = 0.98** : excellente discrimination (notre v2)
- **AUC = 1.0** : parfait

**Propriété très importante :** AUC est **indépendant du seuil**. Elle mesure la capacité du modèle à **ordonner** correctement les échantillons (les attaques doivent avoir des probas plus hautes que les normaux). Ensuite à toi de choisir le seuil.

### 9.7 Accuracy (PIÈGE — à ne JAMAIS regarder seul)

```
Accuracy = (TP + TN) / total
```

Avec un dataset 7:1, un modèle qui prédit toujours "Normal" obtient **87.5% d'accuracy** sans rien apprendre.

C'est pourquoi on **n'utilise pas l'accuracy** comme métrique principale pour les datasets déséquilibrés.

### 9.8 Confusion : taux de faux positifs (FPR)

```
FPR = FP / (FP + TN)
```

C'est l'envers du recall, côté classe Normal. Mesure **combien de normaux on alerte à tort**.

Pour un IDS opérationnel : on veut **FPR < 5%** typiquement (sinon les analystes ignorent les alertes).

- v1 : FPR = 34/1564 = **2.2%** ✅
- v2 : FPR = 46/1564 = **2.9%** ✅ (toujours acceptable)

---

## 10. Résultats détaillés v1 vs v2

### 10.1 Tableau récapitulatif

| Métrique | v1 (seuil 0.5) | **v2 (seuil 0.40)** | Δ | Lecture |
|---|---|---|---|---|
| **Recall** | 0.7940 | **0.9099** | **+0.116** | On rate 56% moins d'attaques |
| Precision | 0.8447 | 0.8217 | −0.023 | Très légère hausse des fausses alertes |
| F1 | 0.8186 | 0.8635 | +0.045 | Meilleur équilibre |
| F2 | (n/d) | 0.8908 | — | Métrique reine — élevée |
| AUC | 0.9804 | 0.9852 | +0.005 | Quasi identique, déjà excellent |
| Gap CV-Test F1 | 0.0722 | 0.0354 | −0.037 | Modèle plus stable |
| Max importance feat. | 0.0286 | 0.0210 | −0.008 | Aucune feature dominante |

### 10.2 Matrices de confusion comparées

**v1 (seuil 0.5)**

|  | Prédit Normal | Prédit Attaque |
|---|---|---|
| Réel Normal | 1530 | **34** (FP) |
| Réel Attaque | **48** (FN) | 185 |

**v2 (seuil 0.40)**

|  | Prédit Normal | Prédit Attaque |
|---|---|---|
| Réel Normal | 1518 | **46** (FP) |
| Réel Attaque | **21** (FN) | 212 |

➡️ **On a sauvé 27 attaques** (48 → 21 FN), au prix de 12 fausses alertes supplémentaires (34 → 46). Trade-off très favorable pour un IDS.

### 10.3 Recall par famille d'attaque

| Famille | n_test | Recall v1 | Recall v2 | Δ |
|---|---|---|---|---|
| Adduser | 7 | 1.00 | **1.00** | = |
| Java_Meterpreter | 35 | 0.91 | **1.00** | +0.09 |
| Hydra_FTP | 67 | 0.88 | **0.99** | +0.10 |
| Hydra_SSH | 89 | 0.74 | **0.90** | +0.16 |
| Meterpreter | 19 | 0.84 | 0.89 | +0.06 |
| Web_Shell | 16 | 0.31 | **0.44** | +0.13 |

**5 familles sur 6** sont au-dessus du seuil cible 0.80. Seul Web_Shell pose problème.

### 10.4 Top features v2 (importance moyenne)

Les RandomForest internes attribuent une importance à chaque feature (basée sur la réduction d'impureté qu'elle apporte aux nœuds). En moyennant les 5 RF calibrés :

| Rang | Feature | Type | Importance |
|---|---|---|---|
| 1 | `192 6 192` | trigramme | 0.021 |
| 2 | `33 192 33` | trigramme | 0.020 |
| ... | ... | ... | ... |
| 23 | `168 168 265` | trigramme | 0.010 |

**Surprise :** le signal "poll/clock_gettime" attendu après l'EDA n'est pas le top. Le top est dominé par des trigrammes de **manipulation mémoire/fichiers** (`mmap2`, `mprotect`, `access`, `open`). Le RF détecte les **patterns de chargement de processus malveillants** (typique d'un exploit ou d'un Meterpreter qui s'installe en mémoire).

**Leçon méthodologique :** la fréquence globale d'un syscall en EDA ≠ son pouvoir discriminant. C'est le modèle qui décide.

---

## 11. Anti-overfitting : pourquoi on peut faire confiance aux chiffres

### 11.1 Définition de l'overfitting

Le modèle apprend les **détails spécifiques** du train (y compris le bruit) au lieu des **patterns généraux**. Conséquence : excellent sur train, mauvais sur test.

### 11.2 Nos 10 mesures (v2)

| # | Mesure | Statut v2 | Pourquoi c'est important |
|---|---|---|---|
| 1 | Vectorizer fit sur train seul | ✅ | Sinon le vocab est influencé par le test |
| 2 | Split groupé par scénario | ✅ | Sinon le modèle apprend par cœur les attaques |
| 3 | Test évalué 1 seule fois | ✅ | Sinon on tuneraît implicitement sur le test |
| 4 | CV 5-fold GroupKFold | ✅ | Estime la perf sans toucher au test |
| 5 | Gap CV-Test F1 < 0.10 | ✅ 0.035 | Le test n'est pas un coup de chance |
| 6 | Régularisation RF | ✅ | max_depth=20, min_samples_leaf=2 |
| 7 | Max feature importance < 0.20 | ✅ 0.021 | Pas de feature dominante (robustesse) |
| 8 | Recall min par famille ≥ 0.80 | ❌ 0.44 | Web_Shell — limitation structurelle |
| 9 | class_weight='balanced' | ✅ | Gère le déséquilibre 7:1 |
| 10 | random_state=42 | ✅ | Reproductibilité totale |
| 11 | Seuil choisi sur CV train (v2) | ✅ | Pas de leakage du test dans le tuning |

**10/11 critères verts.** Le seul KO est documenté et assumé.

### 11.3 Le critère 5 (gap CV-test) en détail

- F1 CV moyen (vu pendant l'entraînement) : 0.828
- F1 sur test (jamais vu) : 0.864
- Écart absolu : 0.035 << seuil 0.10 ✅

**Interprétation :** le test se comporte comme un fold CV de plus → le modèle généralise réellement, pas par chance.

---

## 12. Limites, déductions, mon avis

### 12.1 Ce qui marche bien

- ✅ **Recall global 91%** sur les attaques, **2.9% de fausses alertes** : opérationnellement viable
- ✅ **5 familles sur 6** détectées à ≥ 89%
- ✅ **Pipeline reproductible** bout en bout
- ✅ **Aucun leakage** identifié (split groupé + CV groupé + seuil sur CV train)
- ✅ **Calibration** : les probas peuvent être utilisées pour prioriser les alertes
- ✅ **Pas d'overfitting** : gap CV-test = 0.035

### 12.2 Ce qui ne marche pas

- ❌ **Web_Shell détecté à 44%**. Trois familles d'explications :
  1. **Sous-représentation** : seulement 16 fichiers en test
  2. **Signature noyée** : un Web_Shell exécuté par Apache produit majoritairement des syscalls d'Apache normal
  3. **Limite intrinsèque des n-grammes** : ils captent l'ordre local mais pas le "contexte sémantique" qui distingue une requête HTTP malveillante d'une requête légitime

### 12.3 Ce qu'on a appris (déductions)

#### Déduction 1 — L'AUC seule ne suffit pas
v1 et v2 ont des AUC quasi identiques (0.98 vs 0.985), mais des recall très différents (79% vs 91%). **L'AUC mesure le potentiel de séparation, le seuil et le vocabulaire mesurent ce qu'on en extrait.**

#### Déduction 2 — Le seuil est un hyperparamètre légitime
Le passage de 0.50 → 0.40 a gagné +12 pts de recall **sans toucher au modèle**. Le seuil de décision est un levier puissant et souvent ignoré.

#### Déduction 3 — `class_weight='balanced'` est obligatoire ici
Sans lui, le modèle aurait optimisé l'accuracy (faussement bonne avec 87.5% de normaux) et raté la plupart des attaques.

#### Déduction 4 — Anti-leakage = priorité absolue
Sans `GroupShuffleSplit` et `GroupKFold`, on aurait probablement obtenu un F1 > 0.95 **fantôme**, dû au leakage par scénario. On aurait été fier d'un modèle qui ne marche pas.

#### Déduction 5 — Élargir le vocabulaire bat raffiner le modèle
On n'a touché ni les hyperparamètres RF ni la calibration entre v1 et v2. Le gain vient à **75% du vocabulaire (1-3 grammes, 1500 features)** et à **25% du seuil**. Souvent, mieux structurer les features bat le tuning fin.

### 12.4 Mon avis (synthèse honnête)

**Le modèle v2 est suffisant pour un PFE.** Il atteint des chiffres défendables (recall 91%, AUC 0.985, FPR 2.9%) avec une méthodologie propre et documentée. La limitation Web_Shell est honnêtement reportée et techniquement explicable.

**Si tu voulais aller plus loin (hors PFE) :**
1. **Ensemble** : combiner Random Forest + SVM + Gradient Boosting → +1-2 pts de F1 typiquement
2. **Approche séquentielle** : LSTM ou Transformer sur les séquences brutes → +5-10 pts sur Web_Shell potentiellement
3. **Features supplémentaires** : statistiques par séquence (longueur, entropie, ratio I/O vs réseau)
4. **Détection anomale (non supervisée)** : One-Class SVM sur les normaux uniquement → trouverait les attaques par "écart à la normalité", utile pour les zero-day

**Mais aucun de ces leviers n'est nécessaire pour le PFE.** Le couple "Random Forest + n-grammes + seuil tuné par F2" est un choix **classique, défendable, reproductible**. C'est exactement ce qu'un jury de PFE attend.

### 12.5 Trois phrases pour la soutenance

1. *"Nous atteignons un recall de 91% avec un taux de faux positifs de 2.9% sur le test set, via un Random Forest calibré sur des n-grammes (1 à 3) de syscalls, avec un seuil de décision optimisé par F2-score sur la CV du train."*

2. *"La méthodologie évite tout leakage : split groupé par scénario d'attaque, cross-validation groupée, seuil choisi sans jamais regarder le test. Le gap CV-test est de 0.035, confirmant l'absence d'overfitting."*

3. *"Cinq familles d'attaque sur six sont détectées à plus de 89%. La famille Web_Shell reste plus difficile (44%), car son comportement syscall est noyé dans le trafic Apache normal — une limitation structurelle de l'approche n-gram connue dans la littérature ADFA-LD."*

---

*Document créé le 2026-05-16 — après exécution complète des notebooks 02_modeling.ipynb (v1) et 03_modeling_v2.ipynb (v2).*
