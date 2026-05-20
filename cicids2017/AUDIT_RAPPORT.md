# AUDIT RAPPORT — CIC-IDS-2017

**Date :** 2026-05-19
**Auteur de l'audit :** revue critique post-livraison
**Statut :** ❗ Problème majeur détecté → corrigé → re-livrable

---

## TL;DR

À la fin de la Phase 3, le modèle affichait **F1 macro = 0.9720**. Un audit critique a révélé un **leakage massif train↔test** (23.5% des lignes test étaient identiques à des lignes train), causé par la suppression de `Destination Port` qui transformait beaucoup de lignes Port Scanning en doublons exacts.

**Après correction (déduplication avant split)** :
- Leakage résiduel : 0.004% (négligeable)
- F1 macro **réel** : **0.9671** (vs 0.9720 affiché — l'écart venait du leakage qui gonflait Port Scanning et Bots)

**Le modèle reste excellent, mais maintenant les chiffres sont honnêtes.**

---

## 1. POURQUOI cet audit ?

Après livraison de la Phase 3, j'ai voulu vérifier que le F1 macro de 0.97 était **réel** et non un artefact méthodologique. Sur CIC-IDS-2017, la littérature reporte fréquemment des F1 entre 0.95 et 0.99 — ce qui peut cacher des problèmes de leakage classiques sur ce dataset.

**Hypothèses à tester :**
1. Y a-t-il des duplicates internes (train ou test) ?
2. Le test set partage-t-il des lignes avec le train ?
3. La feature dominante (`Init_Win_bytes_backward`) cache-t-elle un shortcut ?
4. Les chiffres sont-ils cohérents entre CV et test ?

---

## 2. CE QUE J'AI FAIT (méthodologie d'audit)

### 2.1 Étape 1 — Recharger les artefacts produits

```python
X_train = np.load('data/processed/X_train.npy')   # (282 754, 51)
X_test  = np.load('data/processed/X_test.npy')    # (121 181, 51)
y_train = np.load('data/processed/y_train.npy')
y_test  = np.load('data/processed/y_test.npy')
```

Pas de re-entraînement — j'ai inspecté **directement** les données que le modèle a vues.

### 2.2 Étape 2 — Mesurer les doublons internes

```python
df_tr = pd.DataFrame(X_train)
df_te = pd.DataFrame(X_test)
n_train_dup = df_tr.duplicated().sum()  # 79 878  (28.25%)
n_test_dup  = df_te.duplicated().sum()  # 31 299  (25.83%)
```

→ **🚨 ÉNORME alerte** : 28% du train et 26% du test sont des doublons internes.

### 2.3 Étape 3 — Mesurer le leakage train↔test

Méthode : hasher chaque ligne (51 features), puis chercher les hashes du test dans le train.

```python
train_hashes = pd.util.hash_pandas_object(df_tr, index=False).values
test_hashes  = pd.util.hash_pandas_object(df_te, index=False).values
n_overlap = sum(1 for h in test_hashes if h in set(train_hashes))
# 28 502 (23.52% du test)
```

→ **🚨 23.5% du test set est BIT-À-BIT identique à des lignes du train.**

### 2.4 Étape 4 — Identifier la source des doublons

Hypothèse : les doublons viennent du nettoyage. J'ai testé en remontant chaque étape :

| État | Doublons total |
|---|---|
| CSV brut (avec Destination Port) | 161 (0.01%) |
| **Après drop Destination Port** | **289 859 (11.5%)** ❌ |
| Après split + scaling | 28% (vu plus haut) |

→ **Le coupable est la suppression de `Destination Port`.**

### 2.5 Étape 5 — Décortiquer par classe

| Classe | Lignes CSV brut | Uniques après drop port | % doublons |
|---|---|---|---|
| Normal Traffic | 2 095 057 | 1 894 447 | 9.6% |
| **Port Scanning** | **90 694** | **1 956** | **97.8%** ❌ |
| Bots | 1 948 | 1 437 | 26.2% |
| DoS | 193 745 | 193 745 | 0% |
| DDoS | 128 014 | 128 014 | 0% |
| Brute Force | 9 150 | 9 150 | 0% |
| Web Attacks | 2 143 | 2 143 | 0% |

**Découverte clé :** Port Scanning n'avait que **1 956 vrais patterns** réseau. Les 90 694 lignes du CSV étaient des copies de ces 1 956 patterns mais avec des **ports différents** (1 000 ports balayés).

➡️ Quand on supprime `Destination Port` pour anti-shortcut, on transforme **97.8% des Port Scanning en doublons exacts**. Le split aléatoire 70/30 répartit ces copies dans train ET test → leakage massif.

---

## 3. POURQUOI ce problème n'a pas été détecté avant ?

Plusieurs raisons :

1. **Sur le CSV brut, il n'y avait que 161 doublons (0.01%)** — invisible
2. La suppression de `Destination Port` était **justifiée** (anti-shortcut prouvé) — on ne s'attendait pas à un effet secondaire
3. Le `train_test_split` stratifié est honnête, mais il ne sait pas que les lignes sont déjà des doublons
4. Le F1 = 0.97 et le gap CV-Test = 0.0015 paraissaient cohérents → faux signal de confiance

**Leçon méthodologique :** toujours **dédupliquer après transformation** des features, pas avant.

---

## 4. CORRECTION APPLIQUÉE

### 4.1 Modification du code

#### `pipeline/io_utils.py` — fonction `clean_dataset`

**Avant :**
```python
def clean_dataset(df):
    df = df.drop(columns=['Destination Port'])
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], 0)
    df['Flow Bytes/s'] = df['Flow Bytes/s'].clip(lower=0)
    return df
```

**Après :**
```python
def clean_dataset(df):
    df = df.drop(columns=['Destination Port'])
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], 0)
    df['Flow Bytes/s'] = df['Flow Bytes/s'].clip(lower=0)
    df = df.drop_duplicates().reset_index(drop=True)  # ✅ NOUVEAU
    return df
```

#### `pipeline/preprocess.py` — ordre des étapes

**Avant :**
```python
df = load_dataset()
df = stratified_sample(df)   # sample AVANT clean
df = clean_dataset(df)
```

**Après :**
```python
df = load_dataset()
df = clean_dataset(df)        # clean (avec dédup) AVANT sample
df = stratified_sample(df)
```

**Pourquoi ce nouvel ordre ?** Si on échantillonne avant de dédupliquer, on garde les doublons dans le sample. La déduplication doit être faite sur le dataset complet, puis on sample.

### 4.2 Pourquoi `drop_duplicates` et pas autre chose ?

J'ai considéré 3 options :

| Option | Avantage | Inconvénient | Décision |
|---|---|---|---|
| **drop_duplicates** | Garantit unicité, simple, rapide | Réduit drastiquement Port Scanning (90k → 2k) | ✅ Retenu |
| Garder les doublons + utiliser GroupShuffleSplit | Préserve la quantité | Comment grouper ? Pas de clé naturelle | ❌ Trop complexe |
| Hashing approximatif (tolérer petites différences) | Garde plus de variabilité | Subjectif (seuil de tolérance arbitraire) | ❌ Pas rigoureux |

**`drop_duplicates` est la solution propre et standard.** On perd des lignes mais on gagne en honnêteté méthodologique.

### 4.3 Impact sur les données

| Étape | Lignes |
|---|---|
| CSV brut | 2 520 751 |
| Après drop port + dédup | **2 230 892** (−289 859 doublons) |
| Sample stratifié (cap 100k/cls) | 314 686 |
| Train (70%) | 220 280 |
| Test (30%) | 94 406 |

Pertes par classe après dédup :
- Port Scanning : 90 694 → **1 956** (−98%)
- Bots : 1 948 → **1 437** (−26%)
- Normal Traffic : 2 095 057 → 1 894 447 (−10%)
- Autres : aucune perte

→ **Port Scanning et Bots ont moins d'exemples uniques, mais ce qu'on a est désormais 100% honnête.**

---

## 5. RÉSULTATS APRÈS CORRECTION

### 5.1 Vérification post-correction

```
Train : (220 280, 51)
Test  : (94 406, 51)
Doublons internes train : 5  (0.00%)
Doublons internes test  : 0  (0.00%)
Leakage train→test      : 4  (0.004%)
```

→ Leakage résiduel **négligeable** (4 lignes sur 94 406). Audit réussi.

### 5.2 Métriques globales : avant vs après correction

| Métrique | Avant (faux) | **Après (réel)** | Δ |
|---|---|---|---|
| F1 macro | 0.9720 | **0.9671** | -0.0049 |
| F1 weighted | 0.9969 | 0.9962 | -0.0007 |
| Recall macro | 0.9950 | **0.9920** | -0.0030 |
| Precision macro | 0.9556 | 0.9498 | -0.0058 |
| AUC OVR | 0.9999 | 0.9998 | -0.0001 |
| Gap CV-Test | 0.0015 | 0.0015 | 0 |
| Max feature importance | 0.0773 | ~0.08 | similar |

**Lecture :** la baisse globale est **petite** (-0.5 pt sur F1 macro). Pourquoi ? Parce que les doublons étaient concentrés sur **Port Scanning et Bots**, qui pèsent peu en absolu vs Normal/DoS/DDoS.

### 5.3 Métriques par classe : avant vs après

| Classe | F1 avant | F1 après | Δ | Lecture |
|---|---|---|---|---|
| DDoS | 0.9997 | 0.9997 | 0 | inchangé (pas de doublons) |
| Brute Force | 0.9987 | 0.9978 | -0.001 | inchangé en pratique |
| DoS | 0.9983 | 0.9978 | -0.001 | inchangé |
| Normal Traffic | 0.9939 | 0.9941 | +0.0002 | légère hausse |
| Web Attacks | 0.9829 | 0.9815 | -0.001 | inchangé |
| **Port Scanning** | **0.9994** | **0.9846** | **-0.015** | **vraie performance** |
| **Bots** | 0.8308 | **0.8141** | **-0.017** | légère baisse |

**Conclusions :**
- Port Scanning F1 passe de 0.9994 (gonflé par leakage) à **0.9846** (honnête)
- Bots reste le point faible (F1 = 0.81, precision = 0.69)
- Les autres classes ne bougent pas → leur perf était déjà honnête

### 5.4 Confusion matrix corrigée (Bots toujours problématique)

|  | Bots | Normal | Autres |
|---|---|---|---|
| **Vrai Bots (431)** | 427 ✅ | 4 | 0 |
| Vrai Normal (30 000) | **190** ❌ | 29 731 | 79 |

→ 190 trafics Normal classés Bots à tort (vs 234 avant). Toujours le même problème inhérent, mais légèrement amélioré.

---

## 6. PLAN COMPLET — ce qui a été fait pour cet audit

| # | Étape | Détail |
|---|---|---|
| 1 | **Détecter** | Charger X_train/X_test, mesurer doublons internes via `df.duplicated()` |
| 2 | **Quantifier le leakage** | Hasher chaque ligne, compter combien de hashes test sont dans train |
| 3 | **Trouver la cause** | Tester chaque étape du pipeline pour voir quand les doublons apparaissent |
| 4 | **Isoler** | Identifier que `drop Destination Port` génère les doublons (Port Scanning passe de 90k à 2k uniques) |
| 5 | **Corriger** | Ajouter `df.drop_duplicates()` dans `clean_dataset` + inverser l'ordre clean/sample |
| 6 | **Vérifier** | Re-exécuter le pipeline complet, mesurer les nouveaux doublons (cible : 0%) |
| 7 | **Comparer** | Mesurer l'écart entre les anciennes et nouvelles métriques |
| 8 | **Documenter** | Ce fichier + mise à jour AVANCEMENT.md, README.md, EXPLICATION_MODELS.md |

---

## 7. POURQUOI ces choix méthodologiques

### 7.1 Pourquoi dédupliquer plutôt que garder les doublons ?

**Argument pro-déduplication (retenu) :**
- Un test set doit contenir des exemples **non vus** par le modèle. Si 23% des lignes test sont identiques à train, le modèle "généralise" trivialement.
- La performance reportée doit refléter ce qui se passerait sur **de vrais nouveaux flux** en production.

**Argument contre (rejeté) :**
- "Les doublons reflètent la réalité — Port Scanning lance vraiment le même paquet sur 1 000 ports". Vrai en théorie, mais sans la feature Port, ces 1 000 scans sont **indistinguables** pour le modèle, donc inutiles à modéliser.

### 7.2 Pourquoi ne pas réintroduire `Destination Port` ?

Tentant : si on garde `Destination Port`, on n'a plus de doublons (chaque ligne est unique grâce au port). Mais on retombe dans le **shortcut learning** :
- DoS = 100% port 80 → modèle apprend "port 80 = DoS" en production
- Brute Force = 100% port 21/22

→ **Non-négociable :** on supprime `Destination Port`, on accepte de perdre des lignes Port Scanning, on documente honnêtement.

### 7.3 Pourquoi dédupliquer après drop_port et pas avant ?

Si on déduplique le CSV brut (avant drop) : seulement 161 doublons retirés (0.01%). On garde 90k Port Scanning, mais ils contiennent toujours du shortcut signal via le port. Une fois la feature retirée, **le drop_duplicates devient nécessaire pour la cohérence**.

L'ordre correct est :
```
1. Drop port (anti-shortcut)
2. Clip + Inf (nettoyage technique)
3. Drop duplicates (anti-leakage)   ← l'audit a montré que c'est crucial
4. Sample stratifié
5. Split
6. Scale
```

### 7.4 Pourquoi ne pas utiliser GroupShuffleSplit comme ADFA-LD ?

Sur ADFA, les fichiers d'un même scénario étaient logiquement groupés (même PID → même attaque). Ici, après déduplication, **chaque ligne est unique** et indépendante. Pas de groupes naturels à préserver. `train_test_split(stratify=y)` suffit.

---

## 8. MÉTRIQUES FINALES OFFICIELLES (après audit)

| Métrique | Valeur | Cible | Statut |
|---|---|---|---|
| **F1 macro** | **0.9671** | ≥ 0.85 | ✅ +0.12 |
| F1 weighted | 0.9962 | — | — |
| **Recall macro** | **0.9920** | — | ✅ |
| Precision macro | 0.9498 | — | — |
| **AUC OVR macro** | **0.9998** | ≥ 0.95 | ✅ |
| Gap CV-Test F1 | 0.0015 | < 0.10 | ✅ |
| Min F1 par classe | 0.8141 (Bots) | ≥ 0.80 | ✅ |
| Min Recall par classe | 0.9796 (Port Scan) | ≥ 0.80 | ✅ |
| **Doublons internes train** | **0%** | — | ✅ |
| **Doublons internes test** | **0%** | — | ✅ |
| **Leakage train↔test** | **0.004%** | < 1% | ✅ |
| Destination Port supprimé | OUI | OUI | ✅ |

→ **Toutes les cibles validées, et cette fois avec des chiffres honnêtes.**

---

## 9. CE QUE J'AI APPRIS DE CET AUDIT

### 9.1 Leçons techniques

1. **Toujours dédupliquer après transformation des features**, pas avant. Une feature qui paraît anodine peut "rendre uniques" des milliers de lignes.

2. **Vérifier les doublons train↔test systématiquement.** C'est une vérification triviale (5 lignes de code) qui aurait évité de livrer des métriques gonflées.

3. **CIC-IDS-2017 a un piège supplémentaire** : le `Destination Port` n'est pas juste un shortcut, c'est aussi le **seul** discriminant entre les 90k lignes Port Scanning. Le retirer transforme la classe en données quasi-pures.

4. **Le gap CV-Test ne détecte pas le leakage par doublons.** Si train et test ont les mêmes doublons (parce que `train_test_split` aléatoire), la CV reproduit le même biais. **Il faut vérifier directement les hashes**.

### 9.2 Leçons méthodologiques

1. **F1 trop élevé = drapeau rouge.** F1=0.97 sur un dataset de cybersécurité multi-classes mérite suspicion. Audit obligatoire.

2. **L'audit doit être indépendant.** J'ai fait l'audit moi-même, ce qui est mieux que rien, mais idéalement un tiers (relecteur PFE, collègue) ferait cette vérification.

3. **Documenter le problème ET la correction** est plus crédible que de cacher l'erreur. Un jury préfère "j'ai trouvé un bug, voici comment j'ai corrigé" à "tout est parfait".

---

## 10. RECOMMANDATIONS POUR LA SOUTENANCE

**Comment présenter ces résultats en soutenance PFE :**

### Phrase d'accroche

*"Mon premier modèle obtenait F1 = 0.97. Un audit interne a révélé que 23% du test set était identique au train à cause de doublons générés par la suppression de `Destination Port`. Après correction, le modèle obtient F1 = 0.967 — légèrement plus bas mais maintenant honnête. La rigueur méthodologique est plus importante que le chiffre brut."*

### Slide à montrer

| Étape | Avant audit | Après audit |
|---|---|---|
| F1 macro | 0.9720 (gonflé) | **0.9671** (réel) |
| Leakage train↔test | 23.5% ❌ | 0.004% ✅ |
| Port Scanning F1 | 0.9994 (mémorisé) | 0.9846 (généralisé) |

### Ce qui rend le travail crédible

1. L'audit a **détecté** un problème — preuve de rigueur
2. La cause a été **identifiée** précisément — preuve de compréhension
3. La correction a été **appliquée** et **vérifiée** — preuve méthodologique
4. La perte de performance est **minime** — preuve que le modèle est solide
5. Tout est **documenté** dans ce rapport — preuve de transparence

---

## 11. FICHIERS IMPACTÉS PAR LA CORRECTION

### Code modifié
- ✅ `pipeline/io_utils.py` — ajout déduplication dans `clean_dataset`
- ✅ `pipeline/preprocess.py` — inversion ordre clean/sample

### Données régénérées
- ✅ `data/processed/X_train.npy`, `X_test.npy` (tailles 220k / 94k au lieu de 282k / 121k)
- ✅ `data/processed/y_train.npy`, `y_test.npy`
- ✅ `data/processed/scaler.pkl`, `manifest.json`

### Modèles régénérés
- ✅ `saved_models/v1_final/model.pkl`
- ✅ `saved_models/v1_final/manifest.json`

### Résultats régénérés
- ✅ `results/final/metrics.json`
- ✅ `results/final/classification_report.txt`
- ✅ `results/final/confusion_matrix.png`
- ✅ `results/final/per_class_metrics.{csv,png}`
- ✅ `results/final/feature_importance.{csv,png}`

### Notebooks
- ⚠️ Notebooks 01 et 02 **non re-exécutés** — laissés comme trace historique des résultats pré-audit. Les anciens résultats sont dans `results/eda/` et `results/modeling/` (à titre de comparaison).
- Les **résultats officiels** sont désormais dans `results/final/` (pipeline post-audit).

### Documentation mise à jour
- ✅ `AUDIT_RAPPORT.md` (ce fichier — NOUVEAU)
- ✅ `AVANCEMENT.md` (section "Audit" ajoutée)
- ✅ `README.md` (métriques mises à jour, lien vers audit)
- ✅ `EXPLICATION_MODELS.md` (note d'audit ajoutée)

---

## 12. VERDICT FINAL

**Le modèle CIC-IDS-2017 est solide, mais il a fallu un audit pour le savoir vraiment.**

- F1 macro **réel** = 0.9671 (vs 0.9720 affiché auparavant)
- Aucune classe en dessous de F1 = 0.80
- Leakage train↔test ramené de 23.5% à 0.004%
- Pipeline reproductible avec dédup intégrée

**Points forts à conserver :**
- Anti-shortcut sur `Destination Port` ✅
- Stratification du split + CV ✅
- `class_weight='balanced'` ✅
- Métriques macro ✅
- **Désormais : déduplication anti-leakage** ✅

**Limite résiduelle assumée :**
- Bots precision = 0.69 (190 Normal → Bots) — pas un bug, c'est inhérent à la similarité comportementale Bots ↔ Normal

---

*Rapport d'audit créé le 2026-05-19. Le projet CIC-IDS-2017 est désormais livrable avec des métriques honnêtes et un pipeline résistant au leakage.*
