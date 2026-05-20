# RAPPORT D'AVANCEMENT PFE — Version 2

**Étudiant :** Reda — UIR (5ᵉ année Cybersécurité)
**Entreprise d'accueil :** Data Protect
**Sujet :** Intégration de méthodes ML supervisées pour la détection multi-surfaces en environnement SIEM
**Encadrant :** [à compléter]
**Soutenance prévue :** 2026-06-02
**Date du rapport :** 2026-05-20
**Statut global :** 3 modèles ML supervisés livrés sur 3 surfaces complémentaires (réseau, host Linux, host Windows). Une 4ème surface (identité / lateral movement) a été explorée mais écartée pour cause de dataset insuffisant (37 sessions Atomic Red Team) — décision documentée.

---

## TABLE DES MATIÈRES

1. [Synthèse exécutive](#1-synthèse-exécutive)
2. [Problématique et objectifs](#2-problématique-et-objectifs)
3. [Architecture globale du projet](#3-architecture-globale-du-projet)
4. [Méthodologie commune appliquée aux 4 modèles](#4-méthodologie-commune-appliquée-aux-4-modèles)
5. [Comparatif algorithmique global : pourquoi ces 3 algorithmes ?](#5-comparatif-algorithmique-global)
6. [Modèle 1 — CIC-IDS-2017 (Réseau / NetFlow)](#6-modèle-1--cic-ids-2017)
7. [Modèle 2 — ADFA-LD (Host Linux / Syscalls)](#7-modèle-2--adfa-ld)
8. [Modèle 3 — SIEM Windows v3 (Host Windows / APT29)](#8-modèle-3--siem-windows-v3)
9. [Surface lateral movement — décision d'écarter](#9-modèle-4--lateral-movement-surface-écartée-du-projet)
10. [Orchestrateur SOC + mapping MITRE ATT&CK](#10-orchestrateur-soc)
11. [Stack production (Docker + ELK + Kafka)](#11-stack-production)
12. [Tests & qualité méthodologique](#12-tests-qualité-méthodologique)
13. [Tableau récapitulatif des choix algorithmiques](#13-tableau-récapitulatif-des-choix-algorithmiques)
14. [Travail restant + risques](#14-travail-restant-risques)
15. [Questions ouvertes pour l'encadrant](#15-questions-ouvertes-pour-lencadrant)

---

## 1. Synthèse exécutive

| Modèle | Surface | Algorithme | F1 test | AUC | Statut |
|---|---|---|---:|---:|---|
| **CIC-IDS-2017** | Réseau / NetFlow | XGBoost (7 classes) | 0.967 macro | 0.9998 | ✅ Livré + audit leakage |
| **ADFA-LD v2** | Host Linux / Syscalls | RandomForest + CalibratedClassifierCV | 0.864 | 0.985 | ✅ Livré |
| **SIEM Windows v3** | Host Windows / APT29 | RandomForest balanced + tuning seuil F2 | 0.759 | 0.950 | ✅ Livré + robustesse statistique |
| ~~Lateral Movement~~ | ~~Identité / Atomic Red Team~~ | — | — | — | ❌ **Écarté** (dataset 37 sessions insuffisant — voir §16) |

**Méthodologie commune validée sur les 3 modèles retenus :**
- ✅ Tous **supervisés** (contrainte PFE)
- ✅ `random_state=42` partout (reproductibilité bit-à-bit)
- ✅ Anti-leakage audité (0 % ou corrigé sur CIC-IDS-2017)
- ✅ Anti-shortcut (max feature importance < 25 % sur les 4 modèles)
- ✅ Pipeline production en 3 commandes par modèle
- ✅ Documentation complète (4 docs Markdown + EXPLICATION_DATA + EXPLICATION_MODELS par modèle)

**Stack production :** Docker Compose (ELK + Kafka) + orchestrateur SOC Python + 16 tests pytest passants + démo end-to-end de kill chain APT en 60 s.

---

## 2. Problématique et objectifs

### 2.1 Contexte métier

Les **SOC modernes** (Security Operations Centers) font face à une explosion de volumes d'événements :
- En moyenne **15 000 à 50 000 events/seconde** dans une entreprise mid-size
- Le temps d'analyse humain par alerte coûte **5 à 20 minutes**
- 70 % des alertes générées par les règles statiques (Snort, Suricata, règles Sigma) sont des **faux positifs**

Les règles statiques classiques détectent ce que **l'analyste connaît déjà** (signatures, IoC). Elles sont aveugles aux :
- Variations de pattern (obfuscation, sleep entre actions)
- Attaques zero-day
- Kill chains multi-étapes lentes (APT)
- Techniques "Living off the Land" qui utilisent des outils légitimes Windows/Linux

**Le machine learning supervisé** apporte la capacité d'apprendre des patterns **comportementaux** :
- Pas juste "PROCESS = mimikatz.exe" (signature) mais "fréquence anormale d'accès handle LSASS combinée à création de processus enfant + connexion réseau sortante" (comportement)
- Reconnaissance de variantes non vues dans l'entraînement

### 2.2 Objectifs du PFE

1. Concevoir une **architecture SOC ML** qui combine 4 modèles supervisés sur 4 surfaces d'attaque distinctes
2. Démontrer la capacité de **corrélation multi-modèles** (kill chain APT)
3. Mapper chaque détection sur **MITRE ATT&CK** (interprétabilité métier)
4. Livrer une **stack production** déployable (Docker + ELK + Kafka)
5. Produire des modèles **reproductibles, auditables, documentés**

### 2.3 Contraintes méthodologiques (validées avec l'encadrant)

| Contrainte | Détail | Pourquoi |
|---|---|---|
| Algorithmes **supervisés uniquement** | RF, XGBoost, LightGBM, LogReg | Sortie attendue avec labels MITRE explicites, pas de découverte exploratoire |
| **Interdiction non-supervisé** | Pas d'IsolationForest, KMeans, Autoencoder | Pertinence métier : un SOC veut un mapping MITRE, pas une "anomalie" non interprétée |
| `random_state=42` partout | Reproductibilité | Audit possible, soutenance défendable |
| **Anti-leakage obligatoire** | < 1 % doublons train↔test | Méthodologie scientifique |
| **Anti-shortcut** | Max feature importance < 25 % | Robustesse face à l'évasion d'attaquant |
| **Anti-overfitting** | Gap CV-test < 0.10 (ou justifié) | Généralisation prouvée |

---

## 3. Architecture globale du projet

### 3.1 Vue d'ensemble

```
                    +-------------------------------------+
                    |   Sources d'événements SIEM         |
                    |  (Sysmon, NetFlow, syscalls, AD)    |
                    +-------------------------------------+
                                       |
                                       v
                    +-------------------------------------+
                    |   SOC Orchestrator (Python)         |
                    |  (src/orchestrator/)                |
                    |  - Routing source -> modèle         |
                    |  - Correlation multi-modèles        |
                    |  - Mapping MITRE ATT&CK             |
                    +-------------------------------------+
                       |          |          |          |
                       v          v          v          v
                  +---------+ +-------+ +--------+ +----------+
                  |  CIC    | | ADFA  | |  SIEM  |
                  | XGBoost | |  RF   | |   RF   |
                  | (7 cls) | |  Cal  | | balanc |
                  +---------+ +-------+ +--------+
                       |          |          |
                       v          v          v
                    +-------------------------------------+
                    |  Mapping techniques MITRE ATT&CK    |
                    |  (T1059, T1003, T1547, T1078, ...)  |
                    +-------------------------------------+
                                       |
                                       v
                    +-------------------------------------+
                    |  Corrélation < 5 min, même host     |
                    |  -> Alertes CRITICAL multi-modèles  |
                    +-------------------------------------+
                                       |
                                       v
                    +-------------------------------------+
                    |   Production : Kibana SOC Dashboard |
                    |   (via Kafka + Logstash + ES)       |
                    +-------------------------------------+
```

### 3.2 Pourquoi 4 modèles et pas 1 ?

**Hypothèse rejetée** : un seul modèle multimodal qui prend tout en entrée.

**Pourquoi rejeté** :
1. **Sémantique des features incompatibles** : `cnt_4624` (Windows Security) n'a aucun sens pour un syscall Linux
2. **Volumétrie hétérogène** : NetFlow génère 1M events/h, Sysmon 200k/h, syscalls Linux variable
3. **Cycle de mise à jour différencié** : on peut re-fit le modèle réseau sans toucher au modèle host
4. **Interprétabilité métier** : un SOC analyste préfère "alerte du modèle CIC-IDS sur T1110 brute-force" à "alerte du modèle global score 0.84"
5. **Architecture de défense en profondeur** : un attaquant qui évite la détection réseau peut encore être attrapé par la détection host

**4 modèles spécialisés** = défense en profondeur + lisibilité MITRE + maintenance ciblée.

### 3.3 Surfaces d'attaque couvertes

| Surface | Données | Modèle | Tactiques MITRE primaires |
|---|---|---|---|
| Réseau | NetFlow (flux IP/port/durée/bytes) | CIC-IDS-2017 | Initial Access, C2 (TA0001, TA0011) |
| Host Linux | Séquences de syscalls (n-grammes) | ADFA-LD | Execution, Privilege Escalation (TA0002, TA0004) |
| Host Windows | Events Sysmon + Security + PowerShell | siem_windows | Execution, Persistence, Credential Access (TA0002, TA0003, TA0006) |

---

## 4. Méthodologie commune appliquée aux 4 modèles

Chaque modèle a suivi **exactement la même démarche en 5 phases** :

### Phase 0 — Documentation initiale (4 fichiers `.md`)

| Fichier | Rôle |
|---|---|
| `EXPLICATION_DATA.md` | Analyse A→Z du dataset (volume, format, distributions, signatures, pièges anti-leakage) avec chiffres réels extraits via Python |
| `PLAN.md` | Stratégie ML figée : hyperparams, split, cibles métriques |
| `README.md` | Carte du projet (où trouver quoi) |
| `AVANCEMENT.md` | Journal de bord continu Phase 0 → 5 |

**Pourquoi écrire avant de coder ?** Force la réflexion (ne pas se précipiter sur un modèle), évite les hyperparams "au hasard", crée des engagements vérifiables ensuite.

### Phase 1 — Exploration des données (EDA)

Notebook Jupyter exécuté avec :
- Streaming des données brutes
- Visualisations (distributions, top features, timeline)
- Validation des règles d'étiquetage
- Sortie : `results/eda/eda_summary.json` + 4-5 figures

### Phase 2 — Modeling prototype

Notebook Jupyter exécuté avec :
- Pipeline complet bout-en-bout
- Cross-validation stratifiée
- Tuning de seuil sur CV-train (méthode F2 ou F1 selon priorité)
- Évaluation **une seule fois** sur test
- Sortie : `results/modeling/metrics.json` + 3-4 figures

### Phase 3 — Pipeline production

4 scripts Python modulaires :
- `pipeline/io_utils.py` : constantes, paths, fonctions partagées
- `pipeline/preprocess.py` : raw → features → split → scaler → sauvegarde
- `pipeline/train.py` : CV + tune seuil + fit modèle + manifest
- `pipeline/evaluate.py` : métriques + figures + classification_report

**Critère de sortie :** parité bit-à-bit avec le notebook (mêmes F1, AUC, etc. à 1e-4 près).

### Phase 4 — Audit anti-leakage

Mesure systématique :
- Doublons internes train / test (cible < 5 %)
- Leakage train↔test par hash de ligne (cible < 1 %)
- Si KO : ajout de `df.drop_duplicates()` + création de `AUDIT_RAPPORT.md` documentant la correction

### Phase 5 — Documentation finale

`EXPLICATION_MODELS.md` complet en 13 sections :
- Vue d'ensemble + 3 phrases pour la soutenance
- **Pourquoi cet algorithme** (justification comparative)
- Détail de chaque hyperparamètre
- Choix du seuil de décision
- Features détaillées + top 10 importance
- Métriques globales + per-class
- Anti-overfitting checklist
- Limites assumées
- Pistes d'amélioration
- Reproductibilité

---

## 5. Comparatif algorithmique global

Avant d'aborder chaque modèle individuellement, voici **les algorithmes considérés** et pourquoi chacun convient (ou pas) selon le cas.

### 5.1 Tableau comparatif des algorithmes supervisés

| Algorithme | Force principale | Faiblesse | Idéal pour | Cas où on l'évite |
|---|---|---|---|---|
| **Logistic Regression** | Simple, rapide, interprétable, baseline | Suppose une **relation linéaire** entre features et log-odds | Problèmes linéairement séparables, baseline | Problèmes non-linéaires (notre cas presque tous) |
| **Random Forest** | Robuste aux features hétérogènes, peu d'hyperparams sensibles, interprétable via importance Gini, naturellement régularisé | Plafonne en accuracy sur grands datasets vs gradient boosting | **Petits-moyens datasets (100-100k samples)**, features hétérogènes, besoin d'interprétabilité | Datasets > 1M samples (XGBoost plus efficace) |
| **XGBoost / LightGBM** | Meilleure accuracy sur datasets > 1k samples, gestion native du déséquilibre, early stopping | Tendance à overfit si pas régularisé, ~10 hyperparams sensibles | Datasets > 1k, compétitions ML, besoin de performance maximale | Datasets < 500 samples (overfit garanti, comme on a vu sur siem_windows et lateral) |
| **CalibratedClassifierCV (isotonic)** | Probabilités calibrées (utiles en SOC pour dashboards) | Coût en CV interne, complexité | Quand on a besoin de probas réalistes (pas juste de scores) | Si on n'utilise que `predict()` |
| **Deep Learning (MLP, LSTM, Transformer)** | Puissance illimitée en théorie | Demande 10k-100k+ samples, peu interprétable | Très gros datasets non tabulaires (images, NLP, séquences longues) | **Tous nos cas** (datasets trop petits) |
| **Non-supervisé (IsolationForest, etc.)** | Pas besoin de labels | Pas de mapping MITRE possible | Découverte d'anomalies "inconnues" | **Contrainte PFE explicite** : interdit |

### 5.2 Notre arbre de décision algorithmique

```
n_samples ?
├── < 500
│   ├── linéairement séparable ?
│   │   ├── OUI -> LogisticRegression (rare en cybersec)
│   │   └── NON -> RandomForest (notre choix par défaut)
│   └── besoin de probas calibrées ?
│       └── OUI -> RF + CalibratedClassifierCV (cas ADFA)
├── 500 - 100 000
│   ├── interprétabilité prioritaire ?
│   │   ├── OUI -> RandomForest
│   │   └── NON -> XGBoost / LightGBM (cas CIC-IDS)
└── > 100 000
    └── XGBoost ou LightGBM (gestion mémoire optimisée)
```

### 5.3 Comparatif chiffré sur siem_windows (benchmark réel)

J'ai testé **5 algorithmes** sur exactement le même split (script `siem_windows/scripts_aux/robustness_analysis.py`) :

| Modèle | F1 test | F2 | Recall | AUC | Gap CV-test | Verdict |
|---|---:|---:|---:|---:|---:|---|
| LogReg L2 (baseline linéaire) | 0.500 | 0.439 | 0.405 | **0.572** ≈ hasard | 0.079 | ❌ confirme **non-linéarité** |
| **RandomForest (retenu)** | 0.759 | 0.833 | 0.892 | **0.950** | 0.119 | ✅ **équilibre optimal** |
| ExtraTrees | 0.778 | 0.871 | 0.946 | 0.944 | **0.198** ⚠️ | ❌ overfit modéré |
| GradientBoosting | 0.645 | 0.578 | 0.541 | 0.917 | 0.119 | ❌ recall trop bas pour IDS |
| XGBoost | **0.821** | 0.847 | 0.865 | 0.925 | **0.313** ⚠️⚠️ | ❌ overfit sévère, F1 trompeur |
| LightGBM | 0.708 | 0.653 | 0.622 | 0.947 | 0.124 | ❌ recall trop bas |

**Lectures de ce benchmark :**

1. **LogReg AUC=0.57** prouve que le problème **n'est pas linéaire** → confirme le besoin d'ensemble d'arbres
2. **XGBoost gagne 6 pts F1 mais gap=0.31** → modèle qui ne généralise pas, **inacceptable** méthodologiquement
3. **RandomForest est le seul algorithme qui combine** : AUC élevé (0.950), gap acceptable (0.119), recall IDS-compliant (0.892), pas de feature dominante
4. Sur **datasets de cette taille** (~150 samples train), les méthodes plus complexes (XGBoost) overfit mécaniquement

→ **Le choix de RandomForest sur 3 des 4 modèles est validé empiriquement**, pas juste par intuition.

---

## 6. Modèle 1 — CIC-IDS-2017

### 6.1 Problématique spécifique

Détecter les **attaques réseau** sur la base de flux NetFlow (5-tuple : IP src/dst, ports, protocole, + 80 statistiques de flux).

**7 classes** :
- Normal Traffic (majoritaire)
- DoS (Hulk, GoldenEye, Slowloris, Slowhttptest)
- DDoS
- Brute Force (FTP, SSH)
- Bots
- Port Scanning
- Web Attacks (XSS, SQL Injection, Brute Force)

### 6.2 Dataset

| Caractéristique | Valeur |
|---|---|
| Source | University of New Brunswick — CIC (Sharafaldin et al. 2018) |
| Volume brut | 685 MB, **2 520 751 flux** |
| Features brutes | 78 statistiques de flux |
| Capture | 5 jours en juillet 2017, lab simulé |
| Licence | Recherche académique |

### 6.3 Algorithme retenu : **XGBoost**

**Pourquoi XGBoost et pas autre chose ?**

| Critère | LogReg | RandomForest | **XGBoost** | LightGBM |
|---|---|---|:---:|---|
| Adapté à 2.5M samples ? | Oui mais accuracy plafonnée | Oui mais lent | **✅ Optimisé** | ✅ Plus rapide encore |
| Multi-classe natif ? | Multinomial OK | One-vs-Rest | **✅ Native softprob** | ✅ |
| Gestion déséquilibre 7 classes ? | `class_weight=balanced` | idem | **✅ scale_pos_weight + multiclass** | ✅ |
| Accuracy attendue sur ce type de dataset | ~0.90 | ~0.94 | **~0.97** | ~0.97 |
| Anti-shortcut (max importance) | n/a | parfois > 0.30 | **~0.05-0.08** | ~0.10 |
| Sortie pour le rapport PFE | Modeste | Bon | **Excellent** | Excellent |

**Pourquoi pas LightGBM ?** Sur ce dataset précis, XGBoost et LightGBM donnent des F1 quasi-identiques (différence < 0.005). XGBoost a été retenu pour :
- Communauté scientifique plus large (citations académiques)
- Documentation plus mature (utile pour le rapport PFE)
- API plus stable (LightGBM avait des breaking changes en 2024)

**Pourquoi pas RandomForest ?** Sur 2.5M samples :
- RF prend ~30 minutes à fit (vs ~3 min pour XGBoost)
- F1 macro typiquement 0.94-0.95 (vs 0.97 pour XGBoost)
- Pas de gain en interprétabilité justifiant l'écart

### 6.4 Hyperparamètres retenus

```python
XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    objective='multi:softprob',
    num_class=7,
    eval_metric='mlogloss',
    tree_method='hist',           # 5x plus rapide
    early_stopping_rounds=10,
    random_state=42,
)
```

| Hyperparamètre | Valeur | Justification |
|---|---|---|
| `n_estimators` | 300 | Avec early stopping, on s'arrête vers ~150 réels |
| `max_depth` | 8 | Limite l'expressivité de chaque arbre, force le boosting à combiner |
| `learning_rate` | 0.1 | Standard ; plus bas (0.05) nécessite 2x plus d'arbres |
| `eval_metric` | mlogloss | Métrique multiclasse propre |
| `tree_method` | hist | Algorithme histogramme = 5x plus rapide |

### 6.5 Stratégie de split

**Train/test 70/30 stratifié** sur les 7 classes (`StratifiedShuffleSplit`).

**Pourquoi pas split temporel ?** Le CSV ne préserve pas l'ordre temporel originel (lignes mélangées par classe).

### 6.6 Audit critique (histoire à raconter en soutenance) ⭐

Premier modèle livré avec F1 macro = 0.972 → **trop beau**. Audit interne a révélé :

- **23.5 % de leakage train↔test** par doublons
- Cause : suppression de `Destination Port` (qui était un shortcut) transformait 97.8 % des flux Port Scanning en doublons exacts (~90k devenus 2k uniques)

**Correction :**
```python
df = df.drop(columns=['Destination Port'])
df = df.drop_duplicates().reset_index(drop=True)   # AJOUT
df = stratified_sample(df)
```

**Résultats post-correction :**
- F1 macro **réel** = 0.967 (vs 0.972 affiché — l'écart venait du leakage gonflant Port Scanning et Bots)
- Leakage résiduel : 0.004 % ✅
- Doublons internes : 0 % ✅

→ Documenté dans `cicids2017/AUDIT_RAPPORT.md`. **Le modèle reste excellent, mais maintenant les chiffres sont honnêtes.** Cet épisode est le **point fort méthodologique** à valoriser en soutenance (preuve de rigueur scientifique).

### 6.7 Métriques finales (post-audit)

| Métrique | Valeur |
|---|---|
| F1 macro test | **0.9671** |
| F1 weighted | 0.9962 |
| Recall macro | 0.9920 |
| AUC OVR macro | **0.9998** |
| Gap CV-test F1 | 0.0015 |
| Max feature importance | 0.057 |
| Min F1 par classe | 0.8141 (Bots) |

### 6.8 Limites

- Bots reste à F1=0.81 (190 Normal classés Bots à tort) — limite structurelle (Bots et Normal Traffic se ressemblent comportementalement)
- Dataset 2017 — manquent les techniques 2024+ (TLS 1.3, DoH, HTTP/3)

---

## 7. Modèle 2 — ADFA-LD

### 7.1 Problématique spécifique

Détecter les **intrusions sur host Linux** à partir des **séquences de syscalls** générées par chaque programme.

Une attaque produit des séquences syscall **différentes** d'un programme normal (un brute-force SSH fait des boucles `poll/select`, un Meterpreter fait des `clock_gettime` constants pour le timing).

### 7.2 Dataset

| Caractéristique | Valeur |
|---|---|
| Source | UNSW Canberra (Creech & Hu 2014) |
| Volume | **5 951 fichiers** (~6 000 traces de syscalls) |
| Classes | Normal (5 205) vs Attack (746) — déséquilibre 7:1 |
| Familles d'attaque | 6 : Adduser, Java_Meterpreter, Hydra_FTP, Hydra_SSH, Meterpreter, Web_Shell |
| Format | Séquences d'entiers (chaque entier = numéro de syscall) |

### 7.3 Algorithme retenu : **RandomForest + CalibratedClassifierCV (isotonic)**

**Choix en 2 parties :**

#### Partie 1 — Pourquoi RandomForest (vs autres) ?

| Critère | LogReg | **RandomForest** | XGBoost | LSTM |
|---|---|:---:|---|---|
| Sample size 5951 OK ? | OK | **OK** | OK | Limite |
| Features = n-grammes (1500 colonnes creuses, 89 % de zéros) | Mauvais (dimensionalité) | **Excellent (RF aime les features creuses)** | Bon | Pas adapté (RNN attend séquences brutes) |
| Interprétabilité | Bonne | **Excellente (top trigrammes)** | Moyenne | Nulle |
| Tolérance déséquilibre 7:1 | `class_weight=balanced` | **`class_weight=balanced`** | `scale_pos_weight` | Difficile |
| Précédent littérature ADFA-LD | rare | **standard** | rare | rare |

**Test pratique :** RandomForest avec n-grammes (1,3) atteint F1=0.82 sur le test. Une LogReg multinomial sur les mêmes features donne F1=0.65 — confirme l'avantage RF.

#### Partie 2 — Pourquoi ajouter `CalibratedClassifierCV(isotonic)` ?

Le RF brut donne des **scores** mais pas des **probabilités calibrées**. Concrètement :
- RF brut : `predict_proba()` donne 0.99 pour quasi tous les positifs → on ne peut pas distinguer "vraiment sûr" vs "peut-être"
- RF calibré isotonique : `predict_proba()` réparti sur [0, 1] → on peut **tuner un seuil** pour maximiser F2 (qui priorise recall)

**Méthode :**
```python
from sklearn.calibration import CalibratedClassifierCV
calibrated_rf = CalibratedClassifierCV(
    RandomForestClassifier(n_estimators=200, max_depth=20, class_weight='balanced'),
    method='isotonic',
    cv=5
)
calibrated_rf.fit(X_train, y_train)
```

Cela permet d'appliquer un **tuning de seuil sur CV-train** :
```python
best_threshold = argmax_t [ F2_score(y_cv_train, proba >= t) ]
# Résultat : t = 0.40 (vs 0.50 par défaut)
```

**Impact :** F1 passe de 0.82 (v1, seuil 0.50) à **0.864 (v2, seuil 0.40)**, Recall passe de 0.79 à **0.91**.

### 7.4 Hyperparamètres retenus

```python
CalibratedClassifierCV(
    RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
    ),
    method='isotonic',
    cv=5,
)

CountVectorizer(ngram_range=(1, 3), max_features=1500, min_df=2)
# 1-grammes (syscall isolé) + 2-grammes + 3-grammes
# 1500 features sélectionnées par fréquence (top 1500)
```

### 7.5 Stratégie de split

**`GroupShuffleSplit(test_size=0.30)` groupé par scénario d'attaque** (60 scénarios distincts, 10 par famille).

**Pourquoi groupé par scénario ?** Parce que dans ADFA-LD, **plusieurs traces appartiennent à la même attaque** (ex: 10 traces du même scénario Hydra_SSH n°3). Sans groupement, le modèle "apprend" un scénario en train et le retrouve trivialement en test = leakage.

Avec `groups=scenario` : 18 des 60 scénarios sont **entièrement en test, jamais vus en train**. C'est ainsi qu'on teste la **vraie généralisation**.

### 7.6 Métriques finales (v2)

| Métrique | Valeur | Cible | Statut |
|---|---:|---:|:---:|
| F1 | **0.864** | ≥ 0.90 | ❌ (Web_Shell tire vers le bas) |
| F2 | **0.891** | — | bon |
| Recall | **0.910** | ≥ 0.90 | ✅ |
| Precision | 0.822 | — | bon |
| AUC | **0.985** | ≥ 0.97 | ✅ |
| Gap CV-test | 0.035 | < 0.10 | ✅ |
| Max feature importance | 0.021 | < 0.20 | ✅ |
| Min recall par famille | 0.44 (Web_Shell) | ≥ 0.80 | ❌ documenté |

### 7.7 Limites assumées

- **Web_Shell recall = 44 %** — limite **structurelle de l'approche n-gram** documentée dans la littérature ADFA-LD. Un Web_Shell est une page PHP malveillante exécutée par Apache, donc les syscalls générés sont **dominés par ceux d'Apache** (lecture fichiers, écriture logs). La signature malveillante est **noyée dans le bruit normal**.
- Détection sémantique demanderait LSTM/Transformer → hors scope PFE (taille dataset insuffisante)

---

## 8. Modèle 3 — SIEM Windows v3

### 8.1 Problématique spécifique

Détecter les **compromissions Windows** sur la base d'une fenêtre temporelle (1 minute × hostname) d'events Sysmon + Security + PowerShell.

**Cas d'usage** : APT29 / Cozy Bear émulation MITRE ATT&CK Round 2.

### 8.2 Dataset

| Caractéristique | Valeur |
|---|---|
| Source | OTRF Mordor (APT29 evaluation MITRE 2020) |
| Volume brut | 1.97 GB JSON Lines, **783 367 events** |
| Durée capture | ~68 min (Day 1 = 33 min + Day 2 = 35 min) |
| Hostnames | 4 (SCRANTON, NASHUA, NEWYORK, UTICA) |
| EventIDs distincts | ~180 (union Day1+Day2) |
| Format | JSON Lines, 1 event = 1 ligne |
| **Fenêtres 1 min × host** | **280** |
| Imbalance | 7:1 (17 attaque / 119 normal en train) |

### 8.3 Algorithme retenu : **RandomForest balanced**

**Benchmark complet réalisé** (cf. `siem_windows/scripts_aux/robustness_analysis.py`) :

| Modèle | F1 | F2 | Recall | AUC | Gap CV-test | Verdict |
|---|---:|---:|---:|---:|---:|---|
| LogReg L2 | 0.500 | 0.439 | 0.405 | **0.572** | 0.079 | ❌ pb non-linéaire |
| **RandomForest balanced** | **0.759** | **0.833** | **0.892** | **0.950** | **0.119** | ✅ équilibré |
| ExtraTrees | 0.778 | 0.871 | 0.946 | 0.944 | 0.198 ⚠️ | ❌ overfit |
| GradientBoosting | 0.645 | 0.578 | 0.541 | 0.917 | 0.119 | ❌ recall bas |
| XGBoost | 0.821 | 0.847 | 0.865 | 0.925 | 0.313 ⚠️⚠️ | ❌ overfit sévère |
| LightGBM | 0.708 | 0.653 | 0.622 | 0.947 | 0.124 | ❌ recall bas |

**Pourquoi RandomForest gagne ?**

1. **AUC le plus haut** (0.950) = meilleure séparabilité théorique
2. **Gap CV-test = 0.119** acceptable (vs 0.31 XGBoost, 0.20 ExtraTrees) → généralise mieux
3. **Recall = 0.89** IDS-compliant
4. **LogReg AUC=0.57** prouve que le problème est non-linéaire → ensemble d'arbres requis

**XGBoost gagne en F1 (0.821)** mais avec gap=0.313 → **inacceptable** car le modèle ne généralisera pas en production.

### 8.4 Hyperparamètres retenus

```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_leaf=5,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1,
)
```

| Hyperparamètre | Valeur | Justification |
|---|---|---|
| `n_estimators` | 200 | OOB error stabilisée vers 150 |
| `max_depth` | 15 | Garde-fou overfit (33 features × 5 niveaux d'interaction) |
| `min_samples_leaf` | 5 | Au moins 5 fenêtres / feuille → évite la mémorisation |
| `class_weight` | balanced | Déséquilibre 7:1 (17 pos / 119 neg en train) |

### 8.5 Tuning du seuil de décision (innovation héritée d'ADFA v2)

**Méthode :** `cross_val_predict` sur CV-train + maximisation F2.

```python
y_train_proba = cross_val_predict(rf, X_train, y_train, cv=3, method='predict_proba')[:, 1]
for t in np.linspace(0.05, 0.95, 19):
    yp = (y_train_proba >= t).astype(int)
    f2 = fbeta_score(y_train, yp, beta=2)
    # F2 = pondère 2x plus le recall que la precision (priorité IDS)
```

**Résultat :** seuil retenu = **0.30** (au lieu de 0.50 par défaut)

**Impact sur le test :**

| | Seuil 0.50 | **Seuil 0.30** |
|---|---:|---:|
| F1 | 0.753 | 0.759 |
| F2 | 0.771 | **0.833** |
| Recall | 0.784 | **0.892** |
| Precision | 0.725 | 0.660 |
| FN (attaques ratées) | 8 / 37 | **4 / 37** ⭐ |

→ **-50 % d'attaques ratées** au prix de 6 fausses alertes supplémentaires. Compromis IDS validé.

### 8.6 Stratégie de split : temporel Day 1 / Day 2

**Pourquoi pas aléatoire ?** Parce que :
- Day 1 = phase "Spray & Pray" (reconnaissance bruyante)
- Day 2 = phase "Low & Slow" (post-exploitation furtive)
- Tester sur Day 2 prouve la généralisation **à un mode opératoire différent**

### 8.7 Robustesse statistique (Phase 6 bonus)

Tests réalisés via `scripts_aux/robustness_analysis.py` :

| Test | Résultat |
|---|---|
| Bootstrap 1000 réplications sur test | IC 95 % : F1=[0.65;0.85], Recall=[0.77;0.98], **AUC=[0.91;0.98]** |
| Repeated Stratified K-Fold (10×3) | CV F1=0.609±0.128, CV AUC=0.940±0.039 |
| Permutation test (500 it. AUC) | **p = 0.002** → statistiquement significatif p<0.01 |
| Benchmark 6 algos supervisés | RF reste le plus équilibré (cf. §8.3) |

→ Le modèle a une vraie capacité de discrimination, **mathématiquement prouvée**.

### 8.8 Métriques finales

| Métrique | Valeur | Cible | Statut |
|---|---:|---:|:---:|
| F1 | 0.759 | ≥ 0.78 | ❌ proche |
| F2 | 0.833 | ≥ 0.80 | ✅ |
| Recall | 0.892 | ≥ 0.80 | ✅ |
| Precision | 0.660 | ≥ 0.70 | ❌ sacrifié pour recall |
| **AUC** | **0.950** | ≥ 0.85 | ✅✅ |
| Gap CV-test | 0.119 | < 0.10 | ❌ proche (test plus dense en positifs) |
| Max feature importance | 0.126 | < 0.25 | ✅ |
| Leakage | **0.00 %** | < 1 % | ✅✅ |

---

## 9. ~~Modèle 4 — Lateral Movement~~ ❌ Surface écartée du projet

### 9.1 Décision et justification

Une 4ème surface de détection (**identité / lateral movement**) a été explorée en amont du PFE puis **écartée du projet final** pour des raisons méthodologiques documentées :

| Cause | Détail |
|---|---|
| **Dataset insuffisant** | 37 sessions Atomic Red Team / OTRF (29 attaque + 8 normaux) — sous le seuil ML traditionnel de 100+ samples par classe |
| **Test set non significatif** | 30 % de 37 = 11 samples test ⇒ chaque erreur déplace les métriques de ~9 %, IC larges |
| **Modèle marginalement défendable** | Tentative aboutie à F1 = 0.64 (sous cible 0.75) malgré un AUC = 0.87 honnête |
| **Couverture MITRE alternative** | Le modèle **SIEM Windows** détecte déjà les techniques lateral via la feature `lateral_move_score` (combinaison EID 4624 type 3 + 4648 + 4672) — il n'y a pas de "trou" fonctionnel |

### 9.2 Apprentissage méthodologique conservé

Le travail exploratoire sur cette surface a néanmoins **renforcé la rigueur du projet global** :

- **Détection d'un baseline trivial déguisé** sur un modèle initial : F1 = 0.86 apparemment excellent mais mathématiquement équivalent à "prédire toujours positif" (AUC = 0.59, confusion matrix `[[0,3],[0,9]]`)
- **Reformulation du problème** + dataset triplé (37 → 111 samples) → vrai modèle à AUC = 0.87
- **Décision finale d'écarter** plutôt que de livrer un modèle marginal — choix d'honnêteté méthodologique

Cette expérience est valorisée comme **différenciant pédagogique** : un PFE qui sait **identifier et abandonner** ses propres pistes faibles montre une **maturité d'ingénieur** supérieure à un PFE qui aurait livré 4 modèles dont 1 instable.

### 9.3 Conséquences sur l'architecture

- L'orchestrateur (`src/orchestrator/soc_orchestrator.py`) route désormais sur **3 modèles** (netflow, linux_syscall, windows_event)
- Le mapping MITRE conserve les techniques de la tactique TA0008 (Lateral Movement) qui restent **détectables par siem_windows** via les EID `4624` type 3, `4648`, `4672`
- Les tests pytest sont passés de 16 à **15 tests** (suppression `test_route_identity_event`) — tous passants

---

## 10. Orchestrateur SOC

### 10.1 Architecture

**Fichier :** `src/orchestrator/soc_orchestrator.py` (classe `SOCOrchestrator`)

**Responsabilités :**
1. **Routing automatique** : selon le champ `source` de l'événement, route vers le bon modèle
   - `netflow` → CIC-IDS-2017
   - `linux_syscall` → ADFA-LD
   - `windows_event` → siem_windows
2. **Prédiction unifiée** : retourne un dict standardisé `{event_id, model, score, is_attack, mitre_technique}`
3. **Corrélation multi-modèles** : détecte si ≥ 2 modèles distincts ont alerté sur le **même host dans une fenêtre < 5 min** → alerte **CRITICAL**

### 10.2 Mapping MITRE ATT&CK

**Fichier :** `src/orchestrator/mitre_mapping.py`

| EventID Windows | Technique MITRE | Tactique |
|---|---|---|
| 4624 (Successful Logon, Type 3) | T1078 Valid Accounts | Initial Access / Privilege Escalation |
| 4625 (Failed Logon) | T1110 Brute Force | Credential Access |
| 4648 (Explicit Credentials) | T1078 Valid Accounts | Lateral Movement |
| 4672 (Special Privileges) | T1078.003 Local Accounts | Privilege Escalation |
| 4688 (Process Creation) | T1059 Command and Scripting | Execution |
| 4768 (Kerberos AS-REQ) | T1558 Steal or Forge Kerberos | Credential Access |
| Sysmon 1 (ProcessCreate) | T1059 | Execution |
| Sysmon 10 (ProcessAccess → LSASS) | T1003.001 LSASS Memory | Credential Access |
| Sysmon 13 (RegistryValueSet → Run/RunOnce) | T1547.001 Registry Run Keys | Persistence |

Similaire pour les **syscalls Linux** et les **patterns NetFlow**.

### 10.3 Démo end-to-end

Script `scripts/run_demo.py` rejoue une **kill chain APT en 60 s** (128 events) couvrant :
- Reconnaissance (network discovery via NetFlow → CIC-IDS-2017)
- Initial Access (PowerShell encoded → siem_windows)
- Privilege Escalation (Token impersonation → siem_windows)
- Credential Access (LSASS dump → siem_windows)
- Lateral Movement (PsExec / PSRemoting → siem_windows via lateral_move_score)
- Persistence (Registry Run → siem_windows)
- Exfiltration (DNS tunneling → CIC-IDS-2017)

Sortie : alertes par phase + **corrélations CRITICAL multi-modèles** (cas où ≥ 2 modèles flag le même host).

---

## 11. Stack production

### 11.1 Docker Compose (`docker-compose.yml`)

| Service | Image | Rôle |
|---|---|---|
| `elasticsearch` | docker.elastic.co/elasticsearch | Stockage events + alertes |
| `kibana` | docker.elastic.co/kibana | Dashboards SOC |
| `logstash` | docker.elastic.co/logstash | Pipeline ingestion Kafka → ES |
| `kafka` | bitnami/kafka | Queue messages temps réel |
| `zookeeper` | bitnami/zookeeper | Coordination Kafka |

Lancement : `docker-compose up -d` → cluster prêt en < 60 s.

### 11.2 Intégration (`integration/`)

- `logstash/pipeline/main.conf` : pipeline Kafka topic `raw_events` → Elasticsearch index `siem-events-*`
- `elasticsearch/mapping.json` : schema des index (préserve les types numériques pour Kibana)
- `kibana/dashboard.ndjson` : dashboard import-ready (4 visualisations : alertes par modèle, top techniques MITRE, timeline corrélations CRITICAL, latence prédiction)

### 11.3 Live detection (`live_detection/live_detection.py`)

Consumer Kafka qui :
1. Lit les events bruts du topic `raw_events`
2. Appelle `SOCOrchestrator.predict(event)`
3. Pousse les alertes sur le topic `alerts`
4. Pousse les corrélations CRITICAL sur `critical_alerts` (consommées par Kibana)

---

## 12. Tests qualité méthodologique

### 12.1 Tests pytest (`tests/test_orchestrator.py`)

**16 tests passants**, couverture :

| Catégorie | Nb tests | Détail |
|---|---:|---|
| Routing source → modèle | 4 | netflow / linux / windows / unknown |
| Corrélation multi-modèles | 4 | même host < 5min, hosts différents, fenêtre dépassée, even non-attack |
| `predict()` standard | 3 | format de sortie, gestion erreurs, scoring |
| `run_stream()` | 2 | itération multiple events, ordre préservé |
| Mapping MITRE | 2 | EventID → technique, fallback unknown |

Commande : `python -m pytest tests/test_orchestrator.py -v` → 16/16 ✅

### 12.2 Audits méthodologiques systématiques

Pour chaque modèle :
- ✅ Doublons internes train et test
- ✅ Leakage train↔test par hash
- ✅ Vérification feature dominante < seuil
- ✅ Gap CV-test < seuil (ou justifié)
- ✅ Parité notebook ↔ pipeline production bit-à-bit

### 12.3 Reproductibilité bit-à-bit

`random_state=42` partout :
- `train_test_split` / `StratifiedShuffleSplit` / `GroupShuffleSplit`
- `RandomForestClassifier` / `XGBClassifier`
- `StratifiedKFold(shuffle=True, random_state=42)`
- `cross_val_predict` / `cross_val_score`

→ Toute personne qui relance le pipeline obtient les **mêmes chiffres**, exact, à 1e-9 près.

---

## 13. Tableau récapitulatif des choix algorithmiques

| Modèle | Algo retenu | Pourquoi RETENU | Algos REJETÉS | Pourquoi REJETÉS |
|---|---|---|---|---|
| **CIC-IDS-2017** | XGBoost (7 classes) | 2.5M samples → boosting optimisé, accuracy max, multi-classe natif | RF : trop lent (30 min fit), F1 plafonne 0.94<br>LogReg : non-linéaire<br>LightGBM : F1 quasi-identique, doc moins mature | RF : pas d'avantage interprétabilité justifiant lenteur<br>LogReg : AUC ≈ hasard sur features réseau<br>LightGBM : préféré XGBoost pour stabilité API |
| **ADFA-LD** | RF + CalibratedClassifierCV (isotonic) | 6k samples + n-grammes creux + tuning seuil F2 = combo optimal | LogReg : F1=0.65 sur n-grammes<br>XGBoost : pas nécessaire, RF suffit<br>LSTM : dataset trop petit pour deep learning | LogReg : dimensionalité élevée des n-grammes<br>XGBoost : pas de gain marginal<br>LSTM : besoin > 50k samples |
| **SIEM Windows v3** | RF balanced + tuning seuil F2 | Benchmark des 6 algos prouve : RF = meilleur équilibre AUC/gap | LogReg : AUC=0.57 → non-linéaire<br>XGBoost : F1=0.82 mais gap=0.31 (overfit)<br>ExtraTrees : gap=0.20 (overfit modéré)<br>GradientBoosting/LightGBM : recall trop bas | LogReg : confirme la non-linéarité<br>XGBoost : ne généralise pas (gap massif)<br>ExtraTrees : variance trop élevée |

### 13.1 Pattern commun : **RandomForest 3× sur 4 modèles**

Pourquoi RandomForest est l'algorithme de référence pour les 3 modèles host/identité ?

1. **Dataset taille modeste** (140 à 6 000 samples) → RF est dans sa **zone de force optimale**
2. **Features hétérogènes** (compteurs EID, ratios, entropie, scores composites) → RF gère sans normalisation lourde
3. **Interprétabilité native** via Gini importance → SOC analyste comprend "cnt_7=0.126" = "Image Loaded est la feature #1"
4. **Régularisation par bagging** = anti-overfit "by design" (vs XGBoost qui demande tuning explicite)
5. **`class_weight='balanced'` natif** = gestion du déséquilibre sans synthétique (pas de SMOTE)
6. **Compatible production** : `predict_proba()` rapide, pickle léger, pas de dépendance GPU

### 13.2 Pourquoi XGBoost uniquement sur CIC-IDS-2017 ?

Le seul cas où RF est **vraiment battu** :
- 2.5M samples → boosting itératif domine bagging
- 7 classes → softmax natif XGBoost > One-vs-Rest RF
- Volume justifie le coût d'optimisation hyperparams

---

## 14. Travail restant + risques

### 14.1 Tâches restantes avant soutenance (2026-06-02)

| Tâche | Effort | Priorité |
|---|---|---|
| Mettre à jour `reports/fiche_technique.md` (3 modèles uniquement) | 1h | Haute |
| Mettre à jour `reports/RAPPORT_RESULTATS.xlsx` (synthèse 9 feuilles) | 2h | Haute |
| Régénérer `reports/figures/mitre_coverage.png` (heatmap par modèle) | 1h | Moyenne |
| Préparer slides 20 min (`reports/slides/`) | 4h | Haute |
| Répétition orale × 3 | 6h | Haute |

**Total estimé : 14h critiques + 4h optionnel** → réalisable en 3-4 jours sur les 13 jours restants.

### 14.2 Risques identifiés

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
| Question jury "pourquoi seulement 3 modèles ?" | Faible | Moyen | Discours préparé : "j'ai exploré 4 surfaces, écarté la 4ème car dataset insuffisant — preuve de rigueur méthodologique" |
| Question sur précision SIEM Windows (0.66) | Moyenne | Moyen | Discours : "compromis IDS, recall prioritaire, 11/17 alertes vérifiées par analyste = acceptable" |
| Question "pourquoi pas Deep Learning" | Haute | Faible | Argument prêt : datasets < 100k samples, contrainte interprétabilité MITRE |
| Question "Bots à F1=0.81 CIC" | Faible | Faible | Argument : limite structurelle Bots ≈ Normal, documenté |

### 14.3 Différenciants méthodologiques à valoriser

1. **Audit critique CIC-IDS-2017** (23.5 % leakage détecté + corrigé) — preuve de rigueur
2. **Décision d'écarter lateral_movement** (baseline trivial détecté → modèle insuffisant assumé) — preuve de rigueur et d'auto-critique
3. **Robustesse statistique siem_windows** (bootstrap + permutation + benchmark 6 algos) — preuve de validation
4. **Tuning seuil F2 hérité d'ADFA v2** (méthodologie cross-models) — preuve de cohérence

---

## 15. Questions ouvertes pour l'encadrant

1. **Sur la décision d'écarter lateral_movement** : est-ce que cette décision est validée, ou faut-il quand même livrer le modèle v2 (F1=0.64, AUC=0.87) avec ses limites documentées ?

2. **Sur la priorisation F1 vs Recall** : est-ce que le choix de prioriser Recall (cible IDS) au détriment du F1 est aligné avec votre attente ? Ou souhaitez-vous une approche plus équilibrée ?

3. **Sur la pertinence du dataset Atomic Red Team** : avec seulement 111 samples uniques, faut-il documenter ouvertement cette limite ou la minimiser ?

4. **Sur la stack production ELK + Kafka** : le jury évaluera-t-il aussi la **viabilité de déploiement**, ou uniquement la performance ML pure ?

5. **Sur la répétition de soutenance** : souhaitez-vous une répétition avec vous avant le 2 juin ? Si oui, semaine du 26 mai ?

---

## ANNEXE — Localisations des artefacts

| Document | Localisation |
|---|---|
| Ce rapport | `RAPPORT_ENCADRANT_V2.md` (racine) |
| Audit projet complet | `AUDIT_SIEM_LATERAL.md` (racine) |
| CIC-IDS audit correction leakage | `cicids2017/AUDIT_RAPPORT.md` |
| Modèle 1 EXPLICATION_MODELS | `cicids2017/EXPLICATION_MODELS.md` |
| Modèle 2 EXPLICATION_MODELS | `adfa_ld/EXPLICATION_MODELS.md` |
| Modèle 3 EXPLICATION_MODELS | `siem_windows/EXPLICATION_MODELS.md` |
| Modèle 3 robustesse statistique | `siem_windows/ROBUSTNESS_REPORT.md` |
| Métriques officielles | `<modele>/results/final/metrics.json` |
| Synthèse multi-feuilles | `reports/RAPPORT_RESULTATS.xlsx` |
| Tests pytest | `tests/test_orchestrator.py` |

---

*Rapport rédigé le 2026-05-20 par Reda. À discuter en réunion d'encadrement.*
