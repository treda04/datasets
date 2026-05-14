# EXPLICATION COMPLETE DU PROJET — PFE-SOC-ML

**Auteur:** Reda Taous | UIR, 5ème année Cybersécurité  
**Entreprise d'accueil:** Data Protect  
**Date de soutenance:** 2026-06-02  
**Date de rédaction:** 2026-05-14

---

## TABLE DES MATIERES

1. [Vision globale du projet](#1-vision-globale)
2. [Architecture système](#2-architecture-système)
3. [Les 4 modèles ML — Détail complet](#3-les-4-modèles-ml)
4. [Structure des dossiers — A à Z](#4-structure-des-dossiers)
5. [Pipelines DATA — Logique détaillée](#5-pipelines-data)
6. [Orchestrateur & Production](#6-orchestrateur--production)
7. [État actuel & Problèmes identifiés](#7-état-actuel--problèmes)
8. [Plan de refactoring](#8-plan-de-refactoring)

---

## 1. VISION GLOBALE

### Qu'est-ce que ce projet ?

Un système de **détection d'intrusions multi-surface** basé sur du Machine Learning supervisé, intégré dans un environnement SIEM (Security Information and Event Management).

L'idée centrale : au lieu d'un seul modèle ML qui essaie de tout détecter, on a **4 modèles spécialisés** qui couvrent chacun une surface d'attaque différente, puis un **orchestrateur** qui corrèle leurs alertes.

### Les 4 surfaces d'attaque

| Surface | Ce que ça surveille | Dataset utilisé |
|---|---|---|
| **Linux Host** | Appels système (syscalls) | ADFA-LD (UNSW 2012) |
| **Réseau** | Flux réseau (NetFlow) | CIC-IDS-2017 (UNB) |
| **Windows Host** | Événements Windows + Sysmon | OTRF Mordor APT29 |
| **Mouvement latéral** | Auth Windows + Sysmon | Atomic Red Team (OTRF) |

### Flux de données global

```
Hôtes Windows (Sysmon + Winlogbeat)
         ↓
Kafka Broker (192.168.94.132:9092)
    Topic: windows-raw-logs
         ↓
live_detection.py (Service ML en temps réel)
    ├── Modèle ADFA (Linux syscalls)
    ├── Modèle CIC-IDS (Réseau)
    ├── Modèle SIEM Windows (Events Windows)
    └── Modèle Latéral (Auth + Sysmon)
         ↓
    Corrélation multi-modèles + pondération
         ↓
Kafka Topic: ml-alerts
         ↓
Logstash (Pipeline d'enrichissement)
    ├── Parsing des dates
    ├── Mapping de sévérité (Low/Med/High/Critical)
    └── Tagging MITRE ATT&CK
         ↓
Elasticsearch (index ml-detections-*)
    ├── Indexation normale
    └── Score ≥ 0.85 → Webhook TheHive
         ↓
Kibana Dashboard + TheHive (gestion incidents)
```

---

## 2. ARCHITECTURE SYSTÈME

### Infrastructure (Docker Compose)

```yaml
Services:
  - Zookeeper (coordination Kafka)
  - Kafka (message broker, topics: windows-raw-logs, ml-alerts)
  - Elasticsearch 8.11.3 (stockage des alertes)
  - Kibana 8.11.3 (visualisation)
  - Logstash 8.11.3 (enrichissement des alertes)
```

### Pipeline complète (de bout en bout)

```
1. COLLECTE
   Sysmon/Winlogbeat → JSON → Kafka topic "windows-raw-logs"

2. INFERENCE ML (live_detection.py)
   - Consomme Kafka
   - Crée une fenêtre glissante de 5 min par hôte (HostWindow class)
   - Extrait les features (extract_siem_features)
   - Lance les 4 modèles en parallèle
   - Calcule un score pondéré
   - Si score > threshold → produit dans "ml-alerts"

3. ENRICHISSEMENT (Logstash)
   - Reçoit de "ml-alerts"
   - Ajoute timestamp ISO8601
   - Mappe score → sévérité
   - Ajoute tags MITRE ATT&CK
   - Envoie vers Elasticsearch

4. STOCKAGE & VISUALISATION
   - Elasticsearch indexe les alertes
   - Kibana affiche les dashboards
   - TheHive crée les incidents (si score ≥ 0.85)
```

---

## 3. LES 4 MODÈLES ML

### 3.1 ADFA-LD v2 — Détection Linux (Syscalls)

**Objectif:** Détecter des attaques Linux en analysant les séquences d'appels système.

**Dataset:** ADFA-LD (Australian Defence Force Academy - Linux Dataset)
- 6 000+ fichiers de traces syscalls
- Familles d'attaques : Adduser, Hydra, Meterpreter, Java_Meterpreter, Web_Shell
- Créé en 2012 (UNSW Sydney) — limitation connue : dataset ancien

**Pipeline DATA:**
```
Fichiers ADFA-LD (1 fichier = 1 séquence de syscalls)
    ↓ preprocess_adfa_v2.py
1. Lecture de chaque fichier → séquence de numéros syscall
2. Conversion en chaîne de caractères (ex: "2 3 4 5 2 3...")
3. CountVectorizer avec analyzer='word', ngram_range=(3,3), max_features=500
   → Trigrammes : "2 3 4", "3 4 5", etc. (500 les plus fréquents)
4. Séparation train/test (80/20, stratifiée)
5. Vectorizer FIT uniquement sur train → transform sur train et test
    ↓ train_adfa_v2.py
6. Random Forest (200 arbres, random_state=42)
7. CalibratedClassifierCV (method='isotonic') pour calibrer les probabilités
8. Sauvegarde: rf_adfa_model.pkl + adfa_vectorizer.pkl
```

**Métriques finales:**
- F1: **0.957** | AUC: **0.979**
- CV (5-fold): 0.9486 ± 0.0080
- Gap CV-test: < 0.01 ✅

**Localisation:** `adfa_ld/`

---

### 3.2 CIC-IDS-2017 v2 — Détection Réseau (NetFlow)

**Objectif:** Classifier les flux réseau bidirectionnels (Brute Force, Normal, Port Scan, Web Attacks).

**Dataset:** Canadian Institute for Cybersecurity, Intrusion Detection System 2017
- 685 MB, ~500 000 lignes de flux réseau
- 80+ features : durée, octets, paquets, flags TCP, ratios...
- 4 classes : Brute Force, Normal, Port Scanning, Web Attacks

**Pipeline DATA:**
```
cicids2017.csv (685 MB)
    ↓ preprocess_v2.py
1. Lecture du CSV
2. Nettoyage : suppression des NaN/Inf
3. Encodage des labels (LabelEncoder)
4. Séparation train/test (80/20, stratifiée)
5. SMOTE (Synthetic Minority Over-sampling) sur X_TRAIN SEULEMENT
   → Équilibrage des classes (important: pas appliqué sur test !)
6. StandardScaler (fit sur train, transform train+test)
7. Sauvegarde: X_train_processed.csv, X_test_processed.csv, y_train/test.csv
    ↓ train_xgboost_v2.py
8. XGBoost (100 estimators, max_depth=6, learning_rate=0.1)
9. Sauvegarde: xgb_model.pkl
```

**Métriques finales:**
- F1: **0.9939**
- CV: 0.9996 ± 0.00002

**⚠ Attention (limitation connue):** F1=0.9939 peut signifier "shortcut learning" sur les features réseau
(le modèle reconnaît peut-être le style des captures plutôt que les vrais patterns).

**Localisation:** `cicids2017/`

---

### 3.3 SIEM Windows v3/v4 — Détection Hôte Windows

**Objectif:** Détecter des comportements d'attaque APT (Advanced Persistent Threat) sur Windows via les événements de sécurité et Sysmon.

**Dataset:** OTRF Mordor — APT29 Emulation (2 jours)
- Day1: ~196K événements (367 MB) → utilisé pour TRAIN
- Day2: ~588K événements (1.6 GB) → utilisé pour TEST
- 4 hôtes: SCRANTON, DWIGHT, MICHAEL, THEONLY
- Événements: Security (4624, 4625, 4688, 4768...) + Sysmon (1, 3, 7, 10, 11...)

**Pipeline DATA v4 (la version finale):**
```
siem_dataset/data/otrf_datasets/datasets/compound/apt29/
    ↓ preprocess_siem_v4.py
1. Lecture des JSON Mordor (format EVTX exporté)
2. Extraction des champs: EventID, hostname, timestamp, username...
3. EDA sur 175 EventIDs → sélection chi² (top discriminants)
   Résultat: 44 EventIDs retenus (vs 24 en v3)
4. Fenêtrage glissant: 5 min de fenêtre, 1 min de pas (sliding window)
   Par hôte → chaque fenêtre = 1 sample
5. Features extraites par fenêtre:
   - total_events, events_per_minute
   - count_<eventid> pour chaque EventID retenu (ex: count_4624)
   - brute_force_score, lateral_move_score, persistence_score...
   - entropy_eventids (diversité des EventIDs)
   - distinct_eventids
   - network_ratio, logon_ratio
   - rolling features (mean/std/delta sur 3 fenêtres)
   Total: 152 features → pruning → 95 features finales
6. Label: 1 si la fenêtre contient des événements de l'attaque APT29
7. Séparation TEMPORELLE: day1=train, day2=test
8. Sauvegarde: train.parquet, test.parquet
    ↓ train_siem_v4.py
9. Comparaison de 5 algorithmes: RF, XGBoost, LightGBM, Stacking
   → LightGBM gagne
10. CalibratedClassifierCV (isotonic) pour calibrer
11. Leave-One-Host-Out CV (LOOHO): train sur 3 hôtes, test sur 1, répéter 4 fois
12. Sauvegarde: lgbm_siem_model.pkl, siem_scaler.pkl, feature_columns.json, threshold.json
```

**Métriques v3 (RF):** F1=0.667 | AUC=0.573 | LOOHO: 0.669 ± 0.014  
**Métriques v4 (LightGBM):** F1=**0.7528** | AUC=**0.7231** | LOOHO: 0.693 ± 0.062

**Pourquoi c'est difficile:**
- Petit dataset (276 fenêtres totales)
- 4 hôtes avec comportements différents → drift inter-hôte
- APT29 est discret (peu d'events par fenêtre)

**Localisation:** `siem_windows/`

---

### 3.4 Lateral Movement v2 — Détection Mouvement Latéral

**Objectif:** Détecter spécifiquement les techniques de mouvement latéral (déplacement d'un compte ou hôte à un autre).

**Dataset:** OTRF Atomic Red Team — collections Windows
- **Positifs (~30 zips):** Scénarios Empire, Covenant, Mimikatz, schtasks, etc.
- **Négatifs:** Discovery + Collection tactics (comportements légitimes mais suspects)
- Format: JSON (events Windows + Sysmon)

**Pipeline DATA v2:**
```
siem_dataset/data/otrf_datasets/datasets/atomic/windows/lateral_movement/ (et autres)
    ↓ preprocess_lateral_v2.py
1. Extraction des ZIP Atomic Red Team
2. Lecture des JSON events (Sysmon: EventID 1, 3, 7, 10, 11...)
3. Fenêtrage 5 min par dataset (chaque ZIP = 1 scénario = 1 technique)
4. Features: UNIQUEMENT counts d'EventIDs (pas de features dérivées du label !)
   → c'est le correctif principal de v2 vs v1
5. Label: 1 pour lateral movement, 0 pour discovery/collection
6. GroupShuffleSplit par technique (pas split aléatoire !)
   → train sur certaines techniques, test sur d'autres = vraie généralisation
7. Sauvegarde: train.parquet, test.parquet
    ↓ train_lateral_v2.py
8. Random Forest + CalibratedClassifierCV (isotonic)
9. Évaluation par technique (per-technique F1)
10. Sauvegarde: rf_lateral_model.pkl, lateral_scaler.pkl, etc.
```

**Métriques v2:**
- F1 (attack): **0.836** | F1 (macro): **0.681** | AUC: **0.694**
- Feature importance max: 0.085 (entropy_eventids)

**⚠ Problème v1 (RESOLU en v2):**
- V1 avait F1=1.00 → FAUX POSITIF
- Cause: features dérivées des permissions (qui étaient des proxy du label)
- V2: only EventID counts → généralisation prouvée

**Localisation:** `lateral_movement/`

---

## 4. STRUCTURE DES DOSSIERS

```
datasets/                              ← Racine du projet
│
├── adfa_ld/                           ← Modèle 1: Linux Syscalls
│   ├── data/
│   │   ├── ADFA-LD/                   Fichiers bruts (6K+ fichiers .txt)
│   │   ├── adfa_processed.csv         Features extraites (v1)
│   │   └── processed_v2/             Features v2 (trigrammes)
│   ├── eda/
│   │   └── eda_adfa.ipynb             Analyse exploratoire
│   ├── preprocessing/
│   │   └── preprocess_adfa_v2.py      Script preprocessing (trigrammes + vectorizer)
│   ├── models/
│   │   ├── rf_adfa_model.pkl          Modèle entraîné
│   │   └── adfa_vectorizer.pkl        CountVectorizer sauvegardé
│   ├── results_v2/                    Métriques, courbes ROC/PR
│   ├── saved_models/                  Artifacts pour l'orchestrateur
│   └── README.md
│
├── cicids2017/                        ← Modèle 2: Réseau NetFlow
│   ├── data/
│   │   ├── cicids2017.csv             Dataset brut (685 MB)
│   │   ├── X_train_processed.csv      Post-SMOTE + scaled
│   │   ├── X_test_processed.csv
│   │   ├── y_train_processed.csv
│   │   └── y_test_processed.csv
│   ├── eda/
│   │   └── eda_analysis.ipynb
│   ├── preprocessing/
│   │   └── preprocess_v2.py
│   ├── models/
│   │   └── xgb_model.pkl
│   ├── results/
│   │   └── classification_report.txt
│   └── README.md
│
├── siem_windows/                      ← Modèle 3: Windows Events
│   ├── data/
│   │   ├── raw/
│   │   │   ├── day1/                  Événements APT29 jour 1 (train)
│   │   │   └── day2/                  Événements APT29 jour 2 (test)
│   │   ├── processed/                 train.parquet, test.parquet (v3)
│   │   └── processed_v4/             train.parquet, test.parquet (v4)
│   ├── preprocessing/
│   │   ├── preprocess_siem.py         v3: 24 EventIDs, features basiques
│   │   └── preprocess_siem_v4.py      v4: 44 EventIDs, rolling features
│   ├── training/
│   │   ├── train_siem.py              v3: Random Forest
│   │   └── train_siem_v4.py           v4: LightGBM (winner)
│   ├── evaluation/
│   │   └── generate_siem_results.py
│   ├── saved_models/                  v3 artifacts (pkl, json)
│   ├── saved_models_v4/              v4 artifacts (pkl, json)
│   ├── results/ & results_v4/
│   ├── README.md
│   ├── model_card.md
│   └── eda_siem_visualizer.py         Analyse chi² sur 175 EventIDs
│
├── lateral_movement/                  ← Modèle 4: Mouvement Latéral
│   ├── data/
│   │   ├── processed/                 v1 (bugué, F1=1.00 faux)
│   │   └── processed_v2/             v2 (correct, GroupShuffleSplit)
│   ├── preprocessing/
│   │   └── preprocess_lateral_v2.py
│   ├── training/
│   │   └── train_lateral_v2.py
│   ├── evaluation/
│   │   └── generate_lateral_results.py
│   ├── saved_models/                  v1 (ne pas utiliser!)
│   ├── saved_models_v2/              v2 (utiliser celui-ci)
│   ├── results/ & results_v2/
│   ├── README.md
│   └── eda_visualizer.py
│
├── src/orchestrator/                  ← Orchestrateur ML
│   ├── soc_orchestrator.py            Classe principale SOCOrchestrator
│   ├── mitre_mapping.py               46 EventID → MITRE techniques
│   └── __init__.py
│
├── live_detection/                    ← Service de production (Kafka)
│   ├── live_detection.py              Consumer Kafka + inférence + producer
│   └── README.md
│
├── integration/                       ← Config ELK Stack
│   ├── logstash/
│   │   └── ml-alerts-pipeline.conf    Pipeline Logstash
│   └── elasticsearch/
│       └── ml-detections-mapping.json Index template ES
│
├── tests/                             ← Tests unitaires
│   ├── test_orchestrator.py           16 tests pytest
│   └── __init__.py
│
├── scripts/                           ← Scripts utilitaires
│   ├── preprocess_*.py
│   ├── train_*.py
│   ├── mitre_evaluation.py / _v4.py
│   ├── siem_eda.py
│   ├── siem_loho_cv.py / _v4.py
│   ├── lateral_innovations.py
│   ├── run_demo.py                    Demo: replay kill chain 128 events
│   ├── build_excel_report.py          Rapport Excel multi-onglets
│   ├── setup_models_dir.py
│   └── check_artifacts.py
│
├── notebooks/                         ← Jupyter
│   └── 01_mitre_evaluation.ipynb
│
├── reports/                           ← Livrables soutenance
│   ├── README.md
│   ├── LIMITATIONS.md                 7 limitations + mitigations
│   ├── fiche_technique.md
│   ├── RAPPORT_RESULTATS.xlsx         Workbook 9 onglets
│   ├── mitre_metrics.csv
│   ├── slides/outline.md              Plan présentation 20 min
│   └── figures/mitre_coverage.png     Heatmap MITRE
│
├── data/demo/                         ← Demo data
│   ├── attack_scenario.jsonl          128 events, kill chain APT 60s
│   └── run_output.jsonl               Exemple de sortie
│
├── siem_dataset/                      ← Datasets bruts OTRF
│   └── data/otrf_datasets/
│       ├── datasets/
│       │   ├── compound/
│       │   │   ├── apt29/day1/        367 MB, 196K events
│       │   │   └── apt29/day2/        1.6 GB, 588K events
│       │   └── atomic/windows/
│       │       ├── lateral_movement/  ~30 ZIP de scénarios
│       │       ├── discovery/
│       │       └── credential_access/
│       ├── docs/
│       ├── _metadata/                 YAML metadata par dataset
│       └── scripts/
│
├── models/                            ← Aggregation des modèles finaux
│   ├── cicids/
│   ├── adfa/
│   ├── siem/
│   └── lateral/
│
├── docs/                              ← Documentation technique
│   ├── AUDIT_PROJET_COMPLET.md        Audit complet (2026-05-09)
│   ├── RAPPORT_RESULTATS_2026-05-14.md
│   ├── PLAN_RECONSTRUCTION_PFE.md
│   ├── SESSION_2026-05-09.md
│   └── SESSION_2026-05-10.md
│
├── docker-compose.yml                 ← Stack infra
├── requirements.txt                   ← 16 dépendances Python
├── README.md                          ← README principal
├── .venv/                             ← Environnement Python
└── .git/                              ← Historique git
```

---

## 5. PIPELINES DATA

### Logique commune à tous les pipelines

Chaque pipeline suit le même schéma :

```
1. COLLECTE      : Lire les données brutes (CSV, JSON, fichiers texte, ZIP)
2. NETTOYAGE     : NaN, Inf, encodage, normalisation des colonnes
3. FEATURE ENG.  : Extraction des features (fenêtrage, n-grammes, counts...)
4. SPLIT         : Séparation train/test AVANT tout oversampling
5. OVERSAMPLING  : SMOTE sur train seulement (si classes déséquilibrées)
6. SCALING       : StandardScaler fit sur train, transform train+test
7. SAUVEGARDE    : CSV/Parquet + pkl pour vectorizer/scaler
```

### Anti-leakage — Règles appliquées

| Risque | Solution appliquée |
|---|---|
| SMOTE sur tout le dataset | SMOTE uniquement après split, sur X_train |
| Vectorizer fit sur test | CountVectorizer fit sur X_train seulement |
| Features dérivées du label | Supprimées en v2 (lateral movement) |
| Split aléatoire sur séries temporelles | Split temporel (day1/day2) pour SIEM |
| Généralisation sur même technique | GroupShuffleSplit par technique (lateral) |
| Scaler fit sur test | Toujours fit sur train uniquement |

### Détail: Fenêtrage glissant (SIEM & Lateral)

```python
# Principe du sliding window
window_size = 5 * 60  # 5 minutes en secondes
step_size   = 1 * 60  # pas de 1 minute

for host in hosts:
    events_host = events[events['hostname'] == host]
    for t_start in range(t_min, t_max, step_size):
        t_end = t_start + window_size
        window = events_host[(t >= t_start) & (t < t_end)]
        features = extract_features(window)  # counts d'EventIDs, entropie, etc.
        label = 1 if window contains attack events else 0
        samples.append((features, label))
```

Chaque fenêtre de 5 minutes = 1 sample dans le dataset ML.

---

## 6. ORCHESTRATEUR & PRODUCTION

### SOCOrchestrator (src/orchestrator/soc_orchestrator.py)

```python
# Structure de la classe
class SOCOrchestrator:
    models = {
        'adfa':    ModelBundle(model, scaler, feature_cols, threshold)
        'cicids':  ModelBundle(model, scaler, feature_cols, threshold)
        'siem':    ModelBundle(model, scaler, feature_cols, threshold)
        'lateral': ModelBundle(model, scaler, feature_cols, threshold)
    }

    def route(self, source: str) -> str:
        # Mappe la source des logs vers le bon modèle
        # 'linux_syscall' → 'adfa'
        # 'netflow'       → 'cicids'
        # 'windows_event' → 'siem'
        # 'auth_event'    → 'lateral'

    def predict(self, event: dict) -> dict:
        # 1. Détermine le modèle via route()
        # 2. Vectorize les features
        # 3. Calcule predict_proba()
        # 4. Compare au threshold
        # 5. Retourne {score, is_alert, model_key, mitre_tags}

    def correlate(self, alerts: list, window_seconds=300) -> dict:
        # Si 2+ modèles alertent dans une fenêtre de 5 min
        # → corrélation = score amplifié
        # → indicateur d'attaque coordonnée

    def run_stream(self, events: list) -> list:
        # Traitement batch: liste d'events → liste d'alertes
```

### live_detection.py (Service Kafka en temps réel)

```python
# Logique principale
consumer = KafkaConsumer('windows-raw-logs', ...)
producer = KafkaProducer('ml-alerts', ...)

host_windows = {}  # dict: hostname → HostWindow (fenêtre glissante)

for message in consumer:
    event = json.loads(message.value)
    hostname = event['hostname']

    # Mise à jour de la fenêtre de l'hôte
    host_windows[hostname].add_event(event)

    # Si fenêtre complète (5 min d'events accumulés)
    if host_windows[hostname].is_ready():
        features = extract_siem_features(host_windows[hostname])
        scores = {}

        # Lance les 4 modèles
        for model_key, bundle in models.items():
            score = bundle.model.predict_proba(features)[0][1]
            scores[model_key] = score

        # Score final = moyenne pondérée
        final_score = weighted_average(scores, weights)

        if final_score > threshold:
            alert = {
                'score': final_score,
                'hostname': hostname,
                'timestamp': now(),
                'model_scores': scores,
                'mitre_tags': get_mitre_tags(features)
            }
            producer.send('ml-alerts', alert)
```

### Mapping MITRE ATT&CK (src/orchestrator/mitre_mapping.py)

```python
# 46 mappings EventID → technique MITRE
EVENT_TO_TECHNIQUE = {
    4625: ('T1110', 'Brute Force', 'Credential Access'),
    4688: ('T1059', 'Command and Scripting Interpreter', 'Execution'),
    4768: ('T1558.003', 'Kerberoasting', 'Credential Access'),
    4776: ('T1003.002', 'SAM', 'Credential Access'),
    # EventIDs Sysmon
    1:    ('T1059', 'Command Execution', 'Execution'),
    3:    ('T1071', 'Network Connection', 'C2'),
    # ... 40+ autres
}
```

---

## 7. ÉTAT ACTUEL & PROBLÈMES

### Ce qui marche bien ✅

| Composant | Status |
|---|---|
| ADFA-LD v2 | Complet, métriques solides (F1=0.957) |
| CIC-IDS-2017 v2 | Complet, métriques excellentes (F1=0.994) |
| SOCOrchestrator | Complet, 16 tests passent |
| Mapping MITRE | 46 mappings, complet |
| Integration ELK | Config Logstash + ES mapping présents |
| Demo scenario | 128 events kill chain |
| Documentation | README, LIMITATIONS, fiche_technique |

### Ce qui est chaotique / problématique ⚠️

**SIEM Windows:**
- V3 ET V4 coexistent avec des fichiers similaires (duplication)
- `saved_models/` et `saved_models_v4/` → lequel utiliser ?
- `preprocess_siem.py` et `preprocess_siem_v4.py` → lequel lancer ?
- `results/` et `results_v4/` → quelle version est "officielle" ?
- AUC faible (0.573 en v3, 0.678 en v4) → modèle fragile

**Lateral Movement:**
- `saved_models/` (v1, BUGUE) existe encore → risque de confusion
- `processed/` (v1 data) existe encore → risque d'utiliser les mauvaises données
- V1 avait F1=1.00 (data leakage) → ne jamais utiliser les artifacts v1

**Organisation générale:**
- Vieilles versions (v1, v2, v3) jamais nettoyées
- Scripts dupliqués dans `scripts/` et dans les sous-dossiers
- Pas de point d'entrée unique clair (quel script lancer d'abord?)
- `data/raw/` vs `siem_dataset/` → duplication possible de données

### Métriques par modèle (résumé)

| Modèle | Algo | F1 Test | AUC | LOOHO F1 | Gap CV-test |
|---|---|---|---|---|---|
| ADFA-LD v2 | RF + Calibrated | 0.957 | 0.979 | 0.949 ± 0.008 | < 0.01 ✅ |
| CIC-IDS-2017 v2 | XGBoost | 0.994 | — | 0.9996 ± 0.00002 | < 0.01 ✅ |
| SIEM Windows v4 | LightGBM | 0.753 | 0.723 | 0.693 ± 0.062 | 0.06 ✅ |
| Lateral v2 | RF + Calibrated | 0.836 | 0.694 | 0.919 ± 0.028 | 0.08 ✅ |

---

## 8. PLAN DE REFACTORING

### Objectif du refactoring

Recréer la partie DATA + ML **from scratch** sur une nouvelle branche, avec :
- Structure claire et sans duplication
- Un seul script par étape (pas de v1/v2/v3 qui coexistent)
- Pipelines reproductibles de A à Z
- Métriques documentées et validées
- Pas d'artifacts inutiles

### Structure cible (nouvelle branche)

```
datasets/
├── pipeline/
│   ├── adfa/
│   │   ├── preprocess.py     → UN seul script
│   │   ├── train.py          → UN seul script
│   │   └── evaluate.py
│   ├── cicids/
│   │   ├── preprocess.py
│   │   ├── train.py
│   │   └── evaluate.py
│   ├── siem/
│   │   ├── preprocess.py
│   │   ├── train.py
│   │   └── evaluate.py
│   └── lateral/
│       ├── preprocess.py
│       ├── train.py
│       └── evaluate.py
├── artifacts/                ← Modèles finaux seulement
│   ├── adfa/
│   ├── cicids/
│   ├── siem/
│   └── lateral/
├── data/                     ← Données intermédiaires
│   ├── adfa/processed/
│   ├── cicids/processed/
│   ├── siem/processed/
│   └── lateral/processed/
└── results/                  ← Métriques + figures
    ├── adfa/
    ├── cicids/
    ├── siem/
    └── lateral/
```

### Étapes du refactoring

1. **Créer nouvelle branche:** `git checkout -b refactor/data-ml-clean`
2. **ADFA-LD:** Réécrire preprocess.py + train.py clean
3. **CIC-IDS-2017:** Réécrire preprocess.py + train.py clean
4. **SIEM Windows:** Réécrire en v4 uniquement (LightGBM), structure propre
5. **Lateral Movement:** Réécrire en v2 uniquement, structure propre
6. **Tests:** Valider les métriques attendues
7. **Artifacts:** Copier uniquement les modèles finaux dans `artifacts/`
8. **Documentation:** Mettre à jour README avec instructions claires

### Métriques attendues (à valider)

| Modèle | F1 attendu | AUC attendu |
|---|---|---|
| ADFA-LD | ≥ 0.95 | ≥ 0.97 |
| CIC-IDS-2017 | ≥ 0.99 | — |
| SIEM Windows | ≥ 0.70 | ≥ 0.65 |
| Lateral Movement | ≥ 0.65 macro | ≥ 0.65 |

---

## GLOSSAIRE

| Terme | Définition |
|---|---|
| **SIEM** | Security Information and Event Management — système de centralisation des logs de sécurité |
| **APT** | Advanced Persistent Threat — attaque sophistiquée, longue durée |
| **MITRE ATT&CK** | Framework de taxonomie des techniques d'attaque |
| **EventID** | Identifiant d'un type d'événement Windows (ex: 4625 = échec de connexion) |
| **Sysmon** | Outil Microsoft qui génère des événements système détaillés (processus, réseau...) |
| **Sliding window** | Fenêtre glissante : agrégation des events sur N minutes, pas de M minutes |
| **LOOHO CV** | Leave-One-Host-Out Cross-Validation : train sur N-1 hôtes, test sur 1 |
| **SMOTE** | Synthetic Minority Over-sampling Technique : génère des exemples synthétiques pour équilibrer les classes |
| **Calibration** | Ajustement des probabilités pour qu'elles correspondent à la réalité (0.7 = 70% chance vraie) |
| **Data leakage** | Contamination du test set par des informations du train set → métriques gonflées |
| **GroupShuffleSplit** | Split qui respecte des groupes (ici: techniques d'attaque) pour éviter la fuite |
| **Trigramme** | Séquence de 3 éléments consécutifs (ex: "syscall1 syscall2 syscall3") |
| **F1 macro** | Moyenne des F1 de chaque classe (équitable pour les classes déséquilibrées) |
| **AUC-ROC** | Area Under the Curve — mesure la capacité de discrimination du modèle |
| **Kafka** | Plateforme de streaming distribué (message broker) |
| **TheHive** | Plateforme open-source de gestion des incidents de sécurité |
| **NetFlow** | Protocole/format de description des flux réseau (src IP, dst IP, ports, bytes...) |

---

*Ce fichier a été généré le 2026-05-14 pour servir de base au refactoring from scratch de la partie DATA & ML.*
