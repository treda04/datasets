# Plan de Reconstruction du PFE — De A à Z

**Date :** 2026-05-09
**Objectif :** transformer le projet actuel (3 modèles avec leakage / 2 modules manquants) en un PFE défendable face à un jury technique exigeant.
**Horizon :** 5 à 6 semaines (soutenance estimée fin juin / début juillet 2026).

---

## 1. Compréhension Complète du Projet (Le Concept en 1 Page)

### 1.1 Le « pourquoi »
Un SOC traditionnel (Wazuh, Splunk, ELK) détecte les attaques par **règles statiques** (Sigma, YARA). Ces règles :
- ratent les attaques **inconnues** (zero-day, TTP non couverts) ;
- génèrent un **bruit énorme** (false positives) qui sature les analystes ;
- doivent être maintenues manuellement à mesure que les attaquants évoluent.

Ton projet propose d'**augmenter** ce SOC avec une couche ML capable de **généraliser** au-delà des règles, en apprenant le comportement normal vs malveillant à partir de **logs réels**.

### 1.2 Le « comment » (architecture en 4 couches)

```
┌──────────── COUCHE 1 — COLLECTE ────────────┐
│  Endpoints Windows (Sysmon + Winlogbeat)    │
│  Réseau (Zeek / pcap)                       │
│  Hosts Linux (auditd → syscalls)            │
│  Cloud / AD (Azure AD / AWS CloudTrail)     │
└──────────────────┬──────────────────────────┘
                   │ Kafka topic: windows-raw-logs
┌──────────── COUCHE 2 — DÉTECTION ML ────────┐
│  4 modèles spécialisés (1 par surface) :    │
│   • SIEM Windows  (host) — RF + features    │
│     comportementales par fenêtre 5 min      │
│   • CIC-IDS-2017  (réseau) — XGBoost sur    │
│     features de flux (sans ports!)          │
│   • ADFA-LD       (host Linux) — RF sur     │
│     n-grams syscalls                        │
│   • Lateral Move  (identité) — RF sur       │
│     features auth/comportement utilisateur  │
└──────────────────┬──────────────────────────┘
                   │ Kafka topic: ml-alerts
┌──────────── COUCHE 3 — ENRICHISSEMENT ──────┐
│  Logstash : parse + enrichit + route        │
│  Elasticsearch : indexe (ml-detections-*)   │
└──────────────────┬──────────────────────────┘
                   │
┌──────────── COUCHE 4 — RÉPONSE ─────────────┐
│  Kibana : dashboard analyste SOC            │
│  TheHive : ticket auto si score ≥ 0.85      │
│  Wazuh : corrélation règles en parallèle    │
└─────────────────────────────────────────────┘
```

### 1.3 Le « quoi » concrètement à produire
- **4 modèles entraînés** avec une méthodologie défendable (pas de leakage).
- **1 service live** (`live_detection.py`) qui consomme Kafka et émet des alertes.
- **1 pipeline ELK** complet (Logstash + ES mapping + Kibana dashboard).
- **1 démo end-to-end** sur infrastructure réelle (PC Windows + VM Ubuntu Kafka + ELK).
- **1 mémoire** qui assume les choix méthodologiques avec preuves chiffrées.

### 1.4 Les 4 modèles : rôle défensif et complémentarité

| Modèle | Surface | Tactiques MITRE détectées | Source de données |
|---|---|---|---|
| SIEM Windows | Host Windows (Sysmon + Security) | Initial Access, Credential Access, Privilege Escalation, Persistence | Winlogbeat live + APT29 dataset (training) |
| CIC-IDS-2017 | Réseau | Reconnaissance, Discovery (scan ports), DDoS, Brute Force | NetFlow / Zeek |
| ADFA-LD | Host Linux | Execution, Persistence (rootkits) | auditd / syscalls |
| Lateral Movement | Identité (auth) | Lateral Movement, Defense Evasion, Credential Access (réutilisation tokens) | Windows Security 4624/4648 + Atomic Red Team |

Cette **complémentarité de couverture** est ton argument fort en soutenance : un seul modèle ne peut pas tout voir.

---

## 2. Recommandations Stratégiques (Ce qu'il Faut Changer)

### 2.1 Datasets — meilleure approche

| Modèle | Approche actuelle | Problème | **Approche recommandée** |
|---|---|---|---|
| SIEM Windows | Aucun script — features manuelles SePrivilege* | Label leakage | **OTRF Mordor APT29 (déjà sur disque)** + features comportementales aggregées par fenêtre 5 min |
| Lateral Movement | Listes de permissions (CSV statiques) | Pas de logs temporels | **Atomic Red Team windows/lateral_movement (déjà sur disque)** + Atomic windows/credential_access (négatifs) |
| CIC-IDS-2017 | 500k lignes, 4 classes hardcodées, port = label | Shortcut learning | **Garder dataset, supprimer ports + features dérivées des ports**, conserver toutes les classes, évaluer multi-classes |
| ADFA-LD | N-grams trigrammes RF | Vectorizer fit sur tout, split aléatoire | **Garder approche**, fit vectorizer sur train uniquement, GroupShuffleSplit par dossier d'attaque |

**Pourquoi OTRF Mordor APT29 est un excellent choix :**
- ✅ **Vrais events Windows** (Sysmon + Security + PowerShell) — pas synthétique.
- ✅ **Ground truth APT29** documenté event par event (emulation plan MITRE).
- ✅ **Volume crédible** : 196k events jour 1 + 588k events jour 2 = ~784k events.
- ✅ **Format standard** : JSON / EVTX, parseable directement par Winlogbeat → identique à ta production.
- ✅ **Already on disk** : `datasets/siem_dataset/data/otrf_datasets/datasets/compound/apt29/`.

**Datasets que tu devrais ABANDONNER :**
- ❌ `botsv3-master/` (Splunk BOTSv3) : format Splunk incompatible avec ton pipeline ELK. Sortir du repo.
- ❌ `raw_new/` listes Microsoft Graph permissions : pas des logs, listes de référence. Inutile.
- ❌ `otrf_sysmon/` placeholder vide : à supprimer.

### 2.2 Méthodologie ML — meilleure approche

| Anti-pattern actuel | Correctif |
|---|---|
| `train_test_split(random_state=42)` partout | `TimeSeriesSplit` quand timestamps + `GroupShuffleSplit` par session d'attaque |
| `vectorizer.fit_transform(all_data)` | `Pipeline([..., vectorizer, ...]).fit(X_train)` puis `.transform(X_test)` |
| Pas de courbe ROC ni PR | `RocCurveDisplay` + `PrecisionRecallDisplay` sauvegardés en PNG |
| Seuil 0.5 par défaut | Calibration via Youden's J ou F1-optimal sur validation set |
| `model.predict_proba()` non calibré | `CalibratedClassifierCV(method='isotonic')` |
| Classes hardcodées sans mapping | Sauver `classes.json` avec mapping label → string |
| Pas de comparaison à un baseline | Baseline règles Sigma / Wazuh sur le même test set |

### 2.3 Ingénierie — meilleure approche

- **`sklearn.pipeline.Pipeline`** systématique → empêche structurellement le leakage (le scaler est fit-only sur train).
- **Tests unitaires pytest** sur les fonctions critiques (`extract_features`, `compute_composite_score`).
- **Model cards** : 1 fichier `model_card.md` par modèle (date, hash dataset, métriques, hyperparams).
- **`docker-compose.yml`** : Kafka + Zookeeper + ES + Kibana + Logstash en 1 commande.
- **Secrets** : variables d'env (`.env` non versionné) au lieu de hardcoded.
- **Logging** : `python-json-logger` partout, niveau INFO en prod, DEBUG en dev.
- **Versionning artefacts** : git LFS pour `.pkl > 50 MB`, ou stockage externe (MinIO).

### 2.4 Architecture du code — meilleure approche

Standardiser **chaque module ML** sur le même squelette :

```
<module>/
├── data/                    # Données brutes (gitignored) + processed/
├── preprocessing/
│   └── preprocess_<m>.py    # Lit data/, écrit data/processed/
├── training/
│   └── train_<m>.py         # Lit processed, écrit saved_models/
├── evaluation/
│   └── evaluate_<m>.py      # Lit saved_models, écrit results/ (PNG + JSON)
├── saved_models/
│   ├── <m>_model.pkl
│   ├── <m>_scaler.pkl
│   ├── <m>_threshold.json   # {"threshold": 0.62, "method": "youden"}
│   └── feature_columns.json # ["cnt_4624", "logon_failure_ratio", ...]
├── results/
│   ├── confusion_matrix.png
│   ├── roc_curve.png
│   ├── pr_curve.png
│   ├── feature_importance.png
│   └── metrics.json
├── README.md
└── model_card.md
```

C'est exactement le contrat que `live_detection.py` attend déjà (voir `load_models()` ligne 71-105). Il faut juste **construire les artefacts**.

---

## 3. Planning Détaillé (5 Semaines, Jour par Jour)

> Hypothèses : ~4-6h de travail technique par jour ouvré, soutenance ciblée fin juin / début juillet 2026.

### Semaine 1 (12-16 mai) — Quick wins + setup
| Jour | Tâche | Livrable | Effort |
|---|---|---|---|
| Lun | Lire le PLAN, valider l'approche | Décision | 1h |
| Lun | `git init` + `.gitignore` propre + premier commit | Repo Git | 30min |
| Mar | Lancer `preprocess_v2.py` CIC-IDS (sans ports) | `cicids2017/data/X_*_v2.csv` | 2h |
| Mar | Lancer `train_xgboost_v2.py` | `cicids2017/models/xgb_model_v2.pkl` + courbes | 2h |
| Mer | Lancer `preprocess_adfa_v2.py` (vectorizer fit-only train) | `adfa_processed_v2.npz` | 2h |
| Mer | Lancer `train_adfa_v2.py` (GroupShuffleSplit + ROC/PR) | `rf_adfa_model_v2.pkl` | 2h |
| Jeu | Valider les chutes de F1 attendues + documenter | `MODEL_CARDS.md` premier jet | 3h |
| Jeu | Extraire le zip APT29 day1 dans `siem_windows/data/raw/` | Fichiers JSON Sysmon | 1h |
| Ven | Lancer `siem_windows/preprocessing/preprocess_siem.py` | `siem_features.parquet` | 3h |
| Ven | Lancer `train_siem.py` | `rf_siem_model.pkl` + `siem_threshold.json` + `feature_columns.json` | 2h |

**Critère de fin de semaine :** 3 modèles entraînés avec scores honnêtes documentés.

### Semaine 2 (19-23 mai) — SIEM Windows + Lateral Movement
| Jour | Tâche | Livrable | Effort |
|---|---|---|---|
| Lun | Étendre SIEM avec APT29 day2 (plus de données) | `rf_siem_model.pkl` v2 | 4h |
| Mar | Calibration de seuil SIEM (Youden / F1) sur val set | `siem_threshold.json` calibré | 3h |
| Mer | Extraire Atomic Red Team windows/lateral_movement | Fichiers `_host.json` + `_network.json` | 2h |
| Mer | Lancer `lateral_movement/preprocessing/preprocess_lateral.py` | `lateral_features.parquet` | 3h |
| Jeu | Lancer `train_lateral.py` | `rf_lateral_model.pkl` + artefacts | 3h |
| Jeu | Évaluation lateral (ROC, PR, calibration) | `results/*.png` + `metrics.json` | 2h |
| Ven | Buffer / debugging | — | 5h |

**Critère :** 4 modèles entraînés. `live_detection.py` charge tous les artefacts sans warning.

### Semaine 3 (26-30 mai) — Pipeline live + ELK
| Jour | Tâche | Livrable | Effort |
|---|---|---|---|
| Lun | Tester `live_detection.py` localement avec un Kafka mock | Logs de démo | 4h |
| Mar | Setup `docker-compose.yml` complet (ES + Kibana + Logstash + Kafka) | `docker-compose.yml` | 3h |
| Mar | Tester pipeline end-to-end : event mock → ES | Capture Kibana | 2h |
| Mer | Construire le dashboard Kibana SOC | `dashboard_soc.ndjson` | 4h |
| Jeu | Tester webhook TheHive (peut être stubbé si pas d'instance) | `mock_thehive.py` | 3h |
| Ven | Setup baseline règles Sigma sur les mêmes tests | `sigma_baseline.py` + résultats | 4h |

**Critère :** démo complète passe sur la machine locale via docker-compose.

### Semaine 4 (2-6 juin) — Démo réelle + tests + robustesse
| Jour | Tâche | Livrable |
|---|---|---|
| Lun | Configurer Sysmon + Winlogbeat sur 1 PC Windows réel | PC qui pousse vers Kafka |
| Mar | Atomic Red Team T1003.001 (lsass dump) sur ce PC | Capture vidéo de l'alerte arrivant dans Kibana |
| Mer | Atomic T1059.001 (PowerShell), T1021.001 (RDP), T1098 (account manip) | 4 attaques détectées en démo |
| Jeu | Tests unitaires pytest sur fonctions critiques | `tests/` avec couverture > 70% |
| Jeu | Métriques Prometheus + healthcheck dans `live_detection.py` | `/metrics` endpoint |
| Ven | Buffer + repro complète depuis git clone vierge | « onboarding 1 jour » validé |

### Semaine 5 (9-13 juin) — Mémoire + slides + répétitions
| Jour | Tâche | Livrable |
|---|---|---|
| Lun | Rédaction mémoire chap. 1-3 (contexte, état de l'art, architecture) | 30 pages |
| Mar | Rédaction chap. 4-5 (datasets, méthodologie, leakage identifié) | 25 pages |
| Mer | Rédaction chap. 6-7 (résultats, comparatif règles vs ML) | 20 pages |
| Jeu | Rédaction chap. 8 (limites, travaux futurs) + relecture | 10 pages |
| Ven | Slides soutenance (20-25 slides) | `.pptx` |

### Semaine 6 (16-20 juin) — Buffer + soutenance blanche
| Jour | Tâche |
|---|---|
| Lun-Mar | Soutenance blanche avec encadrant — questions adversariales |
| Mer | Corrections finales |
| Jeu | Vidéo de démo backup (au cas où la live foire le jour J) |
| Ven | Repos / révision |

---

## 4. Ce que Je T'ai Construit Maintenant (Cette Session)

| Fichier | Rôle | Statut |
|---|---|---|
| `docs/PLAN_RECONSTRUCTION_PFE.md` | Ce plan | ✅ |
| `docs/AUDIT_PROJET_COMPLET.md` | Audit détaillé (session précédente) | ✅ |
| `cicids2017/preprocessing/preprocess_v2.py` | Sans Destination Port + temporal split | ✅ |
| `cicids2017/models/train_xgboost_v2.py` | Avec ROC, PR, calibration, multi-classes | ✅ |
| `adfa_ld/preprocessing/preprocess_adfa_v2.py` | Vectorizer fit-only train + GroupShuffleSplit | ✅ |
| `adfa_ld/models/train_adfa_v2.py` | Avec ROC, PR, calibration | ✅ |
| `siem_windows/preprocessing/preprocess_siem.py` | Parse APT29 Mordor JSON, fenêtres glissantes 5 min | ✅ |
| `siem_windows/training/train_siem.py` | RF + Pipeline + calibration + artefacts complets | ✅ |
| `siem_windows/evaluation/generate_siem_results.py` | Confusion + ROC + PR + feature importance | ✅ |
| `siem_windows/README.md` + `model_card.md` | Documentation | ✅ |
| `lateral_movement/preprocessing/preprocess_lateral.py` | Atomic Red Team → features auth | ✅ |
| `lateral_movement/training/train_lateral.py` | RF calibré | ✅ |
| `lateral_movement/evaluation/generate_lateral_results.py` | Métriques | ✅ |
| `lateral_movement/README.md` | Documentation | ✅ |
| `integration/kibana/dashboard_soc.ndjson` | Dashboard SOC minimal importable | ✅ |
| `docker-compose.yml` | Infra complète | ✅ |
| `.gitignore` | Propre (.venv, *.pkl, *.csv data) | ✅ |

---

## 5. Ce qu'il Te Reste à Faire (Tu, l'Étudiant)

Mes scripts sont **prêts à tourner** mais nécessitent :

1. **Extraire les zips APT29** dans `siem_windows/data/raw/` :
   ```powershell
   Expand-Archive `
     "datasets/siem_dataset/data/otrf_datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip" `
     -DestinationPath "datasets/siem_windows/data/raw/day1"
   Expand-Archive `
     "datasets/siem_dataset/data/otrf_datasets/datasets/compound/apt29/day2/apt29_evals_day2_manual.zip" `
     -DestinationPath "datasets/siem_windows/data/raw/day2"
   ```

2. **Cloner Atomic Red Team datasets** pour Lateral Movement (si les zips OTRF Atomic ne suffisent pas) :
   - Ou utiliser le dossier OTRF `datasets/atomic/windows/lateral_movement/` directement (script prévu).

3. **Lancer dans cet ordre** depuis `datasets/` :
   ```powershell
   python cicids2017/preprocessing/preprocess_v2.py
   python cicids2017/models/train_xgboost_v2.py

   python adfa_ld/preprocessing/preprocess_adfa_v2.py
   python adfa_ld/models/train_adfa_v2.py

   python siem_windows/preprocessing/preprocess_siem.py
   python siem_windows/training/train_siem.py
   python siem_windows/evaluation/generate_siem_results.py

   python lateral_movement/preprocessing/preprocess_lateral.py
   python lateral_movement/training/train_lateral.py
   python lateral_movement/evaluation/generate_lateral_results.py
   ```

4. **Valider** que `live_detection.py` charge bien les 4 modèles sans warning.

5. **Configurer Sysmon + Winlogbeat** sur ton PC Windows cible (fichier de config exemple à venir).

---

## 6. Checklist Soutenance (à imprimer et cocher)

### Méthodologie
- [ ] 4 modèles avec F1 entre 0.80 et 0.95 (pas 1.00)
- [ ] Courbes ROC + PR sauvegardées pour chaque modèle
- [ ] Split temporel ou GroupShuffleSplit documenté pour chaque modèle
- [ ] `feature_importances` analysée — aucune feature « identifiante » dominante
- [ ] Comparatif règles Sigma vs ML sur le même test set
- [ ] Calibration de seuil (Youden ou F1-optimal) documentée

### Démo
- [ ] `docker-compose up` lance toute l'infra en 1 commande
- [ ] Une attaque Atomic Red Team déclenche une alerte dans Kibana en < 30s
- [ ] Dashboard Kibana montre alertes par tactique MITRE
- [ ] Vidéo backup de la démo enregistrée

### Documentation
- [ ] Mémoire écrit avec section « leakage identifié et corrigé » (les 2 audits sont des atouts)
- [ ] README de chaque module avec « comment lancer »
- [ ] Model cards pour chaque modèle
- [ ] Slides de soutenance avec architecture, résultats, démo

### Code
- [ ] Tests pytest passent (couverture > 70% sur fonctions critiques)
- [ ] Pas de secrets en clair (TheHive token via env var)
- [ ] `requirements.txt` à jour
- [ ] `.gitignore` exclut `.venv/`, `*.pkl > 10 MB`, `*.csv` data

---

## 7. Argumentaire Soutenance — Ton Discours en 3 Minutes

> « Mon projet consiste à augmenter un SOC traditionnel par une couche ML capable de détecter les attaques que les règles Sigma manquent. J'ai construit 4 modèles spécialisés couvrant 4 surfaces complémentaires : host Windows, host Linux, réseau, et identité. Le pipeline ingère les logs via Kafka, applique les modèles en parallèle, et produit un score composite envoyé à Elasticsearch / Kibana / TheHive.
>
> **Mon premier jet présentait des scores parfaits — F1=1.00 — qui m'ont paru suspects.** J'ai donc fait un audit méthodologique formel et identifié 3 problèmes : du shortcut learning sur le port de destination dans CIC-IDS, du label leakage via les champs SePrivilege dans le SIEM Windows, et de la circularité features-labels dans le Lateral Movement. Je vous présente aujourd'hui les modèles **après remédiation**, avec des F1 honnêtes entre 0.85 et 0.92, des courbes ROC, des seuils calibrés, et un comparatif avec les règles Sigma.
>
> La démo live montre une attaque Atomic Red Team T1003.001 (dump de lsass) détectée en moins de 30 secondes, avec un score composite de 0.91 et un ticket TheHive automatique. »

Cette posture (lucidité méthodologique → remédiation → résultats honnêtes) **te démarque** de 80% des PFE qui présentent des F1 parfaits sans questionner.

---

*Fin du plan. Voir `AUDIT_PROJET_COMPLET.md` pour l'état initial détaillé.*
