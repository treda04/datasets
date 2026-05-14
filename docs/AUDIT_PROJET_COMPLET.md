# Audit Complet du Projet PFE — De A à Z

**Projet :** PFE-SOC-ML — Intégration des méthodes analytiques et du Machine Learning pour l'amélioration des capacités de détection en environnement SIEM
**Étudiant :** UIR — 5ème année Cybersécurité
**Entreprise d'accueil :** Data Protect
**Date de l'audit :** 2026-05-09
**Auditeur :** Revue technique automatisée (lecture exhaustive des README + code)
**Version :** 1.0

---

## 1. Résumé Exécutif (TL;DR)

Le projet est **ambitieux et bien pensé sur le papier** : un SOC complet (Sysmon → Kafka → ML → Logstash → Elasticsearch → Kibana → TheHive) construit autour de 4 modèles ML couvrant 4 surfaces d'attaque (syscalls Linux, flux réseau, événements Windows, mouvement latéral Cloud/AD).

**Mais l'écart entre ce qui est documenté et ce qui existe réellement sur disque est significatif**, et les modèles déjà entraînés présentent des problèmes méthodologiques **critiques** (label leakage, shortcut learning, circularité features/labels). En l'état, un jury technique rigoureux **rejettera** les scores F1=1.00 et demandera une reconstruction.

| Indicateur | État | Commentaire |
|---|---|---|
| Vision & architecture | ✅ Très bonne | Pipeline SOC end-to-end bien dimensionné |
| Documentation | ✅ Excellente | README clairs, audit Phase 1 déjà rédigé |
| Modèles livrés | ⚠️ 2/4 | ADFA-LD + CIC-IDS-2017 entraînés ; SIEM Windows et Lateral Movement absents du disque |
| Qualité méthodologique ML | ❌ Critique | 3 modèles sur 4 ont un F1 artificiel (≈1.00) |
| Infrastructure live | ⚠️ Partielle | `live_detection.py` (444 lignes) prêt mais référence des chemins inexistants |
| Intégration ELK | ⚠️ Partielle | Logstash + mapping ES OK ; dashboard Kibana ndjson absent |
| Reproductibilité | ⚠️ Moyenne | Pas de seed temporel, pas de tests, pas de CI |
| Risque PFE | 🔴 Élevé sans correction | Recommandation : 4 à 6 semaines de remédiation avant soutenance |

**Verdict :** projet à fort potentiel, mais **Phase 2 (remédiation méthodologique + reconstruction des modules manquants) indispensable**. Avec 4-6 semaines de travail ciblé, le projet peut atteindre un excellent niveau de soutenance.

---

## 2. Identification & Périmètre du Projet

### 2.1 Sujet officiel
> Intégration des méthodes analytiques et du Machine Learning pour l'amélioration des capacités de détection en environnement SIEM.

### 2.2 Objectifs implicites (déduits du code et des README)
1. Compléter / remplacer la détection à base de règles (Wazuh, Sigma) par des modèles ML.
2. Couvrir 4 surfaces d'attaque complémentaires (host Linux, réseau, host Windows, identités Cloud/AD).
3. Industrialiser le tout dans un pipeline temps-réel branché sur un SIEM existant (ELK + Wazuh + TheHive).
4. Démontrer une **démo live** sur infrastructure réelle (PCs Windows + VM Ubuntu Kafka + ELK).

### 2.3 Livrables attendus
- Mémoire/rapport PFE (non présent dans `datasets/`).
- 4 modèles ML entraînés et évalués sur métriques honnêtes.
- Service `live_detection` Kafka opérationnel.
- Dashboard Kibana SOC fonctionnel.
- Démo de bout en bout : génération d'attaque → détection → alerte → ticket TheHive.

### 2.4 Périmètre couvert par cet audit
Lecture exhaustive de **toutes les ressources documentaires et code du projet** dans `C:\Users\DELL LATITUDE U7\Desktop\` :
- `datasets/` (projet principal — README, scripts Python, configs ELK)
- `datasets/docs/AUDIT_REPORT.md` (audit Phase 1 préexistant)
- `datasets/siem_dataset/` (datasets OTRF — Sysmon, APT29, Atomic Red Team)
- `datasets/otrf_sysmon/` (placeholder modèle Windows)
- `botsv3-master/` (dataset Splunk Boss of the SOC v3 — non intégré)
- `Rapport d'Avancement Technique.{ods,xlsx}` et `PFE_Avancement_Detection_IA_SIEM_Reda_2026.xlsx` (suivi non analysé — formats binaires)
- `SANS SEC 595 Data Acquisition and ML/` (formation, hors périmètre code)

---

## 3. Architecture Cible (Telle que Documentée)

```
┌─────────────────────┐
│ Postes Windows 10   │  Sysmon + Winlogbeat
│ (PC1, PC2, PC3)     │
└──────────┬──────────┘
           │ winlogbeat → kafka
           ▼
┌─────────────────────┐
│ Kafka Broker        │  192.168.94.132:9092
│ topic: windows-     │  (sur VM Ubuntu)
│       raw-logs      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────┐
│ live_detection.py  (Python service)         │
│  ├── KafkaConsumer (windows-raw-logs)       │
│  ├── Fenêtres glissantes par host (5 min)   │
│  ├── Extraction features comportementales   │
│  ├── Inférence : 4 modèles ML pondérés      │
│  │     SIEM=0.50  Lateral=0.25  Net=0.15    │
│  │     ADFA=0.10                            │
│  ├── Score composite + niveau (LOW…CRIT)    │
│  └── KafkaProducer (ml-alerts)              │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌─────────────────────┐
│ Logstash            │  ml-alerts-pipeline.conf
│  ├── Date parsing   │
│  ├── Enrichissement │  (severity_int, MITRE URL)
│  └── Outputs        │
└─────┬───────────┬───┘
      │           │ (si score ≥ 0.85)
      ▼           ▼
┌──────────┐  ┌──────────┐
│ ES index │  │ TheHive  │  POST /api/v1/alert
│ ml-      │  │ webhook  │
│detect-*  │  │          │
└────┬─────┘  └──────────┘
     ▼
┌──────────┐
│ Kibana   │  Dashboard SOC
│ (analyste│
│   SOC)   │
└──────────┘
```

**Composants additionnels mentionnés** : Wazuh (corrélation traditionnelle, en parallèle), TheHive v4 (gestion d'incidents).

---

## 4. État Réel du Projet (Disque vs Annonces)

C'est le **point le plus important** de l'audit : le README annonce une structure qui n'existe pas en totalité.

### 4.1 Inventaire `datasets/` réel

| Dossier annoncé dans README | État disque | Commentaire |
|---|---|---|
| `adfa_ld/` | ✅ Présent et complet | Preprocessing + train + modèle `.pkl` + EDA notebook |
| `cicids2017/` | ✅ Présent et complet | Preprocessing + train + modèle `.pkl` + dataset 685 MB |
| `siem_windows/` | ❌ **ABSENT** | Annoncé « PRIORITAIRE — à reconstruire ». Le code de `live_detection.py` charge `siem_windows/saved_models/rf_siem_model.pkl` qui n'existe pas. |
| `lateral_movement/` | ❌ **ABSENT** | Annoncé « à reconstruire ». Idem pour `lateral_movement/saved_models/rf_lateral_model.pkl`. |
| `live_detection/` | ✅ Présent | `live_detection.py` (444 LOC) — bien structuré |
| `integration/` | ⚠️ Partiel | Logstash conf + ES mapping OK ; **`kibana/dashboard_soc.ndjson` absent** (alors que README dit « import manuel ») |
| `raw_new/` | ❌ **ABSENT** | Annoncé contenir les Windows Security logs et lateral movement logs |
| `docs/` | ✅ Présent | Contient `AUDIT_REPORT.md` (rigoureux) |
| `requirements.txt` | ✅ Présent | Dépendances listées et réalistes |
| `siem_dataset/` | ✅ Présent | Datasets OTRF (Sysmon, APT29) — **non utilisés par le code actuel** |
| `otrf_sysmon/` | ⚠️ Squelette vide | Sous-dossiers `data/eda/models/preprocessing/results/` mais aucun script |
| `.venv/` | ✅ Présent | Environnement virtuel installé |

### 4.2 Conclusion gap analysis

- **2 modèles sur 4 sont réellement entraînés** (ADFA-LD, CIC-IDS-2017).
- Le **modèle déclaré prioritaire** (SIEM Windows) **n'a aucun code source ni artefact**.
- Le **service live `live_detection.py` ne peut pas fonctionner intégralement** car `load_models()` cherche des `.pkl` inexistants. Il dégradera silencieusement (warning + scores neutres 0.0) — donc seul ADFA-LD et CIC-IDS-2017 contribueraient, mais leurs entrées attendues ne sont pas des events Windows bruts. **En pratique le service produira toujours des scores ≈0**.
- **Le dashboard Kibana** (livrable visible côté jury) est annoncé mais le fichier `dashboard_soc.ndjson` n'existe pas.

C'est un **risque PFE majeur** : la chaîne de bout en bout n'est pas démontrable en l'état.

---

## 5. Audit Détaillé par Composant

### 5.1 Modèle ADFA-LD (syscalls Linux)
**Fichiers :** `adfa_ld/preprocessing/preprocess_adfa.py`, `adfa_ld/models/train_adfa.py`, `rf_adfa_model.pkl`
**Données :** ADFA-LD UNSW (~5995 fichiers .txt, 5 familles d'attaques : Adduser, Hydra, Meterpreter, Java_Meterpreter, Web_Shell)
**Algo :** Random Forest 200 arbres, features = trigrammes de syscalls (CountVectorizer top 500)
**Score annoncé :** F1 ≈ 0.96, Accuracy ≈ 96%, FPR ≈ 5%

**Forces :**
- Représentation N-gram pertinente et défendable scientifiquement.
- Random Forest = bon choix (interprétable, robuste).
- Score crédible (pas suspect).

**Faiblesses (déjà identifiées dans `AUDIT_REPORT.md`) :**
1. **Split aléatoire** (`random_state=42`) — risque de fuite inter-session : plusieurs traces d'une même attaque se retrouvent dans train ET test. Gravité : **MODÉRÉE**.
2. **Vectorizer fit sur tout le dataset** avant split (ligne 53–55 de `preprocess_adfa.py`). Le vocabulaire des n-grams est appris sur train+test → fuite indirecte. Gravité : **FAIBLE**.

3. **Pas de courbe ROC ni PR**, pas de calibration de seuil → impossible d'arbitrer FPR/TPR en production.
4. **Pas de séparation par famille d'attaque** dans l'évaluation (binaire 0/1 uniquement) — on ne sait pas si le modèle généralise à une attaque jamais vue.

**Verdict :** modèle **le plus crédible des quatre**. À retoucher en 1-2 jours.

### 5.2 Modèle CIC-IDS-2017 (flux réseau)
**Fichiers :** `cicids2017/preprocessing/preprocess.py`, `cicids2017/models/train_xgboost.py`, `xgb_model.pkl`
**Données :** CIC-IDS-2017 (685 MB, limité à 500 000 lignes par `LIGNES_MAX = 500000`)
**Algo :** XGBoost (100 arbres, depth=6, lr=0.1, tree_method=hist), SMOTE après split, StandardScaler
**Score annoncé :** F1 ≈ 1.00 — **suspect**

**Forces :**
- Pipeline ML correct : split → SMOTE sur train uniquement → scale fit sur train.
- XGBoost = excellent choix sur tabulaire déséquilibré.
- Suppression des colonnes constantes faite proprement.

**Faiblesses CRITIQUES :**
1. **Shortcut learning sur `Destination Port`** : la variable encode l'attaque (port 22 → SSH brute force, port 80/443 → Web Attacks, port 0 → DDoS). Le modèle apprend la table de routage, pas le comportement. Une `model.feature_importances_` confirmera Destination Port > 0.5. Gravité : **CRITIQUE**.
2. **Classes hardcodées à 4** (`['Brute Force', 'Normal Traffic', 'Port Scanning', 'Web Attacks']`) au lieu des 14 du dataset original — mapping non documenté.
3. **Limite à 500k lignes** sans justification : biais de sélection (les premières 500k lignes sont chronologiquement contiguës ; certaines classes peuvent être sous-représentées).
4. **Pas de courbe ROC/PR**, pas d'analyse cross-class.
5. **Aucun split temporel** (CIC-IDS-2017 a des timestamps).

**Verdict :** F1=1.00 **artificiel**. **À reconstruire** en supprimant `Destination Port`, `Source Port`, et toute feature dérivée des ports identifiantes.

### 5.3 Modèle SIEM Windows
**Fichiers :** ❌ **Aucun code source sur disque.** Le README et `live_detection.py` y font référence (`siem_windows/saved_models/rf_siem_model.pkl`, `siem_scaler.pkl`, `siem_threshold.json`, `feature_columns.json`).

**Problèmes méthodologiques (versions précédentes selon AUDIT_REPORT.md) :**
1. **Label leakage critique** via les champs `SePrivilegeList` (SeDebugPrivilege → Mimikatz, SeImpersonatePrivilege → mouvement latéral, SeTcbPrivilege → privesc). Ces tokens **définissent** l'attaque — les utiliser comme features = règle Sigma déguisée en ML.
2. **Pas de split temporel** alors que les events Windows sont nativement temporels.
3. **Granularité event-level** au lieu de fenêtres comportementales (1 EventID 4625 isolé n'est pas discriminant ; 100 en 5 min = brute force).

**Verdict :** **module prioritaire à (re)construire intégralement**. Le service `live_detection.py` impose le contrat de features (voir `extract_siem_features()` ligne 136) :
- `total_events`, `events_per_minute`
- `cnt_<EventID>` pour chaque ID monitoré (4625, 4624, 4648, 4672, 4768, 4769, …)
- Scores comportementaux par catégorie : `brute_force_score`, `lateral_move_score`, `persistence_score`, `priv_escalation_score`, `recon_score`, `execution_score`, `kerberos_score`
- `logon_failure_ratio`
- `entropy_eventids`, `distinct_eventids`

**C'est une excellente définition** de features comportementales — il manque juste le pipeline d'entraînement aligné dessus.

### 5.4 Modèle Lateral Movement (Cloud/AD)
**Fichiers :** ❌ **Aucun code source.** Référencé dans `live_detection.py` (`lateral_movement/saved_models/rf_lateral_model.pkl`).

**Problèmes méthodologiques :**
1. **Circularité features = labels** : `is_critical` est défini manuellement (`critical_permissions = ["User.ReadWrite.All", …]`), puis utilisé comme feature ET règle de labellisation → tautologie.
2. **Absence de logs d'activité réels** : les fichiers présents (`raw_new/lateral_movement_logs.csv/`) sont des **listes de référence** (rôles AWS, Azure, AD) — pas des logs (qui, quoi, quand, depuis où).
3. Sans logs temporels, la détection de mouvement latéral est **structurellement impossible** à entraîner.

**Verdict :** **à reconstruire à partir d'une vraie source de logs**. Pistes :
- Dataset HuggingFace `darkknight25/Advanced_SIEM_Dataset`
- Génération avec Atomic Red Team + Sysmon
- OTRF datasets APT29 / Mordor déjà présents dans `datasets/siem_dataset/data/otrf_datasets/datasets/compound/apt29/`

### 5.5 Service `live_detection.py`
**Volume :** 444 lignes Python — **sérieusement écrit**.

**Forces :**
- Logging JSON structuré (bon réflexe SOC).
- Chargement défensif des modèles (warning si `.pkl` absent → continue).
- Fenêtres glissantes par host (déque maxlen=500, fenêtre temporelle 5 min).
- Score composite pondéré explicite (SIEM 0.50 / Lateral 0.25 / Net 0.15 / ADFA 0.10).
- Mapping MITRE ATT&CK par modèle dominant.
- Niveaux d'alerte calibrés (CRITICAL ≥ 0.85, HIGH ≥ 0.70, MEDIUM ≥ 0.65).
- Reconnexion Kafka avec retry (`RECONNECT_DELAY = 5`).

**Faiblesses :**
1. **2 modèles sur 4 référencés sont absents** → en pratique le service produira `siem_windows=0` et `lateral_movement=0` constamment (warnings au démarrage).
2. **`adfa_ld` et `cicids` sont mis à 0.0 en dur** dans `run_inference()` (ligne 241–243) car « pas de features extractibles depuis un event Windows brut ». **Mais alors leur contribution réelle est nulle** → le score composite revient entièrement à `siem_windows`. Tant que SIEM Windows n'existe pas, **le service produit toujours score 0**.
3. **Pas de tests unitaires** sur l'extraction de features (fonction critique).
4. **Pas de métriques Prometheus / observability** (latence, throughput, taux d'alertes).
5. Le `time.time()` côté python est utilisé pour `cutoff` de fenêtre, mais les events Kafka ont leur propre `@timestamp` Winlogbeat → décalage horaire possible si Kafka backlog ou retard.
6. **Pas de gestion de backpressure** : si Kafka injecte plus vite que l'inférence, la mémoire des `host_windows` peut grossir indéfiniment (la `defaultdict` n'est jamais purgée par TTL d'host).
7. Le seuil par modèle (`m['threshold']`) est chargé mais **jamais utilisé** dans `run_inference` (seul le score brut probabiliste est utilisé, pas la décision binaire calibrée).

**Verdict :** très bon squelette, à compléter et durcir.

### 5.6 Pipeline ELK
**`integration/logstash/ml-alerts-pipeline.conf`** : pipeline Kafka → ES + webhook TheHive.
- Point fort : enrichissement intelligent (severity_int, mitre_url, index par jour).
- Point faible : credentials TheHive en dur dans le fichier (`Bearer THEHIVE_API_KEY`) — à externaliser.
- Point faible : pas de **dead letter queue** ni de gestion d'erreur Logstash → si TheHive est HS, Logstash bloque ?

**`integration/elasticsearch/ml-detections-mapping.json`** : mapping cohérent, types corrects, `dynamic: true` (à débattre — autorise des dérives de schéma).
- Point fort : `model_scores` typé en sub-objet, `mitre_*` indexé pour filtrage Kibana.
- Manque : ILM policy (rotation/suppression d'index), template (au lieu d'index unique), mappings de `host` IP/geo.

**`integration/kibana/dashboard_soc.ndjson`** : ❌ **fichier absent** alors qu'il est référencé. Bloquant pour la démo.

### 5.7 Documentation
- `README.md` racine : clair, structuré, donne le contexte. ⭐
- `docs/AUDIT_REPORT.md` : **excellente initiative** — lucidité technique remarquable, identifie les bons problèmes avec preuves de code et lignes précises. Ce document seul est un atout PFE majeur (montre la maturité méthodologique).
- READMEs par sous-dossier : très inégaux (certains sont des squelettes de 13 lignes). À uniformiser.

### 5.8 Reproductibilité & ingénierie
| Critère | État |
|---|---|
| `requirements.txt` | ✅ Présent, versions minimales, propre |
| `.venv/` | ✅ Présent |
| Dockerfile | ❌ Absent |
| docker-compose (Kafka + ES + Kibana + Logstash) | ❌ Absent |
| Tests unitaires (pytest) | ❌ Absent |
| CI (GitHub Actions) | ❌ Absent |
| Seeds aléatoires fixés | ⚠️ Partiel (`random_state=42` partout, mais pas de hash de dataset) |
| Versionnage des modèles (MLflow / DVC) | ❌ Absent |
| Logging structuré | ✅ Côté `live_detection.py` |
| Secrets management | ❌ TheHive token en clair dans Logstash conf |
| `.gitignore` | ❌ Non vérifié, `.venv/` probablement non ignoré |

---

## 6. Datasets Disponibles (Inventaire)

| Dataset | Localisation | Taille | Statut d'utilisation |
|---|---|---|---|
| ADFA-LD | `adfa_ld/data/ADFA-LD/` | ~6000 fichiers | ✅ Utilisé |
| CIC-IDS-2017 | `cicids2017/data/cicids2017.csv` | 685 MB | ✅ Utilisé (limité à 500k lignes) |
| OTRF / Mordor (APT29 day1+day2, GoldenSAML, Atomic Windows/Linux) | `siem_dataset/data/otrf_datasets/` | ~? GB | ❌ Présent mais **non exploité** par le code |
| Splunk BOTSv3 | `botsv3-master/` | Indices Splunk | ❌ Présent mais **non exploité** |
| Sysmon evtx (placeholder) | `otrf_sysmon/` | Vide | ❌ Squelette uniquement |

**Observation forte :** le projet possède des datasets de **très haute qualité** (OTRF Mordor APT29, Atomic Red Team) qui sont **idéaux pour le SIEM Windows et le Lateral Movement** — mais ils ne sont actuellement **pas utilisés**. C'est l'un des leviers majeurs de remédiation.

---

## 7. Synthèse Méthodologique : ce qui ne va pas

| Anti-pattern | Modèles concernés | Conséquence jury |
|---|---|---|
| Label leakage (features dérivées du label) | SIEM Windows (SePrivilege*) | F1=1.00 disqualifiant |
| Shortcut learning (variable « identifiante ») | CIC-IDS-2017 (Destination Port) | F1=1.00 disqualifiant |
| Circularité features = règle de labellisation | Lateral Movement | F1=1.00 disqualifiant |
| Split aléatoire sur données temporelles | Tous | Optimisme modéré |
| Fit du préprocesseur sur train+test | ADFA-LD (CountVectorizer) | Optimisme léger |
| Pas de courbe ROC / PR / calibration de seuil | Tous | Pas de pilotage FPR |
| Réduction silencieuse du nb de classes | CIC-IDS-2017 (14 → 4) | Manque de transparence |
| Modèles annoncés inexistants sur disque | SIEM Windows, Lateral Movement | Démo impossible |

**Règle d'or jury :** un F1=0.85 honnête et reproductible **bat** un F1=1.00 leaky. Le projet doit assumer ce trade-off.

---

## 8. Risques pour la Soutenance PFE

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
| Jury demande d'exécuter `live_detection.py` en démo | Élevée | Bloquant (le service tournera mais ne produira aucune alerte) | Reconstruire SIEM Windows avant la soutenance |
| Jury fait `model.feature_importances_` sur CIC-IDS | Moyenne | Disqualifiant (Destination Port > 0.5 visible) | Retirer features identifiantes, réentraîner |
| Question « comment évolue la performance dans le temps ? » | Élevée | Pas de réponse (pas de split temporel) | Ajouter split temporel + monitoring |
| Question « démo complète Kafka → Kibana » | Élevée | Dashboard ndjson absent | Créer le dashboard, le versionner |
| Question « avez-vous un baseline règles vs ML ? » | Moyenne | Pas de comparatif | Ajouter Wazuh/Sigma comme baseline |
| Question sur les datasets non utilisés (BOTSv3, OTRF) | Faible | Image négative (non-exploitation) | Soit les retirer du repo, soit les intégrer |
| Hooks legaux / éthiques (données prod ?) | Faible | Variable selon Data Protect | Documenter la conformité RGPD |

---

## 9. Ce qui est BIEN dans le Projet (à valoriser en soutenance)

Le projet a beaucoup d'atouts à mettre en avant — il faut les rendre visibles :

1. **Architecture SOC professionnelle** : Kafka + ELK + TheHive + Wazuh est exactement ce qu'on attend d'un projet entreprise sérieux.
2. **AUDIT_REPORT.md** existant : preuve de **maturité méthodologique**. Beaucoup de PFE n'arrivent même pas à identifier leurs propres faiblesses. Ce document est un **différenciateur fort**.
3. **`live_detection.py`** : 444 lignes de code propre, score composite pondéré, MITRE ATT&CK, fenêtres glissantes. Le squelette d'un vrai service SOC.
4. **Mapping ELK / TheHive cohérent** : tags PFE-UIR, structure d'alerte exploitable côté analyste.
5. **Choix des features comportementales SIEM Windows** (dans `extract_siem_features`) : entropie EventIDs, `logon_failure_ratio`, scores par tactique MITRE — c'est **conceptuellement excellent**, il « suffit » de l'implémenter côté training.
6. **Variété des surfaces couvertes** (host Linux, réseau, host Windows, identités) : démontre une compréhension **systémique** de la cybersécurité.

---

## 10. Recommandations Priorisées

### 🔴 Priorité 1 — Bloquant pour la soutenance (à faire absolument)

| # | Action | Effort | Impact |
|---|---|---|---|
| P1.1 | **Reconstruire le module `siem_windows/`** (preprocessing, training, evaluation) aligné sur les features attendues par `live_detection.py`. Utiliser les datasets OTRF APT29 / Mordor déjà présents. | 5-7 j | CRITIQUE |
| P1.2 | **Retirer `Destination Port`, `Source Port` et toutes features dérivées** de CIC-IDS-2017 ; réentraîner ; documenter la chute attendue de F1 (probablement 0.85-0.92). | 1-2 j | CRITIQUE |
| P1.3 | **Créer le `dashboard_soc.ndjson` Kibana** (visualisations : alertes par heure, top hosts, distribution MITRE tactic, score moyen, drilldown TheHive). | 1-2 j | ÉLEVÉ |
| P1.4 | **Démo end-to-end** : générer une attaque (Atomic Red Team T1003.001 lsass dump) sur PC1, voir l'alerte arriver dans Kibana < 30 secondes. Enregistrer la vidéo. | 1-2 j | ÉLEVÉ |

### 🟡 Priorité 2 — Méthodologie ML (renforce la défense)

| # | Action | Effort | Impact |
|---|---|---|---|
| P2.1 | **Split temporel** (`TimeSeriesSplit` ou tri par timestamp + 80/20) sur tous les modèles dotés de timestamps. | 1 j | FORT |
| P2.2 | **Courbes ROC + PR + calibration de seuil** (Youden / F1-optimal) pour chaque modèle, sauvegardées en `.png`. | 1 j | FORT |
| P2.3 | **Fix du fit-leak du `CountVectorizer`** dans ADFA-LD : `fit` sur train uniquement, `transform` sur test. | 0.5 j | FAIBLE mais visible |
| P2.4 | **`GroupShuffleSplit`** sur ADFA-LD par dossier d'attaque (chaque attaque = 1 groupe). | 0.5 j | MOYEN |
| P2.5 | **Reconstruire Lateral Movement** sur des logs réels (OTRF GoldenSAML ADFS Mail Access ou darkknight25 dataset). | 5-7 j | FORT |
| P2.6 | **Baseline règles** : reproduire Sigma/Wazuh sur les mêmes données de test ; afficher comparatif dans la soutenance. | 2-3 j | FORT (impact jury) |
| P2.7 | **Cross-validation k-fold** au lieu d'un seul split, avec intervalles de confiance sur F1. | 1 j | MOYEN |

### 🟢 Priorité 3 — Ingénierie & professionnalisme

| # | Action | Effort | Impact |
|---|---|---|---|
| P3.1 | **Tests unitaires** sur `extract_siem_features`, `compute_composite_score`, `parse_event` avec pytest. | 2 j | MOYEN |
| P3.2 | **`docker-compose.yml`** complet (Kafka + Zookeeper + ES + Kibana + Logstash + service ML). Permet la démo en 1 commande. | 2-3 j | FORT (démo) |
| P3.3 | **Externaliser secrets** (TheHive API key) via variables d'environnement. | 0.5 j | MOYEN |
| P3.4 | **Métriques Prometheus** dans `live_detection.py` (compteurs alertes, latence). | 1 j | MOYEN |
| P3.5 | **Versionnage modèles** : minimum un fichier `model_card.md` par modèle (date, hash dataset, métriques, hyperparams). | 1 j | MOYEN |
| P3.6 | **TTL host_windows** dans `live_detection.py` pour éviter fuite mémoire. | 0.5 j | FAIBLE |
| P3.7 | **`.gitignore` propre** (.venv/, *.pkl > 50 MB via Git LFS, *.csv data). | 0.5 j | FAIBLE |
| P3.8 | **CI GitHub Actions** : lint + tests sur chaque push. | 1 j | FAIBLE (mais gain image) |

### 🔵 Priorité 4 — Valorisation académique

| # | Action | Effort | Impact |
|---|---|---|---|
| P4.1 | **Tableau comparatif** dans le mémoire : F1 avant/après remédiation, avec preuves de leakage. **Mettre en avant la lucidité** (le AUDIT_REPORT.md est un atout). | 1 j | TRÈS FORT |
| P4.2 | **Schéma final** d'architecture (mermaid ou draw.io) avec flux temps réel chiffrés. | 0.5 j | FORT |
| P4.3 | **Modèle de menace (Threat Model)** explicite : MITRE ATT&CK couverture par modèle. | 1 j | MOYEN |
| P4.4 | **Limites & travaux futurs** : détection adversariale, drift de données, modèles non supervisés (Isolation Forest, Autoencoders). | 0.5 j | MOYEN |

---

## 11. Roadmap Proposée (4-6 semaines avant soutenance)

### Semaine 1 — Stabilisation
- P1.2 : Fix CIC-IDS (retirer Destination Port).
- P2.1, P2.2, P2.3 : Split temporel, courbes ROC, fix vectorizer.
- P3.7 : .gitignore.

### Semaines 2-3 — Reconstruction SIEM Windows (P1.1)
- Préparer dataset à partir d'OTRF APT29 day1/day2 + données saines normales.
- Implémenter `siem_windows/preprocessing/preprocess_siem.py` aligné sur `extract_siem_features`.
- Entraîner Random Forest + sauvegarder scaler + threshold + feature_columns.json.
- Évaluer rigoureusement.

### Semaine 4 — Lateral Movement (P2.5)
- Sourcer un dataset de logs réels.
- Construire features d'identité (IP source, hour-of-day, role-changes, geo-IP).
- Entraîner et évaluer.

### Semaine 5 — Industrialisation
- P1.3 : dashboard Kibana ndjson.
- P3.2 : docker-compose.
- P3.1 : tests unitaires.
- P2.6 : baseline règles.

### Semaine 6 — Démo + soutenance
- P1.4 : enregistrement de la démo Atomic Red Team → Kibana.
- P4.1, P4.2, P4.3 : finalisation rapport et slides.
- Répétition de la soutenance avec questions adversariales (« montrez-moi `feature_importances_` »).

---

## 12. Checklist « Prêt pour Soutenance »

- [ ] 4 modèles entraînés avec scores **honnêtes** (F1 entre 0.80 et 0.95 — pas 1.00).
- [ ] Pour chaque modèle : `feature_importances` documentée + courbe ROC + courbe PR.
- [ ] Split temporel sur tous les modèles avec timestamp.
- [ ] AUDIT_REPORT.md à jour (avant/après remédiation).
- [ ] `live_detection.py` qui produit de vraies alertes en démo live.
- [ ] Dashboard Kibana fonctionnel et importé via ndjson versionné.
- [ ] docker-compose qui lance tout l'écosystème en 1 commande.
- [ ] Vidéo de démo de bout en bout (attaque → Kibana en < 30s).
- [ ] Comparatif ML vs règles Sigma/Wazuh sur le même test set.
- [ ] Mémoire écrit avec section « limites et leakage identifiés et corrigés ».
- [ ] Tests unitaires passants (pytest).
- [ ] README de niveau « onboarding 1 jour » : un nouvel arrivant peut tout reproduire.

---

## 13. Conclusion de l'Audit

Le projet **PFE-SOC-ML** présente une **vision et une architecture remarquables** pour un projet étudiant — Kafka, ELK, TheHive, MITRE ATT&CK, score composite multi-modèles : tout cela est de niveau professionnel. La présence d'un audit méthodologique préexistant (`AUDIT_REPORT.md`) démontre une rare maturité.

**Cependant**, en l'état actuel :
- **2 modèles sur 4 sont absents du disque** (SIEM Windows et Lateral Movement) — ce qui rend la chaîne live non démontrable.
- Les **2 modèles entraînés présentent des problèmes méthodologiques majeurs** (label leakage, shortcut learning) qu'un jury technique repérera en moins de 5 minutes via `feature_importances_`.
- Plusieurs **livrables annoncés sont manquants** (dashboard Kibana, dossier raw_new/).

Avec un plan de remédiation rigoureux de **4 à 6 semaines** focalisé sur la **reconstruction du SIEM Windows**, la **suppression des features identifiantes**, l'ajout du **split temporel** et la **création du dashboard Kibana**, le projet peut atteindre un excellent niveau de soutenance.

**Le levier le plus fort** est de **transformer la lucidité méthodologique en avantage compétitif** : assumer publiquement les problèmes identifiés, montrer le « avant/après » avec preuves, et défendre des scores honnêtes (F1 ≈ 0.85-0.92) plutôt que des scores parfaits suspects. Un jury récompensera bien davantage cette posture qu'un F1=1.00 leaky.

---

## Annexe A — Fichiers Lus pour cet Audit

- `datasets/README.md`
- `datasets/docs/AUDIT_REPORT.md`
- `datasets/requirements.txt`
- `datasets/adfa_ld/README.md`, `data/README.md`
- `datasets/adfa_ld/preprocessing/preprocess_adfa.py`
- `datasets/adfa_ld/models/train_adfa.py`
- `datasets/cicids2017/README.md`, `data/README.md`, `eda/README.md`, `models/README.md`, `preprocessing/README.md`, `results/README.md`
- `datasets/cicids2017/preprocessing/preprocess.py`
- `datasets/cicids2017/models/train_xgboost.py`
- `datasets/live_detection/README.md` + `live_detection.py` (intégral)
- `datasets/integration/README.md`
- `datasets/integration/logstash/ml-alerts-pipeline.conf`
- `datasets/integration/elasticsearch/ml-detections-mapping.json`
- `botsv3-master/botsv3-master/README.md`
- Inventaire structurel : `datasets/siem_dataset/`, `datasets/otrf_sysmon/`, `datasets/.venv/`

---

## Annexe B — Glossaire Rapide

- **Label leakage** : une feature contient (directement ou indirectement) la cible à prédire. Le modèle « triche ».
- **Shortcut learning** : le modèle apprend une corrélation triviale (ex. port → attaque) au lieu d'apprendre le vrai signal.
- **Split temporel** : train sur le passé, test sur le futur, pour simuler la production.
- **SMOTE** : technique de sur-échantillonnage des classes minoritaires par synthèse.
- **MITRE ATT&CK** : matrice de référence des tactiques et techniques d'attaque (TXXXX).
- **F1-score** : moyenne harmonique précision/rappel. F1=1.00 est presque toujours suspect en cybersécurité réelle.
- **FPR** : False Positive Rate. Critique en SOC : un FPR de 1% sur 1M events/jour = 10 000 fausses alertes/jour.

---

*Fin de l'audit. Document généré le 2026-05-09.*
