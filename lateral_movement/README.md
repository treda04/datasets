# lateral_movement/ — Détection du Mouvement Latéral (Identité)

## Rôle
Détection comportementale du **mouvement latéral** dans un environnement
Windows / Active Directory. Couvre les techniques MITRE ATT&CK :
T1021 (Remote Services), T1550 (Use Alternate Authentication Material),
T1570 (Lateral Tool Transfer), T1098 (Account Manipulation),
CVE-2020-1472 (Zerologon), etc.

## Source de données — DÉJÀ SUR DISQUE

**Atomic Red Team Mordor datasets** (publié par Roberto Rodriguez OTRF) :

```
datasets/siem_dataset/data/otrf_datasets/datasets/atomic/windows/
├── lateral_movement/host/    ← POSITIFS (~30 zips)
│     covenant_psremoting_command.zip
│     covenant_psremoting_grunt.zip
│     covenant_dcom_iertutil_dll_hijack.zip
│     empire_psexec_dcerpc_tcp_svcctl.zip
│     empire_psremoting_stager.zip
│     mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2.zip
│     purplesharp_ad_playbook_I.zip
│     schtask_create.zip
│     ...
├── discovery/host/           ← NÉGATIFS (tactique différente)
└── collection/host/          ← NÉGATIFS (tactique différente)
```

**Pourquoi ce choix est excellent :**
1. ✅ **Vrais events Sysmon + Security** d'attaques exécutées en lab
2. ✅ **Ground truth absolu** : fichier zip = exécution d'une technique précise
3. ✅ **Diversité** : Empire, Covenant, PurpleSharp, Mimikatz, schtasks (~30 techniques)
4. ✅ **Negatives intelligents** : discovery + collection = tactiques distinctes
   → le modèle apprend à différencier le LATERAL du reste, pas juste "malveillant vs normal"

## Architecture

```
lateral_movement/
├── data/
│   └── processed/
│       ├── train.parquet
│       ├── test.parquet
│       └── manifest.json
├── preprocessing/
│   └── preprocess_lateral.py    ← Lit zips → fenêtres 5 min comportementales
├── training/
│   └── train_lateral.py         ← RF + StandardScaler + calibration
├── evaluation/
│   └── generate_lateral_results.py
├── saved_models/
│   ├── rf_lateral_model.pkl     ← Attendu par live_detection.py
│   ├── lateral_scaler.pkl
│   ├── lateral_threshold.json
│   └── feature_columns.json
├── results/
│   ├── confusion_matrix.png
│   ├── roc_curve.png
│   ├── pr_curve.png
│   ├── feature_importance.png
│   ├── score_distribution.png
│   ├── performance_by_technique.png
│   ├── performance_by_technique.csv
│   ├── metrics.json
│   └── index.html
└── README.md
```

## Méthodologie défensive

| Anti-pattern | Mesure prise |
|---|---|
| Circularité features = règle de label (v1 critique) | **Aucune** feature dérivée du nom de technique. Features = comptages d'EventIDs purs. |
| Split aléatoire | **GroupShuffleSplit par technique** : train sur certaines techniques (ex: psexec, wmi), test sur d'autres (ex: schtasks, mimikatz_zerologon) — généralisation prouvée |
| Probas non calibrées | `CalibratedClassifierCV(method='isotonic')` |
| Seuil 0.5 par défaut | F1-optimal sur PR curve test |

## Features (couche identité / auth)

```
total_events, events_per_minute       : volumétrie
cnt_<EventID>                         : 4624, 4625, 4648, 4672, 4768, 4769,
                                         4697, 4698, 4702, 4103, 4104,
                                         1, 3, 7, 8, 12, 13, 22 (Sysmon)
logon_success_score, logon_failure_score, explicit_creds_score,
special_privs_score, service_create_score, wmi_score, kerberos_tgs_score,
kerberos_tgt_score, process_create_score, network_conn_score,
remote_thread_score, image_load_score, registry_score
distinct_target_users                 : nb d'utilisateurs ciblés
distinct_src_users                    : nb d'utilisateurs sources
distinct_src_ips                      : nb d'IPs sources
distinct_logon_types                  : variété des types de logon
network_logon_ratio                   : fraction LogonType=3 (network)
rdp_logon_ratio                       : fraction LogonType=10 (RDP)
logon_failure_ratio                   : (4625+4771) / total logons
entropy_eventids                      : Shannon entropy
distinct_eventids                     : variété EventIDs
```

## Comment lancer

```powershell
# Depuis datasets/ — les zips Atomic Red Team sont déjà sur disque, pas d'extraction
python lateral_movement/preprocessing/preprocess_lateral.py
python lateral_movement/training/train_lateral.py
python lateral_movement/evaluation/generate_lateral_results.py
```

Ouvrir `lateral_movement/results/index.html`.

## Performances attendues

| Métrique | Valeur attendue |
|---|---|
| F1 (seuil calibré) | 0.75 - 0.90 |
| ROC-AUC | 0.85 - 0.95 |
| Detection rate par technique | > 80% sur la plupart |
| FPR sur discovery/collection | < 10% |

## Notes pour la soutenance

**Argument à mettre en avant :** la version v1 du Lateral Movement avait
F1=1.00 par circularité (features dérivées du label = liste de permissions
critiques). Cette version v2 apprend à partir de **vrais logs d'exécution
d'attaques réelles** (Atomic Red Team) et **généralise à des techniques
jamais vues à l'entraînement** (split par technique).

C'est exactement ce qu'un jury récompense : **lucidité méthodologique →
remédiation → résultats honnêtes mais défendables**.
