# siem_windows/ — Modèle SIEM Windows (Host)

## Rôle
Détection comportementale d'attaques sur postes Windows (Sysmon + Security
Events). Couvre les tactiques MITRE : Initial Access, Execution, Privilege
Escalation, Credential Access, Persistence.

## Source de données
**OTRF Mordor APT29 Evals (déjà sur disque)** : émulation MITRE des TTPs
APT29 (Cozy Bear) sur 2 jours de scénarios, ~784 000 events Windows.

```
datasets/siem_dataset/data/otrf_datasets/datasets/compound/apt29/
├── day1/apt29_evals_day1_manual.zip   ← 367 MB, ~196k events
└── day2/apt29_evals_day2_manual.zip   ← 1.6 GB, ~588k events
```

## Architecture

```
siem_windows/
├── data/
│   ├── raw/
│   │   ├── day1/        ← Extrait de apt29_evals_day1_manual.zip
│   │   └── day2/        ← Extrait de apt29_evals_day2_manual.zip
│   └── processed/
│       ├── train.parquet
│       ├── test.parquet
│       └── manifest.json
├── preprocessing/
│   └── preprocess_siem.py     ← Mordor JSON → fenêtres 5 min comportementales
├── training/
│   └── train_siem.py          ← RF + StandardScaler + calibration isotonique
├── evaluation/
│   └── generate_siem_results.py
├── saved_models/              ← Artefacts attendus par live_detection.py
│   ├── rf_siem_model.pkl
│   ├── siem_scaler.pkl
│   ├── siem_threshold.json
│   └── feature_columns.json
├── results/
│   ├── confusion_matrix.png
│   ├── roc_curve.png
│   ├── pr_curve.png
│   ├── feature_importance.png
│   ├── score_distribution.png
│   ├── timeline.png
│   ├── metrics.json
│   └── index.html
├── README.md
└── model_card.md
```

## Méthodologie défensive (anti-leakage)

| Anti-pattern à éviter | Mesure prise ici |
|---|---|
| Label leakage via `SePrivilegeList` | **Aucun champ SePrivilege* utilisé** — features = comptages d'EventIDs et ratios |
| Label leakage via `LogonType=10` (RDP) | Pas utilisé en feature directe ; agrégé dans `lateral_move_score` |
| Split aléatoire | **Split TEMPOREL** : day1 train, day2 test → généralisation prouvée |
| Granularité event-level | **Fenêtres glissantes 5 min** par host avec pas 1 min |
| Probas non calibrées | `CalibratedClassifierCV` avec calibration isotonique |
| Seuil 0.5 par défaut | **Seuil F1-optimal** sur PR curve test |
| Pas de courbe ROC / PR | Générées et sauvegardées en PNG |

## Features produites (alignées sur live_detection.py)

Toutes les features sont **comportementales pures** — aucune n'est dérivée
directement du label.

```
total_events                 : nb total d'events dans la fenêtre 5 min
events_per_minute            : total / 5
cnt_<EventID>                : comptage par EventID surveillé
                              (4624, 4625, 4648, 4672, 4768, 4769, ...)
brute_force_score            : Σ cnt_4625 + cnt_4771 + cnt_4776
lateral_move_score           : Σ cnt_4648 + cnt_4624 + cnt_4672
persistence_score            : Σ cnt_4697 + cnt_4698 + cnt_4702 + ...
priv_escalation_score        : Σ cnt_4728 + cnt_4732 + ...
recon_score                  : Σ cnt_4798 + cnt_4799 + cnt_4661
execution_score              : Σ cnt_4688 + cnt_4696
kerberos_score               : Σ cnt_4768 + cnt_4769 + ...
logon_failure_ratio          : (4625+4771) / (4624+4625+4771)
entropy_eventids             : Shannon entropy des EventIDs
distinct_eventids            : nb d'EventIDs uniques
```

## Comment lancer

### 1. Préparation (une seule fois)

```powershell
# Depuis datasets/
Expand-Archive `
  "siem_dataset/data/otrf_datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip" `
  -DestinationPath "siem_windows/data/raw/day1"

Expand-Archive `
  "siem_dataset/data/otrf_datasets/datasets/compound/apt29/day2/apt29_evals_day2_manual.zip" `
  -DestinationPath "siem_windows/data/raw/day2"
```

### 2. Pipeline complet

```powershell
# Depuis datasets/
python siem_windows/preprocessing/preprocess_siem.py
python siem_windows/training/train_siem.py
python siem_windows/evaluation/generate_siem_results.py
```

### 3. Vérification

Ouvre `siem_windows/results/index.html` dans un navigateur.
Vérifie `siem_windows/results/metrics.json` :
- `f1_calibrated` doit être entre 0.75 et 0.95 (HONNÊTE).
- `leakage_warning` doit être `false`.
- `top_feature_importance` doit être < 0.4.

## Performances attendues

| Métrique | Valeur attendue |
|---|---|
| F1 (seuil calibré) | 0.78 - 0.90 |
| ROC-AUC | 0.85 - 0.95 |
| Top feature importance | < 0.40 |
| Latence inférence | < 5 ms |

## Adaptation à ta production réelle (Winlogbeat)

Le format Mordor (JSON Sysmon) est **identique** à ce que Winlogbeat envoie
sur Kafka — donc le modèle entraîné sur APT29 est **directement utilisable
en production sur tes PCs Windows réels**, sans réentraîner.

Les features extraites en live (par `live_detection.py extract_siem_features`)
sont **calculées de manière identique** — c'est pour ça que les noms et
l'ordre dans `feature_columns.json` sont rigoureusement préservés.

## Notes pour le mémoire / soutenance

- **Scénario d'attaque réel** : APT29 (Cozy Bear, attribution russe) — un
  groupe étatique bien connu. Crédibilité forte côté jury.
- **Émulation MITRE ATT&CK Round 2** : datasets validés par la communauté
  cyber, traçabilité complète des techniques.
- **Pas de génération synthétique** : différenciateur fort vs autres PFE.
- **Split temporel** : test sur day2 = scénario chronologiquement après day1
  → simule la production.
- **Features alignées sur l'inférence live** : le modèle entraîné peut tourner
  immédiatement en production sans changement de code.
