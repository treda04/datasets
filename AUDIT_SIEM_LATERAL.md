# AUDIT PRÉ-TRAVAIL — siem_windows + lateral_movement

**Date :** 2026-05-20
**Périmètre :** projet global (`C:/Users/DELL LATITUDE U7/Desktop/datasets`) + deux datasets à finaliser (`siem_windows/`, `lateral_movement/`)
**Objectif :** dresser un état des lieux complet **avant** de reproduire pour ces deux datasets la même démarche data-scientiste qu'ADFA-LD et CIC-IDS-2017 (Phase 0 → Phase 5 + audit anti-leakage).

---

## TL;DR

| Élément | siem_windows | lateral_movement |
|---|---|---|
| Données brutes disponibles | ✅ APT29 Day1 (368 MB) + Day2 (1.6 GB) JSON Lines | ✅ via `siem_dataset/data/otrf_datasets/datasets/atomic/windows/` (37 ZIPs) |
| Documentation Phase 0 | ❌ 4 fichiers `.md` **vides** (0 ligne) | ❌ 5 fichiers `.md` **vides** (0 ligne) |
| `EXPLICATION_MODELS.md` | ⚠️ Présent mais c'est un blob non formaté (paragraphe unique sans titres ni listes Markdown) | ❌ Vide |
| Notebooks EDA + Modeling | ✅ Existent mais non audités, hyperparams hors-PLAN | ✅ Existent, **dataset 37 samples, test = 12 avec 0 négatif → AUC = NaN** ❗ |
| Pipeline production | ⚠️ 4 scripts mais petits et divergents du PLAN (fenêtre 1 min au lieu de 5, pas de CV, pas de figures sauvegardées hors `generate_results.py`) | ❌ 4 scripts non utilisables (pas de `main`, pas de chemin de sortie, aucune sauvegarde des artefacts) |
| `data/processed/` | ⚠️ 4 parquets dont des artefacts orphelins (`train_day1.parquet` 20 KB, `test_day2.parquet` 21 KB) | ❌ Vide |
| `saved_models/v1_final/` | ✅ Contient `model.pkl + scaler.pkl + features.json` (mais issu d'un pipeline non documenté + un dossier parallèle `saved_models/` avec un autre modèle) | ❌ Vide |
| `results/` | ⚠️ 4 figures éparses, pas de `metrics.json`, pas de classification_report | ⚠️ 2 figures EDA + 1 modeling, pas de `metrics.json` |
| Conformité PLAN_GLOBAL_SIEM | 🟡 ~30 % | 🔴 ~5 % |

**Verdict :** les deux datasets ont les ingrédients (brut OK, dépendances OK, plan global rédigé) mais **aucune des 5 phases méthodologiques** n'est terminée. Avant d'écrire la moindre ligne de code, il faut nettoyer les artefacts orphelins et repartir des templates du `PLAN_GLOBAL_SIEM.md`.

---

## 1. Audit du projet global

### 1.1 Architecture lue dans `README.md` racine

Projet PFE SOC ML — 4 modèles supervisés couvrant 4 surfaces :

| Modèle | Surface | F1 cible affiché dans README | État réel observé |
|---|---|---|---|
| CIC-IDS-2017 v2 | NetFlow | 0.994 | ✅ Pipeline + audit livrés (`cicids2017/AUDIT_RAPPORT.md`) |
| ADFA-LD v2 | Syscalls Linux | 0.957 | ✅ Pipeline + AVANCEMENT.md complet |
| **SIEM Windows v3** | Events Windows | 0.667 | 🟡 chiffres déclaratifs, pas reproduits par le code actuel |
| **Lateral Movement** | Atomic Red Team | 0.836 | 🔴 chiffres impossibles à reproduire (test set sans négatifs) |

➡️ Les chiffres présents dans le README racine pour les deux modèles concernés **ne correspondent à aucun `metrics.json` réel dans le repo** (vérifié : `siem_windows/results/` et `lateral_movement/results/` n'en contiennent pas).

### 1.2 Fil rouge `PLAN_GLOBAL_SIEM.md`

C'est le document de référence (609 lignes) :
- Méthodologie en 5 phases (Doc → EDA → Modeling → Pipeline → Audit → Doc finale)
- Templates Python pour `io_utils.py`, `preprocess.py`, `train.py`, `evaluate.py`
- Cibles métriques (siem_windows F1 ≥ 0.78, AUC ≥ 0.85 — lateral_movement F1 ≥ 0.75, recall ≥ 0.80)
- État global déclaré : siem_windows = "🟡 En cours" Phase 0, lateral_movement = "⏳ À faire"

L'audit confirme : **on est bien dans cet état**.

### 1.3 Dossiers transverses utiles

- ✅ `src/orchestrator/` + `tests/` : 16 tests pytest sur l'orchestrateur — pas impacté par ce travail
- ✅ `docker-compose.yml`, `integration/`, `live_detection/` : production / Elastic — hors périmètre
- ✅ `siem_dataset/data/otrf_datasets/` : datasets OTRF clonés, ils servent de source aux deux modèles
- ⚠️ `ancienne/` : dossier d'anciennes versions — à ne pas toucher

---

## 2. Audit `siem_windows/`

### 2.1 Données brutes

```
data/raw/day1/apt29_evals_day1_manual_2020-05-01225525.json   368 MB
data/raw/day2/apt29_evals_day2_manual_2020-05-02035409.json   1.6 GB
```

- **Format :** JSON Lines (1 event Windows par ligne, mix Sysmon / Security / PowerShell)
- **Champs clés vus à l'échantillonnage :** `EventID`, `@timestamp`, `Hostname`, `Channel`, `Image`, `TargetImage`, `CommandLine`, `ProcessName`, `TargetObject`, `ScriptBlockText`, `LogonType`, `IpAddress`, `User`, `Domain`
- **Sources cohérentes** avec `PLAN_GLOBAL_SIEM.md` (OTRF Mordor APT29 — Days 1 & 2)
- Day 1 = phase "Spray & Pray" / Day 2 = phase "Low & Slow" → **split temporel naturel** Day1 train / Day2 test

### 2.2 Documentation Phase 0 — **TOUT EST VIDE**

```
README.md              0 ligne
PLAN.md                0 ligne
AVANCEMENT.md          0 ligne
EXPLICATION_DATA.md    0 ligne
```

Seul `EXPLICATION_MODELS.md` contient quelque chose mais **c'est un paragraphe unique non-formaté** (recopié depuis une réponse ChatGPT, sans saut de ligne, sans titres Markdown réels — voir aperçu ci-dessous) :

> *"Voici le contenu ultra-détaillé, structuré et rigoureux que tu vas pouvoir coller directement dans ton fichier siem_windows/EXPLICATION_MODELS.md. […] Composant Technologique Spécification Retenue Justification […]"*

→ Le contenu sémantique est bon (cite RF, fenêtre 1 min, scores composites, etc.) **mais la forme est inutilisable telle quelle** : pas de hiérarchie, pas de tableaux Markdown rendus, pas de blocs code. **À réécrire intégralement.**

### 2.3 Pipeline `siem_windows/pipeline/`

**`io_utils.py` (19 lignes)**
- Définit `BASE_DIR`, chemins raw/processed, `MODEL_DIR = saved_models/v1_final`
- Liste 20 `TARGET_EIDS` en `str`
- ❌ **Pas de** `RANDOM_STATE`, `WINDOW_MINUTES`, hyperparams RF, `CV_FOLDS`, fonctions utilitaires partagées — contrairement au template du PLAN

**`preprocess.py` (62 lignes)**
- Lit Day1 et Day2 en JSON Lines, parse les champs utiles, regroupe par `(Hostname, window)`
- ❗ **Fenêtre = 1 minute** au lieu des **5 minutes** explicitement demandées dans `PLAN_GLOBAL_SIEM.md` (ligne 248 et template `preprocess.py`)
- Étiquetage par règles MITRE **partiellement implémenté** (PowerShell encodé, Mimikatz, EID 10 → LSASS, EID 13 → Run/RunOnce, brute_force_score ≥ 5) — pas de Schtasks (T1053.005) malgré le template
- `for _, row in group.iterrows(): … if … : label = 1; break` : casse à la première règle déclenchée → on perd la `technique` détectée (jamais sauvegardée)
- ❌ Aucun `StandardScaler`, aucune sauvegarde de `feature_names.json`, aucun split explicite, aucun `manifest.json` (cf. ce que fait ADFA-LD)
- ❌ Pas d'`if __name__ == '__main__'` propre — appelle directement `process_json_to_parquet(...)` qui écrit dans `data/processed/`

**`train.py` (34 lignes)**
- Charge `train_day1.parquet`, drop `Hostname/window/label`, fit `StandardScaler`, fit `RandomForestClassifier(200, 15, 5, balanced, rs=42)`
- Sauvegarde `model.pkl`, `scaler.pkl`, `features.json` dans `saved_models/v1_final/`
- ❌ **Aucune cross-validation** (le PLAN demande `StratifiedKFold(5)` + `cross_val_score` → CV F1 mean/std affiché dans manifest)
- ❌ Aucun `manifest.json` (hyperparams + métriques CV)
- ⚠️ `df_train = pd.read_parquet(PROCESSED_TRAIN)` — `PROCESSED_TRAIN` pointe vers `train_day1.parquet` mais le preprocess actuel écrit dans `day1.parquet` → **incohérence de noms de fichiers**

**`evaluate.py` (28 lignes)**
- Print `classification_report` + AUC, c'est tout
- ❌ Pas de `metrics.json`, pas de `confusion_matrix.png` (c'est `generate_results.py` au niveau racine qui le fait, mais hors pipeline)
- ❌ Pas de comparaison CV vs test, pas de calcul du gap, pas d'audit duplicates / leakage

**`generate_results.py` (à la racine, 56 lignes, hors `pipeline/`)**
- Recharge test + modèle, génère `confusion_matrix.png` (modeling+final) + `feature_importance.png`
- ⚠️ Ne sauvegarde toujours pas `metrics.json` ni `classification_report.txt`
- ❌ Casse le principe "tout dans `pipeline/`" — ce code devrait être dans `pipeline/evaluate.py`

### 2.4 Données intermédiaires `data/processed/`

```
day1.parquet           1.7 MB   ← écrit par preprocess.py current
day2.parquet           4.0 MB
train_day1.parquet     20 KB   ← orphelin (8 lignes ?), nom différent
test_day2.parquet      21 KB   ← orphelin idem
```

➡️ **Confusion entre 2 noms de fichiers** : `preprocess.py` actuel produit `day1.parquet` / `day2.parquet` (1.7 + 4 MB, taille cohérente), mais `train.py` cherche `train_day1.parquet` (20 KB). Soit le pipeline a été lancé un jour avec d'autres noms, soit il y a eu un renommage cassé. **À nettoyer.**

Sans `pyarrow` installé localement je n'ai pas pu charger ces parquets pour confirmer le shape — à faire en première étape Phase 0.

### 2.5 `saved_models/`

```
saved_models/
├── feature_columns.json          ← ancien modèle (orphelin)
├── rf_siem_model.pkl             ← ancien modèle (orphelin)
├── siem_scaler.pkl               ← ancien modèle (orphelin)
└── v1_final/
    ├── features.json
    ├── model.pkl
    └── scaler.pkl
```

→ **Doublon** : 2 modèles coexistent, l'un à la racine et l'un dans `v1_final/`. Aucun `manifest.json` n'indique lequel est officiel. À uniformiser : on garde `v1_final/` et on **supprime** les artefacts racine.

`features.json` du `v1_final/` :
```json
["total_events", "cnt_1", "cnt_3", "cnt_7", "cnt_8", "cnt_10", "cnt_11", "cnt_12",
 "cnt_13", "cnt_22", "cnt_4103", "cnt_4104", "cnt_4624", "cnt_4625", "cnt_4648",
 "cnt_4672", "cnt_4688", "cnt_4697", "cnt_4698", "cnt_4702",
 "brute_force_score", "lateral_move_score", "execution_score"]
```

23 features → **inférieur aux ~35 visées** par le PLAN (manque : `persistence_score`, `kerberos_score`, `logon_failure_ratio`, `entropy_eventids`, `events_per_minute`, `distinct_eventids`, etc.).

### 2.6 `results/`

```
results/eda/distribution_events_day1.png
results/eda/timeline_host_activity.png
results/modeling/confusion_matrix.png
results/modeling/feature_importance.png
results/modeling/rf_evaluation.png
results/final/confusion_matrix_final.png
```

➡️ 6 figures, **aucun fichier JSON** de métriques, **aucun classification_report.txt**, **aucun `eda_summary.json`**. Impossible de citer un chiffre vérifié dans le rapport PFE.

### 2.7 Notebooks

- `01_eda.ipynb` (308 lignes) : présent — non audité en détail, mais existence d'un fichier exécuté est confirmée
- `02_modeling.ipynb` (258 lignes) : présent — non audité en détail

À traiter en Phase 1/Phase 2 lors de la réécriture cohérente avec `PLAN.md`.

### 2.8 Écarts vis-à-vis du `PLAN_GLOBAL_SIEM.md`

| Élément attendu | État actuel | Écart |
|---|---|---|
| Phase 0 : 4 .md remplis | 0/4 documents OK | 🔴 critique |
| `WINDOW_MINUTES = 5` | Code utilise `'1min'` | 🔴 fenêtrage différent → impact sur le nombre de samples et la sémantique |
| ~35 features comportementales | 23 features | 🟡 manquent persistence/kerberos/ratios/entropie |
| `StandardScaler` fit train only | OK (dans train.py) | ✅ |
| Split temporel Day1 / Day2 | Implicite (deux fichiers) — mais nom de fichier incohérent | 🟡 |
| Cross-validation 5-fold | Absente | 🔴 |
| `manifest.json` modèle + CV | Absent | 🔴 |
| `metrics.json` final | Absent | 🔴 |
| Audit duplicates + leakage | Absent | 🔴 |
| `EXPLICATION_MODELS.md` propre | Blob non formaté | 🔴 |
| Anti-leakage : éviter `SePrivilegeList`, `LogonType=10` direct | Non vérifié | 🟡 |
| Cohérence `Channel == 'security'` vs `'Security'` | Non gérée dans le code | 🟡 |

---

## 3. Audit `lateral_movement/`

### 3.1 Données

- `data/raw/` **vide**, `data/processed/` **vide**
- Source réelle utilisée par le notebook : `siem_dataset/data/otrf_datasets/datasets/atomic/windows/`
  - `lateral_movement/host/` → **29 ZIPs** (label = 1) **+ 1 `.json` orphelin** (`purplesharp_ad_playbook_I_2020-10-22042947.json` non zippé, à gérer ou écarter explicitement)
  - `discovery/host/` → **7 ZIPs** (label = 0)
  - `collection/host/` → **1 ZIP** (label = 0)
  - **Total = 37 samples** — c'est ce que confirme le notebook (Cellule 2 : `Dataset Global : 37 échantillons`)

### 3.2 Documentation Phase 0 — **TOUT EST VIDE**

```
README.md               0 ligne
PLAN.md                 0 ligne
AVANCEMENT.md           0 ligne
EXPLICATION_DATA.md     0 ligne
EXPLICATION_MODELS.md   0 ligne
```

→ Phase 0 strictement **non commencée**.

### 3.3 Pipeline `lateral_movement/pipeline/`

**`io_utils.py` (13 lignes)** : juste `get_events_from_zip(zip_path)`. Aucune constante, aucun chemin, aucune fonction d'étiquetage. **À refaire** selon le template du PLAN.

**`preprocess.py` (14 lignes)** : juste une fonction `extract_features(events, label, technique_name)`. Aucun `main`, aucune lecture des ZIPs, aucun split, aucune sauvegarde. **Inopérant en l'état.**

**`train.py` (13 lignes)** : juste une fonction `train_model(X_train, y_train)`. Sauvegarde dans `lateral_model.pkl` (chemin relatif, pas dans `saved_models/v1_final/`). Aucun `main`, aucune CV. **Inopérant.**

**`evaluate.py` (54 lignes)** : a un `main` mais commenté, attend `X_test/y_test` passés en argument depuis un caller inexistant. Génère `evaluation_report.txt`, `confusion_matrix.png`, `roc_curve.png` dans `../results/` (relatif au cwd, pas robuste).

### 3.4 Notebook `02_modeling.ipynb` — **problème méthodologique grave**

Cellule 2 du notebook, recopiée :

```python
df_attacks = df_ml[df_ml['label'] == 1]
df_normal = df_ml[df_ml['label'] == 0]

gss = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
train_idx_atk, test_idx_atk = next(gss.split(df_attacks, groups=df_attacks['Technique']))
train_idx_norm, test_idx_norm = next(gss.split(df_normal, groups=df_normal['Technique']))

train_df = pd.concat([df_attacks.iloc[train_idx_atk], df_normal.iloc[train_idx_norm]])
test_df  = pd.concat([df_attacks.iloc[test_idx_atk], df_normal.iloc[test_idx_norm]])
```

Avec **8 négatifs** (7 discovery + 1 collection), `GroupShuffleSplit` groupé par `Technique` peut très bien envoyer **tous les 0 dans le train et 0 dans le test** parce que chaque ZIP a une technique unique → groups distincts → tirage aléatoire.

**Conséquence visible dans la sortie du notebook :**
```
Détail Test : Attaques=12 | Normal=0
ROC-AUC Score : nan
Recall is ill-defined and being set to 0.0 in labels with no true samples.
Only one class is present in y_true. ROC AUC score is not defined in that case.
```

→ Le test set actuel **ne contient AUCUNE classe 0** → les métriques affichées sont mathématiquement non définies, donc le chiffre `F1 attaque 0.836` du README racine **ne provient pas d'ici**. C'est un **artefact non reproductible**.

**Autres soucis de la même cellule :**
- Les ZIPs négatifs ne sont que 8, dont chacun a sa propre `Technique` → groupes trop fins pour GroupShuffleSplit
- 37 samples au total, c'est statistiquement très petit pour entraîner un RF + faire de la généralisation par technique
- ⚠️ **Risque de leakage par `Technique` côté positifs** (29 ZIPs lateral mov.) : si Train et Test partagent une famille (Covenant / Empire / Mimikatz / …), le RF apprend la famille au lieu du comportement → cf. avertissement du PLAN_GLOBAL_SIEM "❌ Ne PAS utiliser le nom de la technique comme feature (circularité v1)" — pas listée comme feature ici (✅ OK) mais reste un risque sémantique
- ⚠️ `Category` est gardé jusqu'au `drop_cols` : OK, pas de fuite mais à vérifier sur d'autres copies

### 3.5 `results/`

```
results/eda/eventid_distribution.png
results/eda/technique_volumes.png
results/modeling/rf_lateral_eval.png
results/final/  (vide)
```

3 figures, **0 métriques JSON, 0 classification_report**, AUC indéfini dans le notebook → rien de citable.

### 3.6 `saved_models/v1_final/` : **vide**.

### 3.7 Écarts vis-à-vis du PLAN_GLOBAL_SIEM

| Attendu | État actuel | Écart |
|---|---|---|
| 5 documents Phase 0 | 0/5 | 🔴 |
| Pipeline en 3 scripts modulaires + io_utils | 4 fichiers mais aucun exécutable | 🔴 |
| GroupShuffleSplit par **famille** d'attaque, pas par ZIP | Split par `Technique` (= 1 ZIP = 1 groupe) | 🔴 critique |
| Au moins 1 sample négatif dans le test | **0** dans le test actuel | 🔴 critique |
| Métriques sauvegardées | Aucune | 🔴 |
| Audit duplicates + leakage | Aucun | 🔴 |
| Modèle final + manifest | Inexistants | 🔴 |

---

## 4. Risques et pièges identifiés à traiter dans la suite du travail

| # | Risque | Conséquence si ignoré | Mitigation à prévoir |
|---|---|---|---|
| R1 | Doublons train↔test côté `siem_windows` (cf. CIC-IDS) | F1 gonflé | `df.drop_duplicates()` post-features + audit `pd.util.hash_pandas_object` |
| R2 | Lateral movement avec 0 négatifs en test | AUC NaN, métriques non définies | Re-design du split : grouper par **famille** (`covenant_*`, `empire_*`, …) au lieu de chaque ZIP ; ou stratifier explicitement |
| R3 | Fenêtre 1 min vs 5 min sur SIEM Windows | Trop de fenêtres faibles (5 events min), bruite l'apprentissage | Aligner sur `WINDOW_MINUTES=5` du PLAN, comparer empiriquement |
| R4 | `EXPLICATION_MODELS.md` siem_windows non rédigé | Soutenance non préparée | Réécrire entièrement à la fin (Phase 5) |
| R5 | Doublon artefacts modèles (`saved_models/*.pkl` racine + `v1_final/*.pkl`) | Confusion sur lequel est officiel | Supprimer les `*.pkl` racine après confirmation, ne garder que `v1_final/` |
| R6 | `train_day1.parquet` / `test_day2.parquet` orphelins (20 KB) | Fichiers fantômes qui parasitent les chargements | Supprimer après que le pipeline les régénère proprement |
| R7 | Channel = `'Security'` vs `'security'` non géré | Mauvais comptages des events 4624/4625 | Normaliser `df['Channel'].str.lower()` ou utiliser le mapping du template PLAN |
| R8 | Feature dominante > 25 % côté SIEM Windows | Anti-leakage NOK | Surveiller `model.feature_importances_.max()` ≤ 0.25 |
| R9 | RF non régularisé / fit sans CV | Overfitting non détecté | Ajouter `StratifiedKFold` CV obligatoire + reporter `gap CV-test` |
| R10 | Pas de `manifest.json` ni `metrics.json` | Soutenance non défendable (rien de citable) | Sauvegarder systématiquement (`saved_models/v1_final/manifest.json`, `results/final/metrics.json`) |

---

## 5. Plan d'action recommandé (avant de toucher au code)

### 5.1 Nettoyage préalable (à faire en 1 passe, après validation utilisateur)

- 🗑️ Supprimer `siem_windows/saved_models/feature_columns.json`, `rf_siem_model.pkl`, `siem_scaler.pkl` (versions orphelines à la racine de `saved_models/`)
- 🗑️ Supprimer `siem_windows/data/processed/train_day1.parquet` et `test_day2.parquet` (orphelins 20 KB)
- 🗑️ Décider du sort de `lateral_movement/.../atomic/windows/lateral_movement/host/purplesharp_ad_playbook_I_2020-10-22042947.json` (json non zippé) : l'ignorer pour cohérence ou le zipper
- ⚠️ Ne pas toucher aux dossiers `adfa_ld/`, `cicids2017/`, `src/`, `tests/`, `integration/`, `live_detection/`, `siem_dataset/` (source en lecture seule)

### 5.2 Ordre de travail proposé (réplique exacte d'ADFA + CIC-IDS-2017)

```
Pour CHACUN des deux datasets, dans l'ordre :

Phase 0 — Documentation (Day J)
   ├─ Écrire EXPLICATION_DATA.md (chiffres réels extraits via Python)
   ├─ Écrire PLAN.md (3 phases, hyperparams, structure fichiers)
   ├─ Écrire AVANCEMENT.md (squelette journal)
   └─ Écrire README.md (carte du projet)

Phase 1 — EDA (Day J+1)
   ├─ Refondre notebooks/01_eda.ipynb selon PLAN.md
   ├─ Sauvegarder results/eda/eda_summary.json + figures
   └─ Mettre à jour AVANCEMENT.md (section Phase 1)

Phase 2 — Modeling (Day J+2)
   ├─ Refondre notebooks/02_modeling.ipynb
   ├─ Random Forest balanced + CV stratifiée
   ├─ Évaluer une seule fois sur test
   ├─ Sauvegarder results/modeling/metrics.json + figures
   └─ AVANCEMENT.md section Phase 2

Phase 3 — Pipeline production (Day J+3)
   ├─ Réécrire pipeline/io_utils.py selon template PLAN_GLOBAL
   ├─ Réécrire pipeline/preprocess.py (fenêtre 5 min, ~35 features, scaler)
   ├─ Réécrire pipeline/train.py (CV 5-fold + manifest.json)
   ├─ Réécrire pipeline/evaluate.py (metrics.json + 4 figures)
   ├─ Exécuter en 3 commandes, vérifier parité avec notebook
   └─ Régénérer saved_models/v1_final/ + results/final/

Phase 4 — Audit critique (Day J+3, juste après Phase 3)
   ├─ Mesurer doublons internes train / test
   ├─ Mesurer leakage train↔test par hash
   ├─ Si seuils > 1 % : corriger preprocess + rerun + créer AUDIT_RAPPORT.md (modèle CIC-IDS)
   └─ Documenter dans AVANCEMENT.md

Phase 5 — Documentation finale (Day J+4)
   ├─ Réécrire EXPLICATION_MODELS.md (vue d'ensemble, hyperparams, métriques, limites)
   ├─ Mettre à jour README.md (carte projet + métriques finales)
   └─ Finaliser AVANCEMENT.md
```

### 5.3 Critères de réussite (à atteindre avant soutenance)

**siem_windows**
- ✅ F1 binaire ≥ 0.78, Recall ≥ 0.80, Precision ≥ 0.70, AUC ≥ 0.85
- ✅ Gap CV-test < 0.10
- ✅ Max feature importance < 0.25
- ✅ Duplicates train ↔ test < 1 %
- ✅ `manifest.json` + `metrics.json` présents et cohérents

**lateral_movement**
- ✅ F1 binaire (classe 1) ≥ 0.75
- ✅ Recall ≥ 0.80 sur techniques jamais vues
- ✅ AUC ≥ 0.85
- ✅ FPR sur discovery/collection < 10 %
- ✅ **Au moins 1 sample négatif présent dans le test** (sans quoi métriques non calculables)
- ✅ Pas de feature `Technique` / `Category` parmi les inputs du modèle

---

## 6. Conclusion de l'audit

Le projet global est solide (ADFA-LD et CIC-IDS-2017 livrés, orchestrateur en place, plan documenté). Les deux datasets restants partagent le même schéma de défaut :

1. **Phase 0 inexistante** sur les deux datasets (les `.md` sont des fichiers vides)
2. **Pipelines incomplets** — soit sous-spécifiés (siem_windows) soit non exécutables (lateral_movement)
3. **Pas de métriques sauvegardées** — donc rien de citable dans le rapport PFE
4. **Bugs méthodologiques connus** non corrigés (test sans négatifs côté lateral_movement, fenêtre 1 min hors-PLAN côté siem_windows, pas de CV)

➡️ **Avant** d'entamer le travail proprement dit, attendre la validation de cet audit. Ensuite seulement on entamera la **Phase 0 du dataset `siem_windows`** (4 fichiers `.md` à écrire en s'appuyant sur les vrais chiffres extraits via Python), puis on enchaînera Phase 1 → Phase 5, et idem pour `lateral_movement`.

*Audit produit le 2026-05-20 — fichier `AUDIT_SIEM_LATERAL.md` à la racine du projet.*
