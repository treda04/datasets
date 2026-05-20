# PLAN — Modèle SIEM Windows (APT29)

**Auteur :** Reda — PFE UIR 2026
**Lié à :** `EXPLICATION_DATA.md` (chiffres réels), `PLAN_GLOBAL_SIEM.md` (méthodologie générale)
**Objectif :** classifier en binaire les **fenêtres 1 min × hostname** comme `0 = normal` ou `1 = attaque APT29`.

Ce PLAN décrit la **stratégie complète** : EDA → modeling → pipeline production → audit → doc finale. Il est conçu pour être suivi pas-à-pas sans dépendance externe.

---

## 1. Vue d'ensemble en 3 phases

| Phase | Livrable principal | Statut | Critère de sortie |
|---|---|---|---|
| **Phase 1 — EDA** | `notebooks/01_eda.ipynb` + `results/eda/eda_summary.json` | à faire | distributions vues, labels prototypes vérifiés |
| **Phase 2 — Modeling** | `notebooks/02_modeling.ipynb` + `results/modeling/metrics.json` | à faire | F1 ≥ 0.78, AUC ≥ 0.85, gap CV-test < 0.10 |
| **Phase 3 — Pipeline production** | `pipeline/{io_utils,preprocess,train,evaluate}.py` + `saved_models/v1_final/` + `results/final/` | à faire | parité bit-à-bit avec notebook + 4 figures + manifest |
| **Phase 4 — Audit** | `AUDIT_RAPPORT.md` si besoin de correction | optionnelle | duplicates train↔test < 1 % |
| **Phase 5 — Doc finale** | `EXPLICATION_MODELS.md` (réécriture complète) | à faire | rapport prêt pour soutenance |

---

## 2. Décisions techniques figées (issues de l'EDA brut)

### 2.1 Données & split

| Décision | Valeur | Justification |
|---|---|---|
| Granularité fenêtre | **1 minute × hostname** | 5 min → 60 samples (CV impossible), 1 min → ~200 viable. Cf §4.2 EXPLICATION_DATA |
| Filtre minimum | `len(group) >= 5 events` | élimine les minutes mortes (~30 % du brut) |
| Stratégie de split | **temporel** Day 1 → train / Day 2 → test | Day 2 = "Low & Slow" furtif → vrai test de généralisation |
| Stockage intermédiaire | `data/processed/*.parquet` | pyarrow déjà dans le venv |

### 2.2 Features (~35 colonnes)

| Catégorie | Colonnes |
|---|---|
| Volumétrie | `total_events`, `events_per_minute`, `distinct_eventids`, `entropy_eventids` |
| Sysmon | `cnt_1`, `cnt_3`, `cnt_7`, `cnt_8`, `cnt_10`, `cnt_11`, `cnt_12`, `cnt_13`, `cnt_22` |
| PowerShell | `cnt_4103`, `cnt_4104` |
| Security AD | `cnt_4624`, `cnt_4625`, `cnt_4648`, `cnt_4672`, `cnt_4688`, `cnt_4697`, `cnt_4698`, `cnt_4702`, `cnt_4768`, `cnt_4769`, `cnt_4771`, `cnt_4776` |
| Scores composites | `brute_force_score`, `lateral_move_score`, `persistence_score`, `execution_score`, `kerberos_score` |
| Ratios | `logon_failure_ratio` |

**Colonnes interdites (anti-leakage)** : `Hostname`, `window`, `day`, `technique`, `SePrivilegeList`, `LogonType=10 direct`, `ScriptBlockText brut`.

### 2.3 Règles d'étiquetage (rules-based MITRE)

Une fenêtre est `label = 1` si **au moins une** des conditions suivantes est observée :

| Condition | MITRE | Activité réelle dans le dataset |
|---|---|---|
| `CommandLine` ou `ScriptBlockText` matche `-enc` / `-encodedcommand` | T1059.001 | 33 events |
| `CommandLine` matche `downloadstring` / `iex (` / `invoke-expression` | T1059.001 | 28 events |
| `CommandLine` contient `mimikatz` | T1003 | 3 events |
| Sysmon EID `10` avec `TargetImage` matche `lsass.exe` ET `SourceImage` hors `\windows\system32\` | T1003.001 | ≈ 50-200 events (à raffiner Phase 1) |
| Sysmon EID `13` avec `TargetObject` matche `\Run\` ou `\RunOnce\` | T1547.001 | 6 events |
| `cnt_4625 >= 5` | T1110 | **0** (inactive sur ce dataset) |
| `cnt_4648 >= 3` | T1021 lateral | à mesurer Phase 1 |

Les règles inactives (`schtasks`, `4625`) sont **gardées dans le code** pour portabilité mais documentées comme inertes ici.

### 2.4 Modèle

| Hyperparamètre | Valeur | Justification |
|---|---|---|
| Algo | `RandomForestClassifier` | Robuste aux features hétérogènes (comptages + ratios), interprétable, immuneà l'échelle |
| `n_estimators` | 200 | Convergence OOB observée vers 150-200 sur datasets similaires |
| `max_depth` | 15 | Garde-fou overfitting ; permet de capter des combinaisons d'EID (15 features chained) |
| `min_samples_leaf` | 5 | Au moins 5 fenêtres pour qu'une feuille existe — évite la mémorisation 1 fenêtre = 1 feuille |
| `class_weight` | `balanced` | Déséquilibre 7:1 attendu (positifs minoritaires) |
| `random_state` | 42 | Reproductibilité bit-à-bit |
| `n_jobs` | -1 | Tous les cœurs |
| Pré-scaling | `StandardScaler` fit train only | Pas critique pour RF mais standard MLOps |
| Calibration | `CalibratedClassifierCV(isotonic, cv=5)` **optionnelle** | À ajouter Phase 2 si AUC ≥ 0.85 mais probas mal réparties |

### 2.5 Évaluation & cross-validation

| Choix | Valeur | Justification |
|---|---|---|
| CV | `StratifiedKFold(n_splits=5, shuffle=True, random_state=42)` | Sur train Day 1 uniquement |
| Métrique CV | F1 binaire | Aligné avec la métrique finale |
| Seuil de décision | **0.50** (défaut) | À tuner en Phase 2 si recall < 0.80 (méthode F2 sur CV-train comme ADFA v2) |
| Test set | Day 2 — évalué **une seule fois** | Anti-overfitting méthodologique |
| Métriques rapportées | F1, F2, AUC, Precision, Recall, gap CV-test, max feature importance, confusion matrix, classification_report | toutes sauvegardées dans `metrics.json` |

---

## 3. Cibles métriques (critères d'acceptation)

| Métrique | Cible | Catégorie |
|---|---|---|
| F1 binaire (test) | ≥ 0.78 | performance |
| F2 binaire (test) | ≥ 0.80 | orientation IDS (recall prioritaire) |
| Recall (test) | ≥ 0.80 | ne pas rater une attaque |
| Precision (test) | ≥ 0.70 | éviter alert fatigue |
| AUC OVR (test) | ≥ 0.85 | séparation des classes |
| Gap CV-test F1 | < 0.10 | pas d'overfitting |
| Max feature importance | < 0.25 | pas de shortcut |
| Doublons train internes | < 5 % | qualité données |
| Doublons test internes | < 5 % | qualité données |
| Leakage train↔test | < 1 % | intégrité méthodologique |

**Si une cible n'est pas atteinte**, on documente honnêtement le pourquoi et on propose un levier d'amélioration (cf. méthodologie ADFA v1 → v2).

---

## 4. Structure de fichiers cible

```
siem_windows/
├── README.md                          ← Phase 0 (carte projet)
├── PLAN.md                            ← Phase 0 (ce fichier)
├── EXPLICATION_DATA.md                ← Phase 0 (analyse données)
├── EXPLICATION_MODELS.md              ← Phase 5 (rapport final)
├── AVANCEMENT.md                      ← Phase 0+ (journal continu)
├── AUDIT_RAPPORT.md                   ← Phase 4 (si problème détecté)
│
├── notebooks/
│   ├── 01_eda.ipynb                   ← Phase 1
│   └── 02_modeling.ipynb              ← Phase 2
│
├── scripts_aux/
│   └── extract_raw_stats.py           ← stats brutes Phase 0 (déjà fait)
│
├── pipeline/
│   ├── __init__.py
│   ├── io_utils.py                    ← constantes, paths, stream, label_window
│   ├── preprocess.py                  ← stream → window → features → split → scaler → parquet+npy
│   ├── train.py                       ← load → CV 5-fold → fit RF → save model + manifest
│   └── evaluate.py                    ← load → predict → 4 figures + metrics.json
│
├── data/
│   ├── raw/{day1,day2}/*.json         ← brut OTRF (input read-only)
│   └── processed/                     ← parquets + npy + scaler.pkl + feature_names.json
│
├── results/
│   ├── eda/                           ← Phase 1 : raw_stats.json + 4-5 figures + eda_summary.json
│   ├── modeling/                      ← Phase 2 : metrics.json + 4 figures
│   └── final/                         ← Phase 3 : metrics.json + 4 figures (post-pipeline)
│
└── saved_models/v1_final/
    ├── model.pkl
    ├── scaler.pkl
    ├── feature_names.json
    └── manifest.json
```

---

## 5. Workflow Phase 1 — EDA

**But :** rendre visibles les chiffres déjà extraits, vérifier que les règles d'étiquetage produisent un signal, sauvegarder un résumé exploitable.

Notebook `01_eda.ipynb` — étapes :

1. Charger `results/eda/raw_stats.json` (déjà extrait)
2. Stream Day 1 + Day 2 → DataFrame léger (`@timestamp`, `EventID`, `Hostname`, `Channel`, `CommandLine`, `TargetImage`, `TargetObject`, `ScriptBlockText`)
3. Distribution par hostname et par EventID (barplots)
4. Timeline d'activité Day 1 vs Day 2 (events/minute)
5. **Tester les 5 règles d'étiquetage** sur des events individuels → compter combien de fenêtres seraient positives
6. Distribution attendue des labels après fenêtrage 1 min
7. Sauvegarder :
   - `results/eda/eda_summary.json` (toutes les stats agrégées)
   - `results/eda/distribution_eventids.png`
   - `results/eda/timeline_hosts.png`
   - `results/eda/label_density.png`
   - `results/eda/channel_normalization_impact.png`

**Critère de sortie Phase 1 :** on connaît la distribution exacte des labels finaux, le ratio positif/négatif, et on a validé qu'aucune règle ne produit `≥ 80 %` de positifs (signe de label-leakage).

---

## 6. Workflow Phase 2 — Modeling

**But :** prototyper le modèle complet dans `02_modeling.ipynb`, vérifier qu'il dépasse les cibles avant d'extraire en production.

Étapes du notebook :

1. **Reload** des events → DataFrame complet (réutilise le code Phase 1)
2. **Normalisation** Channel (`.str.casefold()`), `EventID` cast en `str`
3. **Fenêtrage** 1 min × hostname avec filtre `len(group) >= 5`
4. **Computation features** (35 colonnes selon §2.2)
5. **Labelling** par les 5 règles MITRE (§2.3)
6. **Split temporel** Day 1 / Day 2
7. **Drop colonnes anti-leakage** (Hostname, window, day, technique)
8. **StandardScaler** fit sur train uniquement
9. **Cross-validation** : `cross_val_score(rf, X_train, y_train, cv=StratifiedKFold(5), scoring='f1')`
10. **Fit final** RF sur tout le train
11. **Prédiction** test (une seule fois)
12. **Métriques** F1, F2, AUC, Precision, Recall, gap CV-test, classification_report
13. **Figures** : confusion matrix, ROC curve, PR curve, feature importance (top 15)
14. **Sauvegarde** `results/modeling/metrics.json` + figures

**Critère de sortie Phase 2 :** F1 ≥ 0.78, AUC ≥ 0.85, gap < 0.10. Sinon → itérer (tuning seuil, ajout features, etc.) avant Phase 3.

---

## 7. Workflow Phase 3 — Pipeline production

**But :** rejouer la Phase 2 en 3 commandes terminal sans Jupyter, avec parité bit-à-bit.

### 7.1 `pipeline/io_utils.py`

Constantes + fonctions partagées :
```python
BASE = Path(__file__).resolve().parent.parent
RAW = {"day1": BASE / "data/raw/day1/...", "day2": BASE / "data/raw/day2/..."}
PROCESSED = BASE / "data/processed"
MODELS = BASE / "saved_models/v1_final"
RESULTS = BASE / "results/final"

RANDOM_STATE = 42
WINDOW_MINUTES = 1
MIN_EVENTS_PER_WINDOW = 5
CV_FOLDS = 5
RF_PARAMS = dict(n_estimators=200, max_depth=15, min_samples_leaf=5,
                 class_weight='balanced', random_state=42, n_jobs=-1)

TARGET_EIDS = [...]                  # 22 EID surveillés
ESSENTIAL_FIELDS = [...]             # champs lus dans le JSON brut

def stream_events(path) -> Iterator[dict]: ...
def normalize_channel(s) -> str: ...
def label_window(events_df) -> tuple[int, str | None]: ...
def compute_features(group_df) -> dict[str, float]: ...
```

### 7.2 `pipeline/preprocess.py`

```
1. Stream day1 + day2 → DataFrame brut (avec colonne 'day')
2. Normalise Channel + cast EventID
3. Drop @timestamp manquants
4. Floor par 1 min → window
5. groupby (Hostname, window, day) → list[events]
6. Filtre len >= 5
7. Pour chaque groupe : compute_features + label_window
8. DataFrame de fenêtres
9. Split temporel (day==day1 / day==day2)
10. Drop colonnes interdites (Hostname/window/day/technique)
11. StandardScaler fit train, transform train+test
12. Save : X_train.npy, X_test.npy, y_train.npy, y_test.npy, scaler.pkl,
         feature_names.json, train.parquet, test.parquet, manifest_preprocess.json
```

### 7.3 `pipeline/train.py`

```
1. Load X_train, y_train
2. RF balanced (cf RF_PARAMS)
3. CV 5-fold sur train : f1 + auc (mean + std)
4. Fit final sur tout le train
5. Save : model.pkl + manifest.json (RF params + CV metrics + feature_names)
```

### 7.4 `pipeline/evaluate.py`

```
1. Load model + scaler + X_test + y_test
2. Predict
3. Compute F1, F2, AUC, Precision, Recall, gap CV-test
4. Save figures :
   - confusion_matrix.png
   - roc_pr_curves.png
   - feature_importance.png (top 15)
   - per_class_metrics.png
5. Save metrics.json + classification_report.txt
```

### 7.5 Commande d'exécution

```bash
cd siem_windows
python pipeline/preprocess.py    # ~2-3 min (stream 2 GB)
python pipeline/train.py         # ~30 s
python pipeline/evaluate.py      # ~5 s
```

**Critère de sortie Phase 3 :** les 3 scripts tournent en séquence sans erreur ; les métriques du `results/final/metrics.json` matchent celles du `notebooks/02_modeling.ipynb` à `1e-4` près.

---

## 8. Workflow Phase 4 — Audit anti-leakage

Identique à `cicids2017/AUDIT_RAPPORT.md` :

```python
import numpy as np, pandas as pd
X_train = np.load('data/processed/X_train.npy')
X_test  = np.load('data/processed/X_test.npy')

n_train_dup = pd.DataFrame(X_train).duplicated().sum()
n_test_dup  = pd.DataFrame(X_test).duplicated().sum()

train_hashes = set(pd.util.hash_pandas_object(pd.DataFrame(X_train), index=False))
test_hashes  = pd.util.hash_pandas_object(pd.DataFrame(X_test), index=False).values
n_leak = sum(1 for h in test_hashes if h in train_hashes)

assert n_leak / len(X_test) < 0.01, "Leakage > 1 %"
assert n_train_dup / len(X_train) < 0.05, "Doublons train > 5 %"
assert n_test_dup / len(X_test) < 0.05, "Doublons test > 5 %"
```

**Si KO :** ajouter `df.drop_duplicates()` dans `preprocess.py` puis rerun + créer `AUDIT_RAPPORT.md` documentant la correction (modèle CIC-IDS).

---

## 9. Workflow Phase 5 — `EXPLICATION_MODELS.md` final

Sections obligatoires (rédigées **après** que les Phase 3+4 soient livrées) :

1. **Vue d'ensemble du pipeline** (1 page)
2. **Détail hyperparamètres** + pourquoi chaque choix (2 pages)
3. **Métriques** globales + par classe (chiffres réels, pas inventés) (1 page)
4. **Anti-overfitting checklist** (10 critères, validés ou non) (1 page)
5. **Feature importance** + interprétation cyber (1 page)
6. **Limites** assumées + axes d'amélioration (1 page)
7. **3 phrases pour la soutenance** (synthèse) (½ page)

**Ce qu'on NE met PAS** : du copier-coller générique, des phrases sans chiffres précis, des affirmations non vérifiables.

---

## 10. Calendrier proposé

| Phase | Effort estimé |
|---|---|
| Phase 1 EDA | ½ journée (1 notebook + 4-5 figures) |
| Phase 2 Modeling | ½ journée (1 notebook + métriques + figures) |
| Phase 3 Pipeline | ½ journée (4 scripts + parité) |
| Phase 4 Audit | ½ journée (mesure + correction éventuelle) |
| Phase 5 Doc finale | ½ journée (rédaction) |
| **Total** | **~2.5 jours** dans le scénario optimiste |

---

## 11. Risques identifiés et mitigations

| Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|
| **Trop peu de samples positifs** après labelling (< 20) | moyenne | élevé | Élargir les règles : ajouter `cnt_4648 >= 3`, `cnt_4672 >= 5`, baisser seuils |
| **Doublons train↔test** (Day 2 partage UTICA avec Day 1) | moyenne | élevé | `drop_duplicates()` post-features + audit hash (Phase 4) |
| **Feature dominante** (probablement `cnt_10` ou `cnt_4103`) | élevée | moyen | Documenter ; si > 25 %, supprimer la feature et re-fit |
| **Overfitting** (gap CV-test > 0.10) | moyenne | moyen | Réduire `max_depth` (15 → 10), augmenter `min_samples_leaf` (5 → 10) |
| **F1 < 0.78 après tuning** | faible | élevé | Accepter et documenter (comme ADFA v1 → v2 a fait avec Web_Shell) |
| **Mauvais étiquetage** (faux positifs LSASS = bruit système) | élevée | moyen | Filtrer `SourceImage` system32 dans `label_window` |

---

*PLAN.md figé pour exécution Phases 1 → 5. Toute déviation par rapport à ce plan sera consignée dans `AVANCEMENT.md` avec justification.*
