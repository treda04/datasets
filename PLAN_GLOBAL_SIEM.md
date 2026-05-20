# PLAN GLOBAL — siem_windows + lateral_movement

**Objectif :** finaliser les 2 modèles Windows du projet PFE en suivant la même méthodologie qu'ADFA-LD et CIC-IDS-2017.

**Date :** 2026-05-19
**Deadline soutenance :** 2026-06-02

Ce document est un **fil rouge auto-suffisant** : si la session avec Claude expire, tu peux reprendre seul (ou avec une nouvelle session) en suivant les étapes ci-dessous.

---

## 🎯 ÉTAT GLOBAL

| Projet | Phase 0 (Doc) | Phase 1 (EDA) | Phase 2 (Model) | Phase 3 (Pipeline) | Audit | Doc finale |
|---|---|---|---|---|---|---|
| **siem_windows** | 🟡 En cours | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| **lateral_movement** | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |

Légende : ✅ Terminé · 🟡 En cours · ⏳ À faire

---

## 📋 MÉTHODOLOGIE (à appliquer pour les 2 modèles)

Chaque dataset suit **EXACTEMENT** la même démarche que ADFA-LD et CIC-IDS-2017 :

### Phase 0 — Documentation initiale (4 fichiers)

1. **EXPLICATION_DATA.md** : A→Z des données avec chiffres réels extraits via Python
2. **PLAN.md** : Stratégie en 3 phases, hyperparams cibles, structure fichiers
3. **AVANCEMENT.md** : Journal de bord squelette
4. **README.md** : Carte du projet (où trouver quoi)

### Phase 1 — EDA (notebook interactif)

- `notebooks/01_eda.ipynb`
- Streaming + extraction features essentielles
- Visualisations : distributions, timelines, top EventIDs
- Test de règles d'étiquetage prototype
- Sauvegarder `results/eda/eda_summary.json` + figures

### Phase 2 — Modeling (notebook)

- `notebooks/02_modeling.ipynb`
- Reprendre pipeline complet de bout en bout
- Random Forest balanced + CV stratifiée
- Évaluer une seule fois sur test
- Métriques par classe + matrice confusion + ROC/PR + feature importance
- Sauvegarder `results/modeling/metrics.json` + figures

### Phase 3 — Pipeline production (4 scripts)

- `pipeline/io_utils.py` — module partagé (constantes, fonctions chargement, règles étiquetage)
- `pipeline/preprocess.py` — Étape 1/3
- `pipeline/train.py` — Étape 2/3
- `pipeline/evaluate.py` — Étape 3/3

Exécution :
```bash
python pipeline/preprocess.py
python pipeline/train.py
python pipeline/evaluate.py
```

Sorties dans `data/processed/`, `saved_models/v1_final/`, `results/final/`.

### Phase 4 — Audit critique

Vérifier **AVANT de livrer** :
```python
import numpy as np, pandas as pd
X_train = np.load('data/processed/X_train.npy')
X_test = np.load('data/processed/X_test.npy')
n_train_dup = pd.DataFrame(X_train).duplicated().sum()
n_test_dup = pd.DataFrame(X_test).duplicated().sum()
# Leakage train↔test
train_hashes = set(pd.util.hash_pandas_object(pd.DataFrame(X_train), index=False))
test_hashes = pd.util.hash_pandas_object(pd.DataFrame(X_test), index=False)
n_leak = sum(1 for h in test_hashes if h in train_hashes)
print(f"Doublons train: {n_train_dup}, test: {n_test_dup}, leakage: {n_leak}")
```

Si problème : créer `AUDIT_RAPPORT.md` documentant la correction.

### Phase 5 — Documentation finale

Créer **`EXPLICATION_MODELS.md`** avec :
- Vue d'ensemble pipeline
- Détail hyperparamètres (pourquoi chaque choix)
- Métriques globales + par classe
- Anti-overfitting checklist
- Limites + mon avis honnête
- 3 phrases pour la soutenance

---

## 🪟 MODÈLE 1 — siem_windows

### Données
- Source : `siem_dataset/data/otrf_datasets/datasets/compound/apt29/` (déjà décompressé dans `siem_windows/data/raw/`)
- Day 1 : 196 081 events (367 MB JSON)
- Day 2 : 587 286 events (1.6 GB JSON)
- Total : 783 367 events Sysmon + Security + PowerShell

### Stratégie ML
**Classification binaire de fenêtres 5 min** :
- Agrégation par `(Hostname, fenêtre 5 min)` → ~11 000 samples
- ~35 features comportementales (comptages, scores agrégés, ratios)
- Étiquetage par règles MITRE (PowerShell encodé, LSASS, Registry Run, Brute force burst, etc.)
- Split **TEMPOREL** : Day 1 train / Day 2 test

### Hyperparamètres cibles
```python
RandomForestClassifier(
    n_estimators=200, max_depth=15, min_samples_leaf=5,
    class_weight='balanced', random_state=42, n_jobs=-1,
)
StandardScaler (fit sur train seulement)
```

### Métriques cibles
- F1 binaire ≥ 0.78
- Recall ≥ 0.80
- Precision ≥ 0.70
- AUC ≥ 0.85
- Gap CV-test < 0.10

### Anti-leakage spécifique
- ❌ Ne PAS utiliser `SePrivilegeList`
- ❌ Ne PAS utiliser `LogonType=10` direct (passer par `rdp_logon_ratio`)
- ✅ Fusionner `Channel == 'security'` et `'Security'`
- ✅ Vérifier doublons train/test post-pipeline

### Fichiers à créer (cycle complet)
```
siem_windows/
├── README.md                          ← Phase 0
├── PLAN.md                            ← Phase 0 ✅ FAIT
├── EXPLICATION_DATA.md                ← Phase 0 ✅ FAIT
├── EXPLICATION_MODELS.md              ← Phase 5
├── AVANCEMENT.md                      ← Phase 0
├── notebooks/
│   ├── 01_eda.ipynb                   ← Phase 1
│   └── 02_modeling.ipynb              ← Phase 2
├── pipeline/
│   ├── __init__.py
│   ├── io_utils.py                    ← Phase 3
│   ├── preprocess.py                  ← Phase 3
│   ├── train.py                       ← Phase 3
│   └── evaluate.py                    ← Phase 3
├── results/
│   ├── eda/                           ← Phase 1
│   ├── modeling/                      ← Phase 2
│   └── final/                         ← Phase 3
└── saved_models/v1_final/             ← Phase 3
```

---

## 🔀 MODÈLE 2 — lateral_movement

### Données
- Source : `siem_dataset/data/otrf_datasets/datasets/atomic/windows/`
- **POSITIFS** : `lateral_movement/host/` — 29 ZIPs (~55 MB), 1 ZIP = 1 technique d'attaque
- **NÉGATIFS** : `discovery/host/` (7 ZIPs) + `collection/host/` (1 ZIP) — 8 ZIPs (~2 MB)

### Techniques POSITIVES principales
- Covenant (PSRemoting, DCOM, WMI, SC, SMB)
- Empire (PSExec, PSRemoting, WMI, SMB)
- Mimikatz (CVE-2020-1472 Zerologon)
- PurpleSharp (AD playbook)
- schtask (create, modify)
- AAD Internals

### Stratégie ML
**Classification binaire** : fenêtre lateral movement (1) vs autre tactique (0)
- 1 fenêtre par ZIP (chaque ZIP = 1 exécution d'attaque)
- ~35 features comportementales identiques à siem_windows
- Split par **GroupShuffleSplit** par technique (train sur certaines techniques, test sur d'autres) → généralisation
- Random Forest balanced

### Hyperparamètres cibles
Identiques à siem_windows.

### Métriques cibles
- F1 binaire ≥ 0.75
- Recall ≥ 0.80 sur techniques jamais vues à l'entraînement
- AUC ≥ 0.85
- FPR sur discovery/collection < 10%

### Anti-leakage spécifique
- ❌ Ne PAS utiliser le nom de la technique comme feature (circularité v1)
- ✅ GroupShuffleSplit par technique → certaines techniques entièrement en test
- ✅ Features = comptages d'EventIDs purs

### Fichiers à créer (cycle complet)
```
lateral_movement/
├── README.md                          ← Phase 0
├── PLAN.md                            ← Phase 0
├── EXPLICATION_DATA.md                ← Phase 0
├── EXPLICATION_MODELS.md              ← Phase 5
├── AVANCEMENT.md                      ← Phase 0
├── notebooks/
│   ├── 01_eda.ipynb                   ← Phase 1
│   └── 02_modeling.ipynb              ← Phase 2
├── pipeline/
│   ├── __init__.py
│   ├── io_utils.py                    ← Phase 3
│   ├── preprocess.py                  ← Phase 3
│   ├── train.py                       ← Phase 3
│   └── evaluate.py                    ← Phase 3
├── results/
│   ├── eda/                           ← Phase 1
│   ├── modeling/                      ← Phase 2
│   └── final/                         ← Phase 3
└── saved_models/v1_final/             ← Phase 3
```

---

## 🛠️ TEMPLATES DE CODE

### Template `io_utils.py` (à adapter pour chaque dataset)

```python
"""Utilitaires partagés du pipeline."""
from __future__ import annotations
from pathlib import Path
import json
import pandas as pd
import numpy as np

# Chemins
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "saved_models" / "v1_final"
RESULTS_DIR = PROJECT_ROOT / "results" / "final"

# Constantes pipeline
RANDOM_STATE = 42
TEST_SIZE = 0.3
RF_N_ESTIMATORS = 200
RF_MAX_DEPTH = 15
RF_MIN_SAMPLES_LEAF = 5
CV_FOLDS = 5
WINDOW_MINUTES = 5

# Champs essentiels JSON Mordor
ESSENTIAL_FIELDS = [
    '@timestamp', 'EventID', 'Channel', 'Hostname',
    'LogonType', 'TargetUserName', 'IpAddress', 'TargetServerName',
    'NewProcessName', 'CommandLine', 'ParentProcessName',
    'Image', 'ParentImage', 'User',
    'TargetImage', 'GrantedAccess',
    'TargetObject', 'TargetFilename',
    'DestinationIp', 'DestinationPort',
    'ScriptBlockText',
]

def stream_events(json_path):
    """Yield events from a JSON Lines file."""
    with open(json_path, 'rb') as f:
        for line in f:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

def extract_essential(ev):
    """Garde uniquement les champs essentiels."""
    return {k: ev.get(k) for k in ESSENTIAL_FIELDS}

# Règles d'étiquetage MITRE
def label_window(events):
    """Retourne (label, technique). 1 si fenêtre contient une attaque APT29."""
    for ev in events:
        cmd = (ev.get('CommandLine','') or '').lower()
        if '-enc ' in cmd or 'iex (' in cmd or 'downloadstring' in cmd:
            return 1, 'T1059.001'
        if 'mimikatz' in cmd:
            return 1, 'T1003'
        if ev.get('EventID') == 10:
            if 'lsass.exe' in (ev.get('TargetImage','') or '').lower():
                return 1, 'T1003.001'
        if ev.get('EventID') == 13:
            obj = (ev.get('TargetObject','') or '').lower()
            if r'\run' in obj or r'\runonce' in obj:
                return 1, 'T1547.001'
        if 'schtasks' in cmd and '/create' in cmd:
            return 1, 'T1053.005'
    return 0, None
```

### Template `preprocess.py` siem_windows

```python
"""Étape 1/3 — Streaming → fenêtrage → features → split."""
import json
import sys
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (
    DATA_RAW, PROCESSED_DIR, RANDOM_STATE, WINDOW_MINUTES,
    stream_events, extract_essential, label_window,
)

def main():
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Streaming Day 1 + Day 2
    all_events = []
    for day in ['day1', 'day2']:
        day_dir = DATA_RAW / day
        for json_file in day_dir.glob('*.json'):
            for ev in stream_events(json_file):
                e = extract_essential(ev)
                e['day'] = day
                all_events.append(e)
    
    df = pd.DataFrame(all_events)
    df['Channel'] = df['Channel'].str.replace('^security$', 'Security', regex=True)
    df['ts'] = pd.to_datetime(df['@timestamp'], utc=True, errors='coerce')
    df['window'] = df['ts'].dt.floor(f'{WINDOW_MINUTES}min')
    
    # 2. Fenêtrage : groupby (Hostname, window)
    windows = []
    for (host, w), grp in df.groupby(['Hostname', 'window']):
        events_list = grp.to_dict('records')
        feat = compute_features(events_list, grp)
        label, tech = label_window(events_list)
        feat.update({'Hostname': host, 'window': str(w), 'day': grp['day'].iloc[0],
                     'label': label, 'technique': tech})
        windows.append(feat)
    
    df_w = pd.DataFrame(windows)
    
    # 3. Split temporel
    train = df_w[df_w.day == 'day1']
    test = df_w[df_w.day == 'day2']
    
    feature_cols = [c for c in df_w.columns 
                    if c not in ['Hostname', 'window', 'day', 'label', 'technique']]
    
    X_train = train[feature_cols].fillna(0).values
    X_test = test[feature_cols].fillna(0).values
    y_train = train['label'].values
    y_test = test['label'].values
    
    # 4. Scaler
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    
    # 5. Save
    np.save(PROCESSED_DIR / 'X_train.npy', X_train_s)
    np.save(PROCESSED_DIR / 'X_test.npy', X_test_s)
    np.save(PROCESSED_DIR / 'y_train.npy', y_train)
    np.save(PROCESSED_DIR / 'y_test.npy', y_test)
    joblib.dump(scaler, PROCESSED_DIR / 'scaler.pkl')
    (PROCESSED_DIR / 'feature_names.json').write_text(json.dumps(feature_cols))
    print(f"Saved: train={X_train_s.shape}, test={X_test_s.shape}")

def compute_features(events, df_group):
    """Calcul des ~35 features comportementales pour une fenêtre."""
    total = len(events)
    eids = [e.get('EventID') for e in events]
    feat = {
        'total_events': total,
        'events_per_minute': total / 5,
        'distinct_eventids': len(set(eids)),
    }
    # Comptages EventIDs surveillés
    for eid in [4624, 4625, 4648, 4672, 4688, 4768, 4769, 4771, 4776,
                4697, 4698, 4702, 4728, 4732,
                1, 3, 7, 8, 10, 11, 12, 13, 22,
                4103, 4104]:
        feat[f'cnt_{eid}'] = sum(1 for e in eids if e == eid)
    # Scores agrégés
    feat['brute_force_score'] = feat['cnt_4625'] + feat['cnt_4771'] + feat['cnt_4776']
    feat['lateral_move_score'] = feat['cnt_4648'] + feat['cnt_4624'] + feat['cnt_4672']
    feat['persistence_score'] = feat['cnt_4697'] + feat['cnt_4698'] + feat['cnt_4702']
    feat['execution_score'] = feat['cnt_4688'] + feat['cnt_1']
    feat['kerberos_score'] = feat['cnt_4768'] + feat['cnt_4769'] + feat['cnt_4771']
    # Ratios
    total_logons = max(1, feat['cnt_4624'] + feat['cnt_4625'])
    feat['logon_failure_ratio'] = feat['cnt_4625'] / total_logons
    # Entropy
    from math import log2
    if total > 0:
        counts = pd.Series(eids).value_counts(normalize=True)
        feat['entropy_eventids'] = -sum(p * log2(p) for p in counts if p > 0)
    else:
        feat['entropy_eventids'] = 0
    return feat

if __name__ == '__main__':
    main()
```

### Template `train.py`

```python
import json, sys
from pathlib import Path
import joblib, numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import (CV_FOLDS, MODELS_DIR, PROCESSED_DIR, RANDOM_STATE,
                                RF_MAX_DEPTH, RF_MIN_SAMPLES_LEAF, RF_N_ESTIMATORS)

def main():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    X_train = np.load(PROCESSED_DIR / 'X_train.npy')
    y_train = np.load(PROCESSED_DIR / 'y_train.npy', allow_pickle=True)
    
    rf = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS, max_depth=RF_MAX_DEPTH,
        min_samples_leaf=RF_MIN_SAMPLES_LEAF, class_weight='balanced',
        random_state=RANDOM_STATE, n_jobs=-1,
    )
    
    skf = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    cv = cross_val_score(rf, X_train, y_train, cv=skf, scoring='f1', n_jobs=-1)
    print(f"CV F1: mean={cv.mean():.4f} std={cv.std():.4f}")
    
    rf.fit(X_train, y_train)
    joblib.dump(rf, MODELS_DIR / 'model.pkl')
    manifest = {
        'rf_params': {'n_estimators': RF_N_ESTIMATORS, 'max_depth': RF_MAX_DEPTH,
                      'min_samples_leaf': RF_MIN_SAMPLES_LEAF, 'class_weight': 'balanced'},
        'cv_metrics': {'f1_mean': float(cv.mean()), 'f1_std': float(cv.std())},
    }
    (MODELS_DIR / 'manifest.json').write_text(json.dumps(manifest, indent=2))

if __name__ == '__main__':
    main()
```

### Template `evaluate.py`

```python
import json, sys
from pathlib import Path
import joblib, numpy as np, pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (classification_report, confusion_matrix, f1_score,
                              precision_recall_curve, precision_score, recall_score,
                              roc_auc_score, roc_curve)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import MODELS_DIR, PROCESSED_DIR, RESULTS_DIR

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    model = joblib.load(MODELS_DIR / 'model.pkl')
    manifest = json.loads((MODELS_DIR / 'manifest.json').read_text())
    X_test = np.load(PROCESSED_DIR / 'X_test.npy')
    y_test = np.load(PROCESSED_DIR / 'y_test.npy', allow_pickle=True)
    
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    p = precision_score(y_test, y_pred)
    r = recall_score(y_test, y_pred)
    gap = abs(manifest['cv_metrics']['f1_mean'] - f1)
    
    print(f"F1={f1:.4f} AUC={auc:.4f} Prec={p:.4f} Recall={r:.4f} Gap={gap:.4f}")
    
    # Sauvegarde figures + métriques
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
    plt.savefig(RESULTS_DIR / 'confusion_matrix.png', dpi=110, bbox_inches='tight')
    
    metrics = {'test': {'f1': float(f1), 'auc': float(auc), 'precision': float(p),
                         'recall': float(r), 'gap_cv_test': float(gap)},
               'confusion_matrix': cm.tolist()}
    (RESULTS_DIR / 'metrics.json').write_text(json.dumps(metrics, indent=2))

if __name__ == '__main__':
    main()
```

---

## ⚙️ COMMANDES À LANCER POUR CHAQUE MODÈLE

### siem_windows
```bash
cd siem_windows
# Phase 1 EDA — créer + exécuter
python -m nbconvert --to notebook --execute --inplace notebooks/01_eda.ipynb
# Phase 2 Modeling
python -m nbconvert --to notebook --execute --inplace notebooks/02_modeling.ipynb
# Phase 3 Pipeline
python pipeline/preprocess.py
python pipeline/train.py
python pipeline/evaluate.py
```

### lateral_movement
Idem mais en utilisant les ZIPs Atomic Red Team.

---

## 🔍 AUDIT À FAIRE EN FIN DE PHASE 3 (les 2 modèles)

```python
# Vérification anti-leakage standard
import numpy as np, pandas as pd

X_train = np.load('data/processed/X_train.npy')
X_test = np.load('data/processed/X_test.npy')

n_train_dup = pd.DataFrame(X_train).duplicated().sum()
n_test_dup = pd.DataFrame(X_test).duplicated().sum()

train_hashes = set(pd.util.hash_pandas_object(pd.DataFrame(X_train), index=False))
test_hashes = pd.util.hash_pandas_object(pd.DataFrame(X_test), index=False).values
n_leak = sum(1 for h in test_hashes if h in train_hashes)

print(f"Doublons train: {n_train_dup}/{len(X_train)} ({n_train_dup/len(X_train)*100:.2f}%)")
print(f"Doublons test:  {n_test_dup}/{len(X_test)} ({n_test_dup/len(X_test)*100:.2f}%)")
print(f"Leakage train→test: {n_leak}/{len(X_test)} ({n_leak/len(X_test)*100:.2f}%)")
```

**Seuils d'acceptation :**
- Doublons internes < 5% : OK
- Leakage train↔test < 1% : OK
- Sinon → ajouter `df.drop_duplicates()` dans `preprocess.py` et rerun

---

## 📅 TIMELINE PROPOSÉE

| Jour | Tâche |
|---|---|
| J+0 (aujourd'hui) | Phase 0 siem_windows ✅ + lateral_movement |
| J+1 | Phase 1 EDA siem_windows + lateral_movement |
| J+2 | Phase 2 Modeling siem_windows |
| J+3 | Phase 3 Pipeline + Audit siem_windows + Doc finale |
| J+4 | Phase 2 Modeling lateral_movement |
| J+5 | Phase 3 Pipeline + Audit lateral_movement + Doc finale |
| J+6+ | Rédaction rapport PFE, préparation soutenance |

---

## 🎓 CONSEILS POUR LE RAPPORT PFE

### Structure suggérée du rapport pour chaque modèle

1. **Introduction** (1 page)
   - Surface d'attaque + contexte threat intel (APT29, lateral movement)
   - Source de données + crédibilité

2. **Compréhension des données** (2-3 pages)
   - Reprendre `EXPLICATION_DATA.md`
   - Chiffres réels, figures EDA, distribution classes
   - Pièges identifiés (leakage potentiels, déséquilibre)

3. **Méthodologie** (3-4 pages)
   - Reprendre `PLAN.md`
   - Choix des hyperparamètres + justifications
   - Anti-overfitting checklist
   - Pourquoi RF balanced, pourquoi split temporel, etc.

4. **Résultats** (3-4 pages)
   - Métriques globales + par classe
   - Matrice confusion + ROC/PR + feature importance
   - **Comparaison CV vs test** (généralisation)

5. **Audit critique** (1-2 pages) ⭐
   - Vérification leakage et doublons
   - Si problème détecté + corrigé : raconter l'histoire (cf CIC-IDS)
   - **C'est ce qui différencie un travail de niveau ingénieur d'un projet étudiant**

6. **Limites & perspectives** (1 page)
   - Limitations du dataset (généralisation production)
   - Pistes d'amélioration (déplacement vers eBPF, datasets 2024+, ML par séquences)

---

## ✅ CHECKLIST DE LIVRAISON FINALE

Pour chaque modèle, vérifier :

- [ ] `README.md` à jour avec métriques finales
- [ ] `EXPLICATION_DATA.md` + `EXPLICATION_MODELS.md` complets
- [ ] `PLAN.md` + `AVANCEMENT.md` à jour
- [ ] `results/final/` contient toutes les figures + JSON
- [ ] `saved_models/v1_final/` contient `model.pkl` + `manifest.json`
- [ ] Pipeline reproductible en 3 commandes
- [ ] Audit doublons + leakage < 1%
- [ ] Métriques cibles atteintes (ou limites documentées)
- [ ] Cohérence avec le projet PFE global (`EXPLICATION.md` racine)

---

*Document créé le 2026-05-19 — fil rouge pour finaliser siem_windows et lateral_movement sans dépendance à Claude.*
