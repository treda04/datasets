# Fiche technique — PFE SOC-ML

**Étudiant :** Reda — UIR / Data Protect
**Soutenance :** 2026-06-02

---

## Stack technique

| Couche | Technologie |
|---|---|
| Langage | Python 3.11 |
| ML core | scikit-learn 1.8, XGBoost 3.2, LightGBM 4.6 |
| Sérialisation | joblib (modèles), parquet (données) |
| Tests | pytest 9.0 |
| Visualisation | matplotlib 3.x |
| Notebook | Jupyter / nbformat 5.10 |
| Excel report | openpyxl 3.1 |
| OS | Windows 11 (dev) — portable Linux/macOS |

---

## Datasets et licences

| Dataset | Source | Volume | Licence |
|---|---|---|---|
| CIC-IDS-2017 | University of New Brunswick (CIC) | 685 MB, 500 K flux utilisés | Recherche académique — citer Sharafaldin et al. 2018 |
| ADFA-LD | UNSW | ~6 000 fichiers traces | CC BY 4.0 |
| OTRF Mordor APT29 | Open Threat Research Forge | day1 = 385 MB, day2 = 1.7 GB JSON | MIT (datasets/code) |
| Atomic Red Team Windows | Red Canary / OTRF | 196 K events positifs + 19 K négatifs | MIT |

---

## Métriques clés (après remédiation V1 → V2/V3)

| Modèle | F1 test | AUC | F1 CV (k=5) | Feature dominante (< 25%) |
|---|---|---|---|---|
| CIC-IDS-2017 v2 (XGBoost) | 0.9939 | — | 0.9996 ± 0.00002 | `Fwd Packet Length Std` (0.232) |
| ADFA-LD v2 (RF + Calibrated) | 0.9574 | 0.9788 | 0.9486 ± 0.0080 | n-grams distribués (< 0.05) |
| SIEM Windows v3 (RF reg.) | 0.667 / **0.669 ± 0.014 LOOHO** | 0.573 / 0.538 ± 0.133 LOOHO | 0.745 ± 0.088 | `events_per_minute` (0.115) |

**Preuve d'absence de leakage :** aucune feature ne dépasse 25 % d'importance sur les 3 modèles.

**Preuve d'absence d'overfitting :** gap CV − test < 0.10 sur les 3 modèles.

**Note :** une 4ème surface (Lateral Movement / Atomic Red Team) a été explorée puis écartée pour cause de dataset insuffisant (37 sessions) — voir `RAPPORT_ENCADRANT_V2.md` §9.

---

## Architecture logicielle

```
datasets/
├── adfa_ld/                      Préprocesseur + modèle ADFA-LD v2
├── cicids2017/                   Préprocesseur + modèle CIC-IDS-2017 v2
├── siem_windows/                 Préprocesseur + modèle SIEM Windows v3
├── models/                       Modèles agrégés pour SOCOrchestrator
│   ├── cicids/{model,scaler,features,label_encoder}.{pkl,json}
│   ├── adfa/{model,vectorizer,features,threshold}.{pkl,json}
│   └── siem/{model,scaler,features,threshold}.{pkl,json}
├── src/orchestrator/
│   ├── soc_orchestrator.py       Classe SOCOrchestrator
│   └── mitre_mapping.py          EventID -> MITRE ATT&CK
├── tests/test_orchestrator.py    16 tests pytest
├── scripts/                      Pipelines (preprocess, train, eval, demo)
├── notebooks/                    01_mitre_evaluation.ipynb
├── reports/                      Documents et figures de soutenance
│   ├── RAPPORT_RESULTATS.xlsx    Synthèse multi-feuilles
│   ├── LIMITATIONS.md            Limites assumées
│   ├── mitre_metrics.csv         F1 par technique MITRE
│   ├── figures/mitre_coverage.png Heatmap MITRE
│   └── slides/outline.md         Plan slides soutenance
├── data/demo/
│   ├── attack_scenario.jsonl     128 events kill chain APT
│   └── run_output.jsonl          Sortie démo (exemple)
└── docs/                         Audits et historique de session
```

---

## Reproduction

### Installation

```bash
git clone <repo-url>
cd datasets
python -m venv .venv
.venv/Scripts/activate          # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

### Reproduction des 3 entraînements

```bash
# 1) CIC-IDS-2017 v2
python cicids2017/preprocessing/preprocess_v2.py
python cicids2017/models/train_xgboost_v2.py

# 2) ADFA-LD v2
python adfa_ld/preprocessing/preprocess_adfa_v2.py
python adfa_ld/models/train_adfa_v2.py

# 3) SIEM Windows v3
python siem_windows/preprocessing/preprocess_siem.py
python siem_windows/training/train_siem.py
python siem_windows/evaluation/generate_siem_results.py

```

### Construction du dossier models/

```bash
python scripts/setup_models_dir.py
```

### Évaluation MITRE

```bash
python scripts/mitre_evaluation.py
# Outputs: reports/figures/mitre_coverage.png, reports/mitre_metrics.csv
```

### Démo live

```bash
python scripts/run_demo.py --speed 5
# Affiche la kill chain en 12 s (60s compressée)
```

### Tests

```bash
python -m pytest tests/test_orchestrator.py -v
# Cible : 16 tests passants
```

---

## Contraintes respectées (PFE)

- ✅ **Tous les modèles supervisés** (RF, XGBoost, LightGBM, LogReg). Aucun import de `IsolationForest`, `OneClassSVM`, `KMeans`, `DBSCAN`, ou autoencoder.
- ✅ `random_state=42` partout (split, RF, XGB, CV, Calibrated, sampling, SMOTE).
- ✅ Tests pytest pour le module orchestrator.
- ✅ Reproductibilité : artefacts versionnés dans `models/`, requirements pinnés.
