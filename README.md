# PFE-SOC-ML — Détection d'Intrusions par Machine Learning Supervisé

**Étudiant :** Reda — UIR (5ᵉ année Cybersécurité)
**Entreprise d'accueil :** Data Protect
**Sujet :** Intégration de méthodes ML supervisées pour la détection multi-surfaces en environnement SIEM
**Soutenance :** 2026-06-02

---

## Vue d'ensemble

Système d'orchestration de **4 modèles ML supervisés** couvrant 4 surfaces de détection complémentaires (réseau, host Windows, host Linux, identité), avec corrélation multi-modèles et évaluation MITRE ATT&CK.

Posture méthodologique : un **audit interne** a identifié 4 problèmes de leakage typiques de la littérature IDS-ML (`docs/AUDIT_PROJET_COMPLET.md`). Les modèles V2/V3 présentent des scores **modestes mais honnêtes**.

| Modèle | Algorithme | Surface | F1 test | AUC |
|---|---|---|---|---|
| CIC-IDS-2017 v2 | XGBoost | Réseau (NetFlow) | **0.994** | — (4-class) |
| ADFA-LD v2 | RF + Calibrated | Host Linux (syscalls) | **0.957** | 0.979 |
| SIEM Windows v3 | RF régularisé | Host Windows (events) | **0.667** (LOOHO 0.669 ± 0.014) | 0.573 |
| Lateral Movement | RF + Calibrated | Identité / Atomic Red Team | **0.836** (F1 attaque) / 0.681 macro | 0.694 |

✅ Anti-leakage validé (toutes les features dominantes sous 25 %).
✅ Anti-overfitting validé (gap CV − test < 0.10).
✅ Contrainte **supervisé pur** respectée (pas de IsolationForest, KMeans, autoencoder).

---

## Structure du dépôt

```
datasets/
├── adfa_ld/                      Préprocesseur + modèle ADFA-LD v2
├── cicids2017/                   Préprocesseur + modèle CIC-IDS-2017 v2
├── siem_windows/                 Préprocesseur + modèle SIEM Windows v3
├── lateral_movement/             Préprocesseur + modèle Lateral Movement
├── models/                       Modèles agrégés (build via setup_models_dir.py)
├── src/orchestrator/             SOCOrchestrator + mapping MITRE ATT&CK
├── tests/                        16 tests pytest sur l'orchestrateur
├── scripts/                      Pipelines (preprocess, train, eval, démo)
├── notebooks/01_mitre_evaluation.ipynb
├── data/demo/attack_scenario.jsonl   Kill chain APT 60 s (128 events)
├── reports/
│   ├── RAPPORT_RESULTATS.xlsx    Synthèse multi-feuilles
│   ├── LIMITATIONS.md            Limites assumées
│   ├── mitre_metrics.csv         F1 par technique MITRE
│   ├── figures/mitre_coverage.png Heatmap MITRE
│   ├── fiche_technique.md
│   └── slides/outline.md
├── docs/                         Audits méthodologiques + sessions
├── integration/                  Logstash, Elasticsearch mapping, Kibana ndjson
├── live_detection/               Service Kafka consumer (production)
├── docker-compose.yml            Infra ELK + Kafka
├── requirements.txt
└── README.md                     ← Ce fichier
```

---

## Installation

```bash
git clone <repo-url>
cd datasets

# Création d'un environnement virtuel
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

# Dépendances
pip install -r requirements.txt
```

Datasets requis (non versionnés — voir `docs/AUDIT_PROJET_COMPLET.md` §6 pour les sources) :

- `cicids2017/data/cicids2017.csv` (685 MB, CIC-IDS-2017)
- `adfa_ld/data/ADFA-LD/` (~6 000 fichiers de traces)
- `siem_windows/data/raw/day1` et `day2` (zips OTRF Mordor APT29 extraits)
- `siem_dataset/data/otrf_datasets/datasets/atomic/windows/...` (Atomic Red Team)

---

## Reproduction des entraînements

> Tous les scripts respectent `random_state = 42`.

```bash
# 1) CIC-IDS-2017 v2 (réseau)
python cicids2017/preprocessing/preprocess_v2.py
python cicids2017/models/train_xgboost_v2.py

# 2) ADFA-LD v2 (host Linux)
python adfa_ld/preprocessing/preprocess_adfa_v2.py
python adfa_ld/models/train_adfa_v2.py

# 3) SIEM Windows v3 (host Windows)
python siem_windows/preprocessing/preprocess_siem.py
python siem_windows/training/train_siem.py
python siem_windows/evaluation/generate_siem_results.py

# 4) Lateral Movement (identité)
python lateral_movement/preprocessing/preprocess_lateral.py
python lateral_movement/training/train_lateral.py
python lateral_movement/evaluation/generate_lateral_results.py

# 5) Construction du dossier models/ pour l'orchestrateur
python scripts/setup_models_dir.py
```

---

## Lancement de l'orchestrateur

```python
from src.orchestrator import SOCOrchestrator

orch = SOCOrchestrator(models_dir="models")

event = {
    "event_id": "abc123",
    "source": "windows_event",
    "host": "PC1",
    "timestamp": 1717000000.0,
    "features": {"total_events": 500, "cnt_4688": 50, ...},
}
pred = orch.predict(event)
# {'event_id': ..., 'model': 'siem', 'score': 0.91, 'is_attack': True,
#  'mitre_technique': 'T1059'}

# Corrélation multi-modèles (>= 2 modèles distincts sur le même host < 5 min)
critical = orch.correlate(predictions, window_seconds=300)
```

---

## Démo end-to-end

Rejoue une kill chain APT (Reconnaissance → Exfiltration) en 60 s (compressé) :

```bash
python scripts/run_demo.py --speed 5     # 12 s, recommandé pour soutenance
python scripts/run_demo.py --speed 1     # temps réel
python scripts/run_demo.py --speed 0     # instantané (debug)
```

Sortie : alertes par phase + corrélations CRITICAL multi-modèles, log JSONL dans `data/demo/run_output.jsonl`.

---

## Évaluation MITRE ATT&CK

```bash
python scripts/mitre_evaluation.py
# -> reports/figures/mitre_coverage.png (heatmap 300 DPI)
# -> reports/mitre_metrics.csv (F1 / precision / recall par technique)
```

Le notebook `notebooks/01_mitre_evaluation.ipynb` reproduit l'analyse cellule par cellule.

---

## Tests

```bash
python -m pytest tests/test_orchestrator.py -v
# Cible : 16 tests passants
```

Tests couverts :
- Routing source → modèle (5 cas)
- Corrélation multi-modèles (4 cas dont hosts différents, fenêtre dépassée, even non-attack)
- Predict + run_stream
- Mapping MITRE EventID → technique

---

## Documents pour la soutenance

| Fichier | Contenu |
|---|---|
| `reports/RAPPORT_RESULTATS.xlsx` | Synthèse 9-feuilles (métriques, anti-overfitting, anti-leakage, comparatif V1/V2, innovations) |
| `reports/LIMITATIONS.md` | 7 limites assumées et leurs mitigations |
| `reports/figures/mitre_coverage.png` | Heatmap MITRE par modèle |
| `reports/slides/outline.md` | Plan slides 20 min |
| `reports/fiche_technique.md` | Stack + métriques + reproduction |
| `docs/AUDIT_PROJET_COMPLET.md` | Audit méthodologique complet (V1 → V2/V3) |

---

## Contraintes PFE respectées

- ✅ Tous les modèles **supervisés** (RF, XGBoost, LightGBM, LogReg).
- ✅ `random_state=42` partout.
- ✅ CIC-IDS-2017 et Lateral Movement non ré-entraînés depuis la validation initiale.
- ✅ Tests pytest sur l'orchestrateur (16 tests passants).
- ✅ Pas de feature dominante > 0.40 (preuve anti-leakage).

---

## Références

- Sharafaldin et al. 2018 — *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization* (CIC-IDS-2017)
- Creech & Hu 2014 — *A Semantic Approach to Host-Based Intrusion Detection Systems Using Contiguous and Discontiguous System Call Patterns* (ADFA-LD)
- Mendsaikhan et al. 2021 — *Methods for Host-based Intrusion Detection with Deep Learning*
- Open Threat Research Forge — Mordor / APT29 Emulation Plan
- Red Canary — Atomic Red Team
- [MITRE ATT&CK Enterprise v14](https://attack.mitre.org/)
