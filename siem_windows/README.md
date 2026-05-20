# siem_windows — Modèle de détection APT29 sur Windows Events

**Surface :** Host Windows (Sysmon + Security + PowerShell)
**Dataset :** OTRF Mordor — APT29 / MITRE ATT&CK Evals Round 2 (2020)
**Tâche ML :** classification binaire de fenêtres 1 min × hostname → `0 = normal`, `1 = attaque`
**Modèle :** RandomForest balanced (200, max_depth=15, min_samples_leaf=5)
**Statut :** Phase 0 terminée (docs + stats brutes) — Phases 1–5 en cours

---

## Carte du projet

```
siem_windows/
├── README.md                     ← ce fichier (carte)
├── PLAN.md                       ← stratégie ML complète Phase 1→5
├── EXPLICATION_DATA.md           ← analyse exhaustive du dataset (chiffres réels)
├── EXPLICATION_MODELS.md         ← rapport final Phase 5 (à écrire)
├── AVANCEMENT.md                 ← journal de bord continu
├── AUDIT_RAPPORT.md              ← (créé si Phase 4 détecte un leakage)
│
├── notebooks/
│   ├── 01_eda.ipynb              ← Phase 1
│   └── 02_modeling.ipynb         ← Phase 2
│
├── scripts_aux/
│   └── extract_raw_stats.py      ← streaming JSON → results/eda/raw_stats.json
│
├── pipeline/                     ← Phase 3 (à réécrire)
│   ├── __init__.py
│   ├── io_utils.py
│   ├── preprocess.py
│   ├── train.py
│   └── evaluate.py
│
├── data/
│   ├── raw/{day1,day2}/*.json    ← brut OTRF (read-only, ~2 GB)
│   └── processed/                ← parquets + .npy + scaler.pkl
│
├── results/
│   ├── eda/                      ← stats brutes + figures Phase 1
│   ├── modeling/                 ← métriques + figures Phase 2
│   └── final/                    ← artefacts Phase 3 (post-pipeline)
│
└── saved_models/v1_final/
    ├── model.pkl
    ├── scaler.pkl
    ├── feature_names.json
    └── manifest.json
```

---

## Comment reproduire (une fois Phase 3 terminée)

```bash
# Depuis siem_windows/  — environnement venv avec pyarrow installé

# 0) Stats brutes (déjà fait, dans results/eda/raw_stats.json)
python scripts_aux/extract_raw_stats.py

# 1) Pipeline production
python pipeline/preprocess.py        # ~2-3 min (stream 2 GB)
python pipeline/train.py             # ~30 s
python pipeline/evaluate.py          # ~5 s

# Sortie : saved_models/v1_final/  + results/final/  prêts pour la soutenance
```

---

## Vue d'ensemble du dataset

| | Day 1 | Day 2 | Total |
|---|---:|---:|---:|
| Events | 196 081 | 587 286 | **783 367** |
| Durée | 33 min | 35 min | ~68 min |
| Hostnames | 4 | 4 | 4 |
| EventIDs uniques | 165 | 172 | ~180 |
| Channels | 11 | 11 | 11 |
| Rôle ML | **train** | **test** | — |

Pour les détails (signatures attaque, EID stratégiques, pièges de casse `Security` vs `security`, etc.) → voir `EXPLICATION_DATA.md`.

---

## Cibles métriques

| Métrique | Cible |
|---|---|
| F1 binaire | ≥ 0.78 |
| Recall | ≥ 0.80 |
| Precision | ≥ 0.70 |
| AUC | ≥ 0.85 |
| Gap CV-test | < 0.10 |
| Max feature importance | < 0.25 |
| Leakage train↔test | < 1 % |

Détails et justifications dans `PLAN.md` §3.

---

## Liens vers la documentation détaillée

- **Ce qu'on a (chiffres réels)** → `EXPLICATION_DATA.md`
- **Ce qu'on va faire (stratégie ML)** → `PLAN.md`
- **Ce qu'on a fait (journal de bord)** → `AVANCEMENT.md`
- **Ce qu'on en conclut (rapport final, Phase 5)** → `EXPLICATION_MODELS.md`
- **Méthodologie projet PFE complet** → `../PLAN_GLOBAL_SIEM.md` (racine)
- **Audit pré-travail** → `../AUDIT_SIEM_LATERAL.md` (racine)

---

*Dernière mise à jour : 2026-05-20 — Phase 0 terminée. Voir `AVANCEMENT.md` pour l'état actuel.*
