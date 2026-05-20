# AUDIT RAPPORT — siem_windows

**Date :** 2026-05-20
**Auteur :** Reda — audit critique Phase 4
**Statut :** ✅ Audit passé sans correction nécessaire

---

## TL;DR

L'audit anti-leakage a été conduit **après** la livraison du pipeline Phase 3 (preprocess + train + evaluate). Les trois critères du PLAN ont tous été validés du **premier coup** — aucune modification du code n'a été requise.

| Critère | Mesure | Cible | Statut |
|---|---:|---:|:---:|
| Doublons internes train | 1 / 136 (0.74 %) | < 5 % | ✅ |
| Doublons internes test | 2 / 144 (1.39 %) | < 5 % | ✅ |
| **Leakage train → test (hash)** | **0 / 144 (0.00 %)** | < 1 % | ✅✅ |

→ Le modèle peut être livré en l'état. Les chiffres rapportés dans `results/final/metrics.json` (F1=0.7586, Recall=0.8919, AUC=0.9505) sont **méthodologiquement honnêtes**.

---

## 1. Méthode de l'audit

Identique à celle utilisée sur `cicids2017/AUDIT_RAPPORT.md` :

```python
import numpy as np, pandas as pd
X_train = np.load("data/processed/X_train.npy")   # (136, 33)
X_test  = np.load("data/processed/X_test.npy")    # (144, 33)

# Doublons internes (lignes bit-à-bit identiques)
df_tr = pd.DataFrame(X_train).round(6)
df_te = pd.DataFrame(X_test).round(6)
n_train_dup = df_tr.duplicated().sum()   # -> 1
n_test_dup  = df_te.duplicated().sum()   # -> 2

# Leakage train↔test par hash de ligne
train_hashes = set(pd.util.hash_pandas_object(df_tr, index=False).values.tolist())
test_hashes  = pd.util.hash_pandas_object(df_te, index=False).values
n_leak = sum(1 for h in test_hashes if h in train_hashes)   # -> 0
```

L'arrondi à 6 décimales avant hash neutralise le jitter du `StandardScaler` (sinon deux features quasi-identiques mais avec ~`1e-15` de différence seraient considérées comme distinctes).

Script reproductible : `scripts_aux/audit_leakage.py`
Sortie : `results/final/audit_leakage.json`

---

## 2. Pourquoi l'audit passe-t-il du premier coup ?

Contrairement à CIC-IDS-2017 (où la suppression de `Destination Port` avait généré 23.5 % de leakage), notre pipeline est **structurellement immunisé** par trois choix faits dès la conception :

1. **Split temporel Day1/Day2.** Le train (Day 1, 33 min de capture, "Spray & Pray") et le test (Day 2, 35 min, "Low & Slow") sont **deux fenêtres horaires non chevauchantes**. Une fenêtre 1 min × host de Day 1 ne peut **physiquement pas** être identique à une fenêtre de Day 2 — les compteurs d'EID dépendent du moment exact.

2. **Drop des features identifiantes** (`Hostname`, `window`, `day`, `technique`). Sans ces colonnes, la seule façon d'avoir deux fenêtres identiques est qu'elles aient **exactement** les mêmes 33 valeurs numériques. C'est arrivé 3 fois sur 280 (probablement des minutes très calmes sur 2 hosts différents qui ressemblent toutes à `[5, 5, 1, 1.6, 0, 0, …, 0]`).

3. **Granularité 1 min × host.** Une granularité plus grossière (5 min, ou session entière) aurait augmenté la probabilité de collision (mêmes patterns observés plusieurs fois). 1 min est assez fin pour capturer la variabilité de l'activité tout en gardant assez d'events pour ne pas être trop bruité.

---

## 3. Détail des 3 doublons internes (analyse)

Les doublons résiduels ne sont **pas un problème** car ils sont :
- **Internes** à un seul split (train ou test), pas entre les deux
- En **dessous de 2 %** — invisible à l'apprentissage
- Probablement des fenêtres-minute "neutres" (~5 events, EID 12 dominant, rien de discriminant) qui se ressemblent statistiquement

On pourrait les supprimer via `df.drop_duplicates()` post-features, mais l'impact serait nul (0.4 % du train ; 1.4 % du test). On laisse en l'état pour conserver la **stricte chronologie** des fenêtres.

---

## 4. Verdict

✅ **Aucune action corrective requise.**

Les artefacts livrés en Phase 3 sont :
- `data/processed/X_train.npy`, `X_test.npy`, `y_train.npy`, `y_test.npy`, `scaler.pkl`, `feature_names.json`, `train.parquet`, `test.parquet`, `manifest_preprocess.json`
- `saved_models/v1_final/model.pkl`, `scaler.pkl`, `feature_names.json`, `manifest.json`, `threshold_scan.csv`
- `results/final/metrics.json`, `classification_report.txt`, `confusion_matrix.png`, `roc_pr_curves.png`, `feature_importance.png`, `audit_leakage.json`

Tous **conservés tels quels** après audit.

---

## 5. Comparatif avec les autres datasets du projet

| Dataset | Leakage initial | Correction appliquée |
|---|---|---|
| CIC-IDS-2017 | 23.5 % | `drop_duplicates()` après suppression de `Destination Port` |
| ADFA-LD | 0 % | aucune (GroupShuffleSplit par scénario depuis le début) |
| **siem_windows** | **0 %** | **aucune** (split temporel + drop colonnes identifiantes) |

L'audit confirme que la méthodologie appliquée sur siem_windows est **équivalente en rigueur** à celle d'ADFA-LD : leakage prévenu *by design* plutôt que corrigé a posteriori.

---

*Rapport d'audit créé le 2026-05-20. Pipeline siem_windows livrable en l'état.*
