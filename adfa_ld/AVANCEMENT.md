# AVANCEMENT — Modèle ADFA-LD

Suivi continu du travail. Mis à jour après chaque phase du [PLAN.md](PLAN.md).

---

## Vue d'ensemble des phases

| Phase | Statut | Date | Description |
|---|---|---|---|
| **Phase 1 — Exploration (EDA)** | ✅ Terminée | 2026-05-14 | Notebook EDA créé et exécuté, stats réelles obtenues |
| **Phase 2 — Prototype modeling** | ⏳ À faire | — | Pipeline preprocess + train + eval en notebook |
| **Phase 3 — Production scripts** | ⏳ À faire | — | 3 scripts reproductibles + métriques finales |

**Légende:** 🟡 En cours · ✅ Terminé · ⏳ À faire · ❌ Bloqué

---

## ✅ Phase 1 — Exploration (EDA)

**Statut:** Terminée
**Date:** 2026-05-14
**Notebook exécuté:** `notebooks/01_eda.ipynb`

---

### A. Résultats bruts obtenus

#### A.1 Décompte des fichiers

| Source | Fichiers | Classe |
|---|---|---|
| Training_Data_Master | 833 | Normal (0) |
| Validation_Data_Master | 4 372 | Normal (0) |
| Attack_Data_Master | 746 | Attaque (1) |
| **TOTAL** | **5 951** | |

**Par famille d'attaque (746 au total) :**

| Famille | Fichiers |
|---|---|
| Hydra_SSH | 176 |
| Hydra_FTP | 162 |
| Java_Meterpreter | 124 |
| Web_Shell | 118 |
| Adduser | 91 |
| Meterpreter | 75 |

**60 scénarios d'attaque distincts** (10 par famille).

#### A.2 Statistiques de longueur (nombre de syscalls par fichier)

|  | Min | Q1 | **Médiane** | Q3 | Max | Moyenne | Std |
|---|---|---|---|---|---|---|---|
| Normal | 77 | 152 | **343** | 444 | 4 494 | 466.9 | 536.6 |
| Attaque | 75 | 139 | **290** | 561 | 2 712 | 425.5 | 403.2 |

#### A.3 Top syscalls

**Top 5 Normal :** `read(3)` 343K · `open(5)` 271K · `close(6)` 178K · `stat64(195)` 175K · `mmap2(192)` 155K

**Top 5 Attaque :** `poll(168)` 75K · `clock_gettime(265)` 61K · `read(3)` 46K · `gettimeofday(78)` 21K · `select(142)` 12K

#### A.4 Anomalies

| Type | Compte |
|---|---|
| Fichiers vides | 0 |
| Trop courts (<10) | 0 |
| Tokens invalides | 0 |
| Noms étranges (`=`) | 28 (tous valides) |

#### A.5 Nettoyage

- Avant : 5 951 fichiers
- À garder : **5 951** (100%)
- À rejeter : **0**

---

### B. Explications et Déductions (lecture simple)

#### 🔍 Déduction 1 — Le dataset est **plus riche** que ce qu'on pensait

**Ce qu'on a appris:**
On a **5 205 exemples normaux** au lieu des 833 utilisés traditionnellement dans la littérature qui ne se sert que de `Training_Data_Master/`.

**Pourquoi c'est important:**
Plus on a d'exemples de comportement normal, mieux le modèle apprend la **frontière** entre normal et anormal. C'est comme apprendre à reconnaître un chien : si tu n'as vu que 10 chiens, tu vas confondre avec des loups. Si tu en as vu 1 000, tu seras précis.

**Implication pour la suite:**
✅ On combine Training + Validation = 5 205 exemples normaux. Pas de raison de jeter 4 372 exemples utiles.

---

#### 🔍 Déduction 2 — Le dataset est **déséquilibré**, mais pas dramatiquement

**Ce qu'on a:**
- 87.5% Normal
- 12.5% Attaque
- Ratio 7:1

**Comparaison avec d'autres datasets:**
- Détection de fraude carte bancaire : 1000:1 (fraude rare)
- Détection de spam email : 5:1
- **ADFA-LD : 7:1** → **proche du spam, gérable**

**Pourquoi c'est important:**
Si on entraînait un modèle "bête" qui dit toujours `Normal`, il aurait **87.5% d'accuracy** sans rien apprendre. C'est pourquoi on ne regarde JAMAIS l'accuracy seule mais le **F1-score** et le **recall sur la classe attaque**.

**Implication:**
✅ On utilisera `class_weight='balanced'` dans Random Forest → le modèle donnera plus d'importance aux 746 attaques pour ne pas les "ignorer".

---

#### 🔍 Déduction 3 — Les longueurs ne suffisent PAS pour distinguer normal vs attaque

**Ce qu'on observe:**
- Médiane Normal : 343 syscalls
- Médiane Attaque : 290 syscalls

Les distributions se chevauchent énormément. Un fichier de 300 syscalls peut être normal OU attaque.

**Conclusion:**
❌ Un modèle qui n'utilise que la longueur sera nul.
✅ Le signal doit venir de **CE QUE FAIT** le programme (quels syscalls et dans quel ordre), pas de **COMBIEN** d'opérations il fait.

**Implication:**
✅ Notre approche par **n-grammes** (séquences de 3 syscalls consécutifs) capture exactement ça : le **comportement**, pas la quantité.

---

#### 🔍 Déduction 4 — Le signal discriminant est **TRÈS clair**

C'est la découverte la plus importante du EDA.

**Programmes Normaux** font surtout :
| Syscall | Action | Fréquence |
|---|---|---|
| `read(3)` | Lire un fichier | 343K |
| `open(5)` | Ouvrir un fichier | 271K |
| `close(6)` | Fermer un fichier | 178K |
| `stat64(195)` | Lire métadonnées | 175K |
| `mmap2(192)` | Allouer mémoire | 155K |

➡️ **Pattern:** un programme normal **manipule des fichiers et de la mémoire**.

**Attaques** font surtout :
| Syscall | Action | Fréquence |
|---|---|---|
| `poll(168)` | Attendre événement I/O | 75K |
| `clock_gettime(265)` | Lire l'horloge | 61K |
| `read(3)` | Lire un fichier | 46K |
| `gettimeofday(78)` | Lire l'heure | 21K |
| `select(142)` | Attendre I/O multiple | 12K |

➡️ **Pattern:** une attaque **attend des événements et regarde l'heure constamment**.

**Pourquoi ce signal existe (interprétation):**
- Une attaque type **Meterpreter** ou **backdoor** attend les ordres du serveur de contrôle → boucle infinie `poll()` + `clock_gettime()` pour le timing
- Un **brute force SSH/FTP** envoie une tentative, attend la réponse → encore `poll()` + `select()`
- Un **web shell** attend que l'attaquant envoie une requête → idem

**Implication:**
✅ Le modèle Random Forest va apprendre ces patterns **sans aucune difficulté**. On peut être confiants sur les résultats à venir.
✅ Le top **trigramme attendu** dans les attaques : `"168 168 265"` (poll, poll, clock_gettime) — c'est la signature d'une boucle d'attente.

---

#### 🔍 Déduction 5 — Les 28 fichiers à nom bizarre ne sont **PAS un problème**

**Ce qu'on a trouvé:** 28 fichiers avec `=` dans le nom (ex: `UAD-Adduser-1-=1.txt`).

**Analyse:**
- Tous ont une longueur normale (75 à 488 syscalls)
- Tous ont des tokens valides (entiers)
- Le `=` est juste dans le PID (`=1` au lieu de `1` à cause d'un bug de naming d'UNSW en 2012)

**Décision:**
✅ **On les garde tous.** Ils contiennent du vrai signal d'attaque utilisable.

---

#### 🔍 Déduction 6 — Le dataset est **étonnamment propre**

**Ce qu'on attendait:** quelques fichiers corrompus, vides, malformés...

**Ce qu'on a trouvé:** **ZÉRO anomalie bloquante** :
- 0 fichier vide
- 0 fichier trop court (< 10 syscalls)
- 0 fichier avec tokens invalides

**Pourquoi c'est positif:**
On a **tous les 5 951 fichiers** pour entraîner le modèle. Pas de perte de données. UNSW a fait un travail de qualité en 2012.

**Implication:**
✅ Étape de nettoyage = **triviale**. On passe directement au preprocessing.

---

### C. Récapitulatif — Ce qu'on sait maintenant

| Question | Réponse |
|---|---|
| Combien de fichiers ? | 5 951 (5 205 normaux + 746 attaques) |
| Le dataset est-il propre ? | ✅ Oui, 100% utilisable |
| Y a-t-il un signal discriminant ? | ✅ Oui, très clair (poll/clock_gettime vs read/open) |
| Déséquilibre des classes ? | 7:1, gérable avec `class_weight='balanced'` |
| Combien de scénarios distincts ? | 60 (à grouper pour éviter le leakage) |
| Faut-il du nettoyage spécial ? | Non, dataset déjà propre |
| Y a-t-il un risque overfitting évident ? | Oui : leakage par scénario → solution `GroupShuffleSplit` |

---

### D. Artefacts produits

- 📄 `notebooks/01_eda.ipynb` — notebook complet exécuté
- 📄 `results/eda/eda_summary.json` — résumé chiffré (170 lignes)
- 🖼️ Figures générées :
  - `results/eda/length_distribution.png`
  - `results/eda/length_by_family.png`
  - `results/eda/top_syscalls_comparison.png`
  - `results/eda/class_balance.png`

---

### E. Décisions validées pour la Phase 2

À partir de ce qu'on sait maintenant :

1. ✅ **Pas de nettoyage** — utiliser tous les 5 951 fichiers
2. ✅ **Split** : `GroupShuffleSplit(test_size=0.3, random_state=42)` avec `groups=scenario` (pour éviter le leakage par scénario d'attaque)
3. ✅ **Features** : trigrammes de syscalls via `CountVectorizer(ngram_range=(3,3), max_features=500, min_df=2)`
4. ✅ **Modèle** : `RandomForestClassifier(n_estimators=200, max_depth=20, class_weight='balanced', random_state=42)`
5. ✅ **Calibration** : `CalibratedClassifierCV(method='isotonic', cv=5)`
6. ✅ **Évaluation** : F1, AUC, recall, matrice confusion + F1 par famille

---

### F. Prochaine étape

➡️ **Phase 2** : créer `notebooks/02_modeling.ipynb` pour prototyper :
1. Chargement (réutiliser le code de Phase 1)
2. Split groupé par scénario
3. Vectorisation trigrammes
4. Entraînement Random Forest + calibration
5. Cross-validation 5-fold
6. Évaluation sur test
7. Visualisations (confusion matrix, ROC, feature importance, F1 par famille)
8. Validation anti-overfitting (gap CV-test < 0.10)

---

## ⏳ Phase 2 — Prototype modeling

**Statut:** À faire

À remplir après création et exécution du notebook `02_modeling.ipynb`.

---

## ⏳ Phase 3 — Production scripts

**Statut:** À faire

À remplir après création des 3 scripts `pipeline/preprocess.py`, `pipeline/train.py`, `pipeline/evaluate.py`.

---

## Métriques finales (à remplir après Phase 3)

| Métrique | Cible | Obtenu |
|---|---|---|
| F1 (test) | ≥ 0.95 | — |
| AUC | ≥ 0.97 | — |
| Recall | ≥ 0.90 | — |
| Gap CV-test | < 0.10 | — |
| Max feature importance | < 0.20 | — |
| F1 min par famille | ≥ 0.80 | — |

---

*Dernière mise à jour : 2026-05-14 (fin de Phase 1, résultats vérifiés via exécution du notebook)*
