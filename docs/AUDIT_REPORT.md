# Rapport d'Audit — Phase 1 : Analyse des 4 Modèles ML

**Date :** 2026-05-04  
**Auditeur :** Encadrant PFE  
**Projet :** PFE-SOC-ML — UIR / Data Protect

---

## Résumé Exécutif

Les 4 modèles présentent des scores suspects (F1 entre 0.96 et 1.00) révélant des problèmes méthodologiques sérieux. Un jury technique expérimenté rejettera ces résultats. Ce rapport documente précisément chaque problème avec les preuves dans le code.

| Modèle | F1 | FPR | Problème Principal | Gravité |
|--------|----|-----|-------------------|---------|
| ADFA-LD | 0.96 | 5% | Split aléatoire, pas de validation temporelle | MODÉRÉE |
| CIC-IDS-2017 | 1.00 | ~0% | Shortcut learning sur Destination Port | CRITIQUE |
| SIEM Windows | 1.00 | ~0% | Label leakage via champs SePrivilege* | CRITIQUE |
| Lateral Movement | 1.00 | ~0% | Circularité feature = règle de labellisation | CRITIQUE |

---

## Modèle 1 — ADFA-LD (Syscalls Linux)

### Score obtenu
- Accuracy: ~96%, F1: ~0.96, FPR: ~5%

### Problèmes identifiés

#### Problème 1 : Split aléatoire (gravité : MODÉRÉE)

**Fichier :** `adfa_ld/models/train_adfa.py`, ligne 26

```python
# CODE PROBLÉMATIQUE
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42   # ← Split ALÉATOIRE
)
```

**Explication :** Un split aléatoire mélange des séquences d'un même processus entre train et test. Si une attaque Hydra génère 50 traces, certaines se retrouveront dans le train ET dans le test — le modèle mémorise les signatures de cette instance spécifique, pas le comportement général.

**Correction :** Utiliser un split basé sur l'identifiant de session d'attaque ou GroupShuffleSplit par famille d'attaque.

#### Problème 2 : Fuite via le vectorizer (gravité : FAIBLE)

**Fichier :** `adfa_ld/preprocessing/preprocess_adfa.py`, ligne 53

```python
# CODE PROBLÉMATIQUE
vectorizer = CountVectorizer(ngram_range=(3, 3), max_features=500)
X = vectorizer.fit_transform(all_sequences)  # ← fit sur TOUT le dataset
```

**Explication :** Le vectorizer apprend le vocabulaire de n-grams sur l'ensemble des données (train + test). Les fréquences de n-grams dans le test influencent donc la sélection des 500 features. En production, seul le vocabulaire du train doit être utilisé.

**Correction :** Faire `fit` uniquement sur X_train, puis `transform` sur X_test.

#### Problème 3 : Absence de courbe ROC/PR et de calibration de seuil

**Fichier :** `adfa_ld/results/generate_adfa_results.py` — pas de courbe ROC ni PR curve

**Impact :** Impossible de calibrer le FPR pour la production. Le seuil par défaut à 0.5 n'est pas optimal.

### Verdict ADFA-LD
Score relativement crédible (0.96) mais méthodologie à renforcer. Ce modèle est le moins problématique des 4.

---

## Modèle 2 — CIC-IDS-2017 (Flux Réseau)

### Score obtenu
- Accuracy: ~100%, F1: ~1.00 — **SUSPECT**

### Problèmes identifiés

#### Problème 1 : Shortcut Learning sur Destination Port (gravité : CRITIQUE)

**Fichier :** `cicids2017/preprocessing/preprocess.py`, ligne 35

```python
# CODE PROBLÉMATIQUE
X = df.drop(columns=[TARGET_COL])  # ← Garde TOUTES les colonnes
y = df[TARGET_COL]
```

**Explication :** Le dataset CIC-IDS-2017 contient `Destination Port` qui encode parfaitement le type d'attaque :
- Port 80/443 → Web Attacks
- Port 22 → Brute Force SSH
- Port 0 → DDoS

Le modèle apprend `Destination Port = X → Label Y` au lieu d'apprendre des patterns comportementaux réels. Ce n'est pas de la détection d'intrusion, c'est une règle de routage.

**Preuve :** Si tu lances `model.feature_importances_`, `Destination Port` sera en tête avec un score > 0.5.

**Correction :** Supprimer `Destination Port`, `Source Port`, et toutes les features directement dérivées des ports avant l'entraînement.

#### Problème 2 : Classes déséquilibrées masquées par SMOTE

**Fichier :** `cicids2017/preprocessing/preprocess.py`, ligne 52

```python
# SMOTE appliqué APRÈS le split → correct techniquement
smote = SMOTE(random_state=42)
X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)
```

**Explication :** Le SMOTE est correctement appliqué après le split (pas de leakage direct). Mais les classes `Web Attacks` sont très minoritaires dans le dataset original. Le SMOTE génère des exemples synthétiques — si les vraies attaques web ne varient pas beaucoup en comportement, les synthétiques sont quasi-identiques, facilitant l'apprentissage artificiel.

#### Problème 3 : Classes incohérentes avec la production

**Fichier :** `cicids2017/models/train_xgboost.py`, ligne 59

```python
# CODE PROBLÉMATIQUE — Classes hardcodées
classes_names = ['Brute Force', 'Normal Traffic', 'Port Scanning', 'Web Attacks']
```

**Explication :** Le vrai dataset CIC-IDS-2017 a 14+ classes d'attaques différentes. Ce modèle réduit à 4 classes sans documenter le mapping. En production, les classes réelles seront différentes.

### Verdict CIC-IDS-2017
Score de 1.00 est **artificiel**. Le modèle apprend le port de destination, pas le comportement réseau. À reconstruire en supprimant les features identifiantes.

---

## Modèle 3 — SIEM Windows (Event IDs)

### Score obtenu
- F1: ~1.00 — **CRITIQUE**

### Problèmes identifiés

#### Problème 1 : Label Leakage via Champs SePrivilege (gravité : CRITIQUE)

**Contexte :** Les Windows Security Event IDs (comme 4672 — Special Logon) contiennent des champs `SePrivilegeList` qui listent les privilèges accordés. Ces champs incluent des tokens comme :
- `SeDebugPrivilege` → présent lors d'une attaque Mimikatz
- `SeImpersonatePrivilege` → présent lors d'un mouvement latéral
- `SeTcbPrivilege` → présent lors d'une élévation de privilèges

**Explication :** Si ces tokens sont encodés en features (one-hot ou comptage), le modèle apprend essentiellement `SeDebugPrivilege présent → attaque`. Ce n'est pas de la détection ML, c'est une règle Sigma. Le F1=1.00 s'explique par le fait que ces features DÉFINISSENT l'attaque.

**Correction :** Supprimer tous les champs SePrivilege* du feature set. Construire des features comportementales pures à partir de fenêtres temporelles.

#### Problème 2 : Absence de Split Temporel

Les événements Windows sont naturellement temporels (timeline d'une attaque). Un split aléatoire fait "voir" au modèle des événements du futur pendant l'entraînement.

**Correction :** Split temporel — les 80% premiers événements chronologiquement en train, les 20% derniers en test.

#### Problème 3 : Granularité Event → Besoin de Fenêtres Comportementales

Un seul événement Windows n'est pas discriminant. Un EventID 4625 (échec logon) peut être bénin (mauvais mot de passe) ou malveillant (brute force). La différence est dans la **densité temporelle** : 100 EventID 4625 en 5 minutes = brute force.

**Correction :** Agréger les événements par fenêtres glissantes de 5 minutes et construire des features comportementales.

### Verdict SIEM Windows
Ce modèle est **prioritaire pour la reconstruction** car directement lié à l'infrastructure live. Le script de preprocessing et d'entraînement rigoureux est dans `siem_windows/`.

---

## Modèle 4 — Lateral Movement (Cloud/AD)

### Score obtenu
- F1: ~1.00 — **CRITIQUE**

### Problèmes identifiés

#### Problème 1 : Circularité Features = Règle de Labellisation (gravité : CRITIQUE)

**Fichier :** `raw_new/lateral_movement_logs.csv/get_microsoft_permissions.py`

**Explication :** La feature `metadata_is_critical` dans `microsoft_graph_permissions.csv` est définie manuellement dans le code :

```python
# CODE PROBLÉMATIQUE
critical_permissions = [
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    # ...
]
is_critical = "yes" if permission_name in critical_permissions else "no"
```

Si le modèle est entraîné en utilisant `is_critical` comme feature (ou les noms de permissions directement), et que le label `is_attack=1` est défini par la présence de ces mêmes permissions critiques, alors features = labels → circularité totale → F1=1.00 trivial.

#### Problème 2 : Pas de Données de Logs Réels

Les fichiers présents sont des **listes de référence** (roles AWS, Azure, AD groups), pas des logs d'activité réels. Sans logs d'activité temporelle (qui a accédé à quoi, quand, depuis quelle IP), un modèle de détection de mouvement latéral est impossible à entraîner correctement.

**Correction :** Utiliser le dataset HuggingFace `darkknight25/Advanced_SIEM_Dataset` ou générer des logs avec Atomic Red Team.

### Verdict Lateral Movement
Le modèle ne peut pas exister sans données d'activité réelles. À reconstruire entièrement à partir d'un dataset structuré.

---

## Plan de Correction — Priorités

| Priorité | Action | Modèle | Impact PFE |
|----------|--------|--------|------------|
| 1 | Reconstruire preprocessing SIEM Windows sans SePrivilege | SIEM Windows | FORT |
| 2 | Implémenter features comportementales + fenêtres temporelles | SIEM Windows | FORT |
| 3 | Split temporel sur tous les modèles | Tous | MOYEN |
| 4 | Supprimer Destination Port de CIC-IDS | CIC-IDS-2017 | FORT |
| 5 | Fix vectorizer leakage ADFA-LD | ADFA-LD | FAIBLE |
| 6 | Sourcer données réelles pour Lateral Movement | Lateral Movement | MOYEN |

---

## Ce qu'un Jury Attend

Un jury technique **ne récompense pas** un F1=1.00. Il récompense :
1. La **conscience** du problème ("J'ai identifié le leakage et voici la preuve")
2. La **correction rigoureuse** (split temporel, features défensibles)
3. Des **résultats honnêtes** (F1=0.85 avec bonne méthodologie > F1=1.00 avec leakage)
4. Une **démo live fonctionnelle** sur l'infrastructure réelle

Les scripts dans `siem_windows/training/train_siem.py` implémentent la méthodologie corrigée.
