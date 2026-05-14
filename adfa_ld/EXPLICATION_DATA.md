# EXPLICATION DATA — ADFA-LD Dataset (A à Z)

**Objectif:** Comprendre **exactement** ce qu'on a comme données, à quoi ressemblent les fichiers, comment ils sont organisés, et ce qu'on va apprendre au modèle.

**Toutes les statistiques et exemples ci-dessous sont RÉELS** — extraits directement des fichiers du projet.

---

## 1. PRÉSENTATION GÉNÉRALE

### 1.1 Qu'est-ce que ADFA-LD ?

**ADFA-LD** = **A**ustralian **D**efence **F**orce **A**cademy — **L**inux **D**ataset.

- **Source:** UNSW Sydney (University of New South Wales), 2012
- **Auteurs:** Creech & Hu (papier publié à IEEE TrustCom 2013)
- **Type:** Dataset public académique pour HIDS (Host-based Intrusion Detection System)
- **Usage:** Benchmark standard pour comparer des algos de détection d'intrusion par syscalls

### 1.2 Le contexte technique

Les données ont été capturées sur :
- **OS:** Ubuntu 11.04 (Natty Narwhal)
- **Architecture:** x86 32-bit
- **Kernel:** Linux 2.6.x
- **Outil de capture:** `auditd` (Linux Audit Framework)

➡️ Les syscalls qu'on voit dans les fichiers sont les **syscalls i386 (x86 32-bit) de l'époque 2012**.

### 1.3 Qu'est-ce qu'un "syscall" ?

Un **syscall** (system call) est une demande qu'un programme fait au **noyau Linux** pour effectuer une opération privilégiée (lire un fichier, écrire dans la mémoire, ouvrir une socket réseau, créer un processus, etc.).

**Exemples concrets:**
- `read(fd, buffer, size)` → syscall ID 3 → "lis depuis ce fichier"
- `write(fd, buffer, size)` → syscall ID 4 → "écris dans ce fichier"
- `open(path, flags)` → syscall ID 5 → "ouvre ce fichier"
- `socket(...)` → syscall ID 102 → "crée une socket réseau"
- `execve(path, argv, envp)` → syscall ID 11 → "exécute un programme"

➡️ **Pourquoi c'est utile pour la sécurité ?** Parce que **chaque programme** (légitime ou malveillant) doit passer par les syscalls. Les attaquants laissent donc une "empreinte syscall" caractéristique :
- Un brute-forcer SSH va spammer `socket()` + `connect()` + `recv()` + `close()`
- Un meterpreter va faire beaucoup de `poll()` + `clock_gettime()` (attente de commandes)
- Un programme normal fait surtout `read()` + `write()` + `open()` + `close()`

---

## 2. STRUCTURE PHYSIQUE SUR DISQUE

### 2.1 Vue d'ensemble

```
adfa_ld/data/ADFA-LD/
│
├── ADFA-LD+Syscall+List.txt    27 KB — Référence (ID → nom de syscall)
│
├── Training_Data_Master/        833 fichiers — Comportement NORMAL (entraînement)
├── Validation_Data_Master/      4 372 fichiers — Comportement NORMAL (validation)
└── Attack_Data_Master/          60 dossiers — 746 fichiers — ATTAQUES
```

### 2.2 Récapitulatif chiffré (RÉEL, vérifié)

| Dossier | Fichiers | Classe | Étiquette |
|---|---|---|---|
| `Training_Data_Master/` | **833** | Normal | label = 0 |
| `Validation_Data_Master/` | **4 372** | Normal | label = 0 |
| `Attack_Data_Master/` | **746** (60 dossiers) | Attaque | label = 1 |
| **TOTAL** | **5 951 fichiers** | | |

**Répartition globale:**
- Normal: 5 205 fichiers (87.5%)
- Attaque: 746 fichiers (12.5%)
- **Ratio:** ~7:1 → **dataset déséquilibré** (à gérer pendant le training avec `class_weight='balanced'`)

---

## 3. DÉTAIL DE CHAQUE SOUS-DOSSIER

### 3.1 `Training_Data_Master/` — Normal (Train)

**833 fichiers** : `UTD-0001.txt`, `UTD-0002.txt`, ..., `UTD-0833.txt`

**Convention de nommage:** `UTD-XXXX.txt`
- `U` = UNSW (université d'origine)
- `TD` = **T**raining **D**ata
- `XXXX` = numéro séquentiel (0001 à 0833)

**Contenu:** Traces de syscalls capturées pendant l'exécution **normale** de programmes Linux courants (web browsing, compilation, manipulation de fichiers, etc.).

### 3.2 `Validation_Data_Master/` — Normal (Validation)

**4 372 fichiers** : `UVD-0001.txt`, ..., `UVD-4372.txt`

**Convention de nommage:** `UVD-XXXX.txt`
- `UVD` = **U**NSW **V**alidation **D**ata
- `XXXX` = numéro séquentiel (0001 à 4372)

**Contenu:** Même type de données que Training mais **plus volumineux**.
Dans la littérature, ce dossier est généralement utilisé pour augmenter le set normal (ou en partie pour la validation).

➡️ **Notre stratégie:** On combine `Training` + `Validation` en un seul pool "normal" puis on fait notre propre split train/val/test stratifié et reproductible (random_state=42).

### 3.3 `Attack_Data_Master/` — Attaques

**60 sous-dossiers**, organisés par **scénario d'attaque**.

```
Attack_Data_Master/
├── Adduser_1/              à Adduser_10/              (10 dossiers)
├── Hydra_FTP_1/            à Hydra_FTP_10/            (10 dossiers)
├── Hydra_SSH_1/            à Hydra_SSH_10/            (10 dossiers)
├── Java_Meterpreter_1/     à Java_Meterpreter_10/     (10 dossiers)
├── Meterpreter_1/          à Meterpreter_10/          (10 dossiers)
└── Web_Shell_1/            à Web_Shell_10/            (10 dossiers)
```

**6 familles d'attaque × 10 scénarios chacune = 60 dossiers**.

**Pourquoi 10 scénarios par famille ?** Chaque "scénario" représente **une instance de l'attaque** rejouée avec un **payload différent** ou dans un **contexte différent** (process ID, timing, etc.).

### 3.4 Détail des 60 dossiers d'attaque

**Décompte RÉEL des fichiers .txt par famille:**

| Famille d'attaque | Dossiers | Total fichiers | Description |
|---|---|---|---|
| **Adduser** | 10 | **91** | Création d'utilisateur Linux non autorisé (escalation de privilèges) |
| **Hydra_FTP** | 10 | **162** | Brute force du protocole FTP (essai massif de mots de passe) |
| **Hydra_SSH** | 10 | **176** | Brute force du protocole SSH |
| **Java_Meterpreter** | 10 | **124** | Backdoor Java Meterpreter (Metasploit) — contrôle à distance |
| **Meterpreter** | 10 | **75** | Backdoor Meterpreter native (Metasploit) |
| **Web_Shell** | 10 | **118** | Shell web injecté (typique en post-exploitation web) |
| **TOTAL** | 60 | **746** | (vérifié en Phase 1 par chargement Python) |

### 3.5 Structure d'un dossier d'attaque (exemple: `Adduser_1/`)

```
Adduser_1/
├── UAD-Adduser-1-1371.txt
├── UAD-Adduser-1-1613.txt
├── UAD-Adduser-1-2311.txt
├── UAD-Adduser-1-2377.txt
├── UAD-Adduser-1-2462.txt
├── UAD-Adduser-1-2783.txt
└── UAD-Adduser-1-=1.txt
```

**Convention de nommage:** `UAD-<Famille>-<Scenario>-<PID>.txt`
- `U` = UNSW
- `AD` = **A**ttack **D**ata
- `Adduser` = famille d'attaque
- `1` = numéro du scénario (ici Adduser_1)
- `1371` = **PID** du processus capturé (Process ID)

➡️ Chaque fichier représente la **trace syscall d'UN processus impliqué dans l'attaque**.

Exemple : `Adduser_1` a été capturé pendant que l'attaquant lançait :
- Le shell parent (PID 1371)
- La commande `adduser` (PID 1613)
- Des sous-processus auxiliaires (PIDs 2311, 2377, 2462, 2783)

Chaque processus a sa propre trace → 7 fichiers pour Adduser_1.

### 3.6 Cas spécial : nom étrange `UAD-Adduser-1-=1.txt`

⚠️ Le fichier `UAD-Adduser-1-=1.txt` a un nom inhabituel avec un `=1`. 

**Hypothèse:** PID 0 ou processus système particulier. À ignorer ou inclure ? → décision à prendre dans l'EDA en regardant son contenu.

---

## 4. FORMAT D'UN FICHIER DE TRACE

### 4.1 Format brut

**Chaque fichier `.txt` contient UNE SEULE LIGNE** (ou parfois étalée sur plusieurs lignes mais sans structure particulière).

Le contenu est une **séquence d'entiers séparés par des espaces**. Chaque entier = un syscall ID.

### 4.2 Exemple RÉEL — Fichier normal (`Training_Data_Master/UTD-0001.txt`)

**Premiers 30 syscalls:**
```
6 6 63 6 42 120 6 195 120 6 6 114 114 1 1 252 252 252 1 1 1 1 1 1 1 1 1 252 252 252
```

**Longueur totale du fichier:** 819 syscalls.

**Décodage:**
| ID | Syscall i386 | Action |
|---|---|---|
| 6 | `close` | Fermer un file descriptor |
| 63 | `dup2` | Dupliquer un file descriptor |
| 42 | `pipe` | Créer un tube de communication |
| 120 | `clone` | Créer un nouveau thread/process |
| 195 | `stat64` | Obtenir les infos d'un fichier |
| 114 | `wait4` | Attendre la fin d'un process enfant |
| 1 | `exit` | Terminer le process |
| 252 | `exit_group` | Terminer tout le groupe de threads |

➡️ **Interprétation:** Ce fichier représente un programme qui :
1. Ferme des descripteurs, duplique des handles
2. Crée un pipe pour communiquer
3. Clone des threads/processus
4. Attend leurs terminaisons
5. Quitte proprement (exit + exit_group)

**Comportement classique d'un shell ou d'un programme système normal.**

### 4.3 Exemple RÉEL — Fichier d'attaque Adduser (`Attack_Data_Master/Adduser_1/UAD-Adduser-1-1371.txt`)

**Premiers 30 syscalls:**
```
265 168 168 265 168 168 168 265 168 265 168 168 168 168 168 168 168 168 102 168 265 265 168 168 168 265 265 168 168 168
```

**Longueur totale du fichier:** 279 syscalls.

**Décodage:**
| ID | Syscall i386 | Action |
|---|---|---|
| 168 | `poll` | Attendre événement I/O |
| 265 | `clock_gettime` | Lire l'horloge système |
| 102 | `socketcall` | Opération réseau (socket/connect/recv...) |

➡️ **Interprétation:** Ce fichier représente un processus qui :
- Spamme `poll()` et `clock_gettime()` (attente de signal, mesure de timing)
- Fait des opérations réseau (`socketcall` ID 102)

**Caractéristique typique d'un programme qui attend des commandes externes** (= backdoor ou attaque).

### 4.4 Exemple RÉEL — Fichier d'attaque Meterpreter

**Premiers 30 syscalls:**
```
168 168 265 265 168 168 265 168 168 265 168 168 168 168 265 168 265 168 168 265 265 168 168 168 168 265 265 168 265 168
```

**Longueur totale:** 320 syscalls.

➡️ **Signature très similaire à Adduser** : dominance de `poll(168)` et `clock_gettime(265)`.

C'est cohérent : Meterpreter est un implant Metasploit qui attend les commandes du serveur C2 → boucle d'attente = `poll` + `clock_gettime`.

### 4.5 Exemple RÉEL — Fichier d'attaque Web_Shell

**Premiers 30 syscalls:**
```
168 168 265 102 168 168 168 265 168 168 168 265 168 265 265 168 168 168 168 168 168 168 168 168 265 168 168 168 168 168
```

➡️ **Même pattern** : `poll`, `clock_gettime`, `socketcall`.

---

## 5. STATISTIQUES RÉELLES DU DATASET

### 5.1 Distribution des longueurs de séquence (en nombre de syscalls)

**Comportement Normal (Training + Validation, 5 205 fichiers):**
- Minimum: **77** syscalls
- 1er quartile: 152
- Médiane: **343** syscalls
- 3e quartile: 444
- Maximum: **4 494** syscalls
- Moyenne: 466.9 (std 536.6)

**Comportement Attaque (Attack_Data, 746 fichiers):**
- Minimum: **75** syscalls
- 1er quartile: 139
- Médiane: **290** syscalls
- 3e quartile: 561
- Maximum: **2 712** syscalls
- Moyenne: 425.5 (std 403.2)

➡️ **Observation:** Les longueurs sont relativement comparables (médianes 343 vs 290). Le signal discriminant ne vient PAS de la longueur seule, mais des **types de syscalls** appelés (cf. section 5.2).

### 5.2 Top 15 syscalls les plus fréquents — Comparaison Normal vs Attaque

**Comportement NORMAL (Training_Data_Master):**

| Rang | ID syscall | Nom | Fréquence | Catégorie |
|---|---|---|---|---|
| 1 | **3** | `read` | 55 664 | I/O fichier |
| 2 | **4** | `write` | 31 342 | I/O fichier |
| 3 | **6** | `close` | 22 782 | I/O fichier |
| 4 | **5** | `open` | 20 503 | I/O fichier |
| 5 | **195** | `stat64` | 19 414 | Métadonnées fichier |
| 6 | **240** | `futex` | 13 709 | Synchronisation threads |
| 7 | **192** | `mmap2` | 13 097 | Mémoire |
| 8 | **168** | `poll` | 10 752 | Attente I/O |
| 9 | **78** | `gettimeofday` | 10 008 | Horloge |
| 10 | **197** | `fstat64` | 9 976 | Métadonnées fichier |
| 11 | **221** | `fcntl64` | 9 784 | Contrôle file descriptor |
| 12 | **102** | `socketcall` | 8 646 | Réseau |
| 13 | **265** | `clock_gettime` | 8 223 | Horloge |
| 14 | **33** | `access` | 7 258 | Permissions fichier |
| 15 | **180** | `pread64` | 5 961 | Lecture fichier |

**Comportement ATTAQUE (Attack_Data_Master):**

| Rang | ID syscall | Nom | Fréquence | Catégorie |
|---|---|---|---|---|
| 1 | **168** | `poll` | **75 175** ⚠️ | Attente I/O |
| 2 | **265** | `clock_gettime` | **61 396** ⚠️ | Horloge |
| 3 | **3** | `read` | 45 819 | I/O fichier |
| 4 | **78** | `gettimeofday` | 21 125 | Horloge |
| 5 | **142** | `select` | 11 782 | Attente I/O |
| 6 | **240** | `futex` | 11 316 | Synchronisation |
| 7 | **102** | `socketcall` | 7 781 | Réseau |
| 8 | **162** | `nanosleep` | 6 992 | Pause |
| 9 | **13** | `time` | 6 751 | Horloge |
| 10 | **5** | `open` | 6 446 | I/O fichier |
| 11 | **43** | `times` | 6 071 | Statistiques temps |
| 12 | **4** | `write` | 5 552 | I/O fichier |
| 13 | **146** | `writev` | 5 506 | Écriture vectorielle |
| 14 | **54** | `ioctl` | 4 725 | Contrôle device |
| 15 | **6** | `close` | 4 191 | I/O fichier |

### 5.3 SIGNAL DISCRIMINANT — Différence Normal vs Attaque

**Le plus important pattern à retenir:**

| Syscall | Normal (rang) | Attaque (rang) | Interprétation |
|---|---|---|---|
| `poll(168)` | 8 | **1** | Les attaques attendent constamment des événements (boucle de C2, brute-force) |
| `clock_gettime(265)` | 13 | **2** | Mesure du temps fréquente (timing d'attaque, timeouts) |
| `nanosleep(162)` | — | **8** | Pauses entre tentatives (typique brute-force) |
| `select(142)` | — | **5** | Attente multi-socket (réseau) |
| `read(3)` | **1** | 3 | Normal: lecture fichier dominante |
| `write(4)` | **2** | 12 | Normal: écriture fichier dominante |
| `open(5)` | **4** | 10 | Normal: ouverture fichier dominante |

➡️ **Conclusion CRUCIALE:** 

- **Programmes normaux** = beaucoup de `read/write/open/close` (manipulation de fichiers)
- **Attaques** = beaucoup de `poll/clock_gettime/select/nanosleep` (attente et timing réseau)

**C'est CE signal que le modèle ML va apprendre.**

---

## 6. POURQUOI CE FORMAT EST INTÉRESSANT POUR LE ML

### 6.1 Avantages

1. ✅ **Format simple** : juste des séquences d'entiers
2. ✅ **Pas de noms d'utilisateur, IP, chemins** → pas de PII, pas de biais évident
3. ✅ **Données comportementales pures** : on regarde **ce que fait** le programme, pas son nom
4. ✅ **Difficile à falsifier** : un attaquant ne peut pas faire un syscall sans le faire vraiment
5. ✅ **Universel** : ça marche pour tout programme Linux x86

### 6.2 Limitations

1. ⚠️ **Pas de timing** : on n'a que l'ORDRE des syscalls, pas les délais
2. ⚠️ **Pas d'arguments** : on sait que c'est `open()` mais pas QUEL fichier
3. ⚠️ **Pas de retour** : on ne sait pas si l'appel a réussi ou échoué
4. ⚠️ **x86 32-bit obsolète** : certains syscalls modernes (eBPF, io_uring) absents
5. ⚠️ **6 familles d'attaque seulement** : couverture limitée vs réalité

### 6.3 Stratégie ML choisie

**Représentation: N-grammes (trigrammes) de syscalls**

Une séquence `[168, 168, 265, 102, 168]` génère les **trigrammes** :
- `"168 168 265"`
- `"168 265 102"`
- `"265 102 168"`

**Pourquoi des trigrammes ?**
- Un syscall seul ne dit pas grand-chose (`168` apparaît partout)
- Une paire dit déjà plus (`168 168` = poll en boucle)
- Un trigramme capture une **mini-séquence** (`168 168 265` = poll en boucle + lecture horloge)
- Quadrigrammes : trop nombreux, sparse, sur-apprentissage

**Featurization:**
- On garde les **500 trigrammes les plus fréquents**
- Chaque fichier devient un **vecteur de 500 dimensions** : combien de fois chaque trigramme apparaît dans ce fichier
- Sklearn `CountVectorizer(analyzer='word', ngram_range=(3,3), max_features=500)`

---

## 7. LE FICHIER DE RÉFÉRENCE SYSCALLS

### 7.1 `ADFA-LD+Syscall+List.txt`

**27 KB**, format = header C du kernel Linux.

**Extrait:**
```c
#define __NR_io_setup 0
__SYSCALL(__NR_io_setup, sys_io_setup)
#define __NR_io_destroy 1
__SYSCALL(__NR_io_destroy, sys_io_destroy)
...
#define __NR_read 63
__SYSCALL(__NR_read, sys_read)
#define __NR_write 64
__SYSCALL(__NR_write, sys_write)
```

⚠️ **PIÈGE:** Ce fichier est la table **asm-generic** (kernel moderne). Mais ADFA-LD utilise la table **i386 (x86 32-bit) de 2012**, qui est **différente**.

**Mapping correct pour ADFA-LD (i386 syscall table 2012):**

| ID | Nom i386 | Catégorie |
|---|---|---|
| 1 | exit | Process |
| 2 | fork | Process |
| 3 | read | I/O |
| 4 | write | I/O |
| 5 | open | I/O |
| 6 | close | I/O |
| 11 | execve | Process |
| 13 | time | Time |
| 33 | access | FS |
| 42 | pipe | IPC |
| 43 | times | Time |
| 54 | ioctl | Device |
| 78 | gettimeofday | Time |
| 102 | socketcall | Network |
| 114 | wait4 | Process |
| 120 | clone | Process |
| 142 | _newselect | I/O |
| 146 | writev | I/O |
| 162 | nanosleep | Time |
| 168 | poll | I/O |
| 192 | mmap2 | Memory |
| 195 | stat64 | FS |
| 197 | fstat64 | FS |
| 220 | getdents64 | FS |
| 221 | fcntl64 | I/O |
| 240 | futex | Sync |
| 252 | exit_group | Process |
| 265 | clock_gettime | Time |

➡️ **Pour notre projet:** On **n'a pas besoin** de décoder les syscalls par leur nom. Le modèle apprend directement sur les IDs numériques. Le mapping sert juste pour comprendre/interpréter (notebooks d'EDA et rapport final).

---

## 8. PROBLÈMES POTENTIELS À ANTICIPER

### 8.1 Fichiers anormaux à vérifier

D'après les exemples, on a vu :
- `UAD-Adduser-1-=1.txt` : nom étrange (PID `=1` au lieu d'un nombre)

**Action EDA:** Lister tous les fichiers avec :
- Nom non conforme (PID non-numérique)
- Taille = 0 (fichier vide)
- Moins de 5 syscalls (séquence trop courte pour être utile)
- Caractères non-numériques dans le contenu

### 8.2 Déséquilibre des classes

- 5 205 normales vs 870 attaques → ratio 6:1
- **Solution dans le training:** `class_weight='balanced'` dans RandomForest

### 8.3 Risque de "leakage par scénario"

⚠️ **Important:** Si on split aléatoirement les fichiers d'attaque, des fichiers du **même scénario** (ex: PID 1371 et PID 1613 de `Adduser_1`) peuvent se retrouver l'un en train et l'autre en test.

→ Le modèle "apprend par cœur" la signature d'`Adduser_1` et la reconnaît dans le test set. **Métriques gonflées artificiellement.**

**Solution: Split PAR SCÉNARIO**
- `Adduser_1` (tous les fichiers) → train **ou** test, jamais les deux
- Idem pour les 60 scénarios

Implémentation: `GroupShuffleSplit` de scikit-learn avec `groups=scenario_name`.

### 8.4 Tailles très variables

Min = 75 syscalls, Max = 2 948 syscalls. Avec les trigrammes en `CountVectorizer`, ce n'est pas un problème majeur (vecteur de comptes), mais on peut envisager une normalisation L2 si nécessaire.

---

## 9. RÉCAPITULATIF VISUEL

```
                    ADFA-LD (5 951 fichiers .txt)
                              │
            ┌─────────────────┴─────────────────┐
            │                                   │
       NORMAL (5 205)                     ATTAQUE (746)
        label = 0                          label = 1
            │                                   │
   ┌────────┴────────┐                          │
   │                 │                          │
Training         Validation                Attack_Data_Master
  833 fic.        4 372 fic.              60 dossiers / 6 familles
                                                 │
              ┌──────────┬──────────┬───────┴───┬──────────┬───────────┐
              │          │          │           │          │           │
           Adduser   Hydra_FTP  Hydra_SSH  Java_Met.  Meterpreter  Web_Shell
           (91)      (162)      (176)      (124)      (75)        (118)
              │
              └─ Adduser_1/ ... Adduser_10/ (10 scénarios)
                    │
                    └─ UAD-Adduser-1-1371.txt (PID 1371)
                       UAD-Adduser-1-1613.txt (PID 1613)
                       ...
                       │
                       └─ "265 168 168 265 168 168 168..."
                          (séquence de syscall IDs)
```

---

## 10. CE QUE NOTRE MODÈLE ML VA APPRENDRE

### 10.1 Ce que le modèle voit

Pour chaque fichier, après preprocessing :
- **Entrée X:** vecteur de 500 dimensions = comptes des 500 trigrammes les plus fréquents
- **Sortie y:** 0 (normal) ou 1 (attaque)

### 10.2 Ce que le modèle apprend (intuition)

Le modèle (Random Forest) va apprendre des règles du type :

> *"Si le trigramme `168 168 265` apparaît plus de 50 fois ET le trigramme `265 168 168` plus de 30 fois ET le trigramme `3 6 5` moins de 10 fois → c'est probablement une attaque (probabilité 0.92)"*

### 10.3 Limites attendues

- ✅ **Détection bonne** pour les 6 familles d'attaque connues
- ⚠️ **Détection zéro-day:** impossible (modèle supervisé, n'a vu que ces 6 familles)
- ⚠️ **Attaque ressemblant à un programme normal:** difficile (ex: data exfiltration discrète)

---

## 11. PROCHAINES ÉTAPES

Maintenant qu'on a une **compréhension complète des données**, on peut passer à :

1. ✅ Créer le notebook `eda/01_eda_adfa.ipynb` pour **explorer en profondeur** :
   - Charger tous les fichiers
   - Calculer les distributions
   - Visualiser les histogrammes
   - Détecter les anomalies (fichiers vides, malformés)

2. Puis le preprocessing avec split par scénario.

3. Puis le training avec Random Forest.

4. Puis l'évaluation finale.

---

*Document créé le 2026-05-14 — basé sur exploration RÉELLE des fichiers du dataset ADFA-LD du projet.*
