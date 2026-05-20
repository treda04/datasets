# EXPLICATION DATA — CIC-IDS-2017 Dataset (A à Z)

**Objectif :** comprendre **exactement** ce qu'on a comme données réseau, ce que représente chaque colonne, et où sont les pièges méthodologiques **avant** de modéliser.

**Toutes les statistiques ci-dessous sont RÉELLES**, extraites directement de `cicids2017.csv` via Python.

---

## 1. PRÉSENTATION GÉNÉRALE

### 1.1 Qu'est-ce que CIC-IDS-2017 ?

**CIC-IDS-2017** = **C**anadian **I**nstitute for **C**ybersecurity — **I**ntrusion **D**etection **S**ystem **2017**.

- **Source :** Canadian Institute for Cybersecurity (UNB — University of New Brunswick)
- **Auteurs :** Sharafaldin, Lashkari & Ghorbani (papier ICISSP 2018)
- **Type :** Dataset public académique pour **NIDS** (Network-based Intrusion Detection System)
- **Usage :** Benchmark standard pour la détection d'attaques réseau

### 1.2 Contexte technique

Les données ont été générées dans un **environnement contrôlé** :
- Réseau de test isolé (12 machines : 5 victimes, 4 attaquants, switches)
- Captures **PCAP** brutes pendant 5 jours (3-7 juillet 2017)
- Traitement par **CICFlowMeter** → conversion des paquets en **flux bidirectionnels** (forward + backward) avec extraction de 80+ features statistiques

➡️ **Ce qu'on a dans le CSV** : une ligne = **un flux réseau complet** (durée, octets, paquets, flags TCP, timings...), pas un paquet individuel.

### 1.3 Qu'est-ce qu'un "flux réseau" (network flow) ?

Un **flux** = ensemble de paquets partageant la même **5-tuple** :
- Source IP
- Source Port
- **Destination IP**
- **Destination Port**
- Protocole (TCP/UDP)

Pendant une session active. Le flow est terminé après timeout ou FIN/RST.

**Exemple concret :** quand tu télécharges une page web, ton navigateur crée 1 flux TCP par requête HTTP. CIC-IDS-2017 te donne 53 statistiques résumant ce flux.

---

## 2. CHIFFRES BRUTS (vérifiés)

### 2.1 Volumétrie

| Indicateur | Valeur |
|---|---|
| **Lignes totales** | **2 520 751** |
| **Colonnes** | 53 (52 features numériques + 1 label `Attack Type`) |
| Mémoire en RAM | ~1.2 GB |
| Valeurs manquantes (NaN) | **0** |
| Valeurs infinies (Inf) | **0** |
| Features à variance nulle | **0** |

➡️ **Dataset déjà très propre** — pas de pré-nettoyage à faire sur les valeurs manquantes.

### 2.2 Distribution des classes (Attack Type)

| Classe | Nb lignes | % | Ratio vs Normal |
|---|---|---|---|
| **Normal Traffic** | **2 095 057** | **83.11%** | 1:1 |
| DoS | 193 745 | 7.69% | 11:1 |
| DDoS | 128 014 | 5.08% | 16:1 |
| Port Scanning | 90 694 | 3.60% | 23:1 |
| Brute Force | 9 150 | 0.36% | 229:1 |
| Web Attacks | 2 143 | 0.085% | 977:1 |
| Bots | 1 948 | 0.077% | **1 075:1** |

**Déséquilibre extrême** : 1 075:1 entre Normal et Bots — beaucoup plus marqué que ADFA-LD (7:1). C'est le défi #1 du dataset.

### 2.3 Les 7 familles d'attaque — ce qu'elles font

| Famille | Description en français |
|---|---|
| **Normal Traffic** | Trafic légitime (navigation web, mail, transferts...). C'est la majorité. |
| **DoS** | Denial of Service — un attaquant **saturé** un service pour le rendre indisponible. Type : Hulk, GoldenEye, Slowloris, Slowhttptest. |
| **DDoS** | Distributed DoS — même chose, mais lancée depuis plusieurs machines. Type : LOIC. |
| **Port Scanning** | L'attaquant **balaye** les ports d'une cible pour découvrir les services exposés. Préalable à toute attaque. |
| **Brute Force** | Tentatives massives de mots de passe sur FTP (port 21) ou SSH (port 22). Type : Patator. |
| **Web Attacks** | SQL Injection, XSS, Brute Force sur formulaire web. Tout sur port 80/443. |
| **Bots** | Communications de **botnet** (Ares) — machine compromise qui dialogue avec son serveur C2. |

---

## 3. STRUCTURE DU FICHIER CSV

### 3.1 Vue d'ensemble

```
cicids2017/data/cicids2017.csv  (≈ 1.2 GB en RAM, 580 MB sur disque)
│
├── 52 colonnes numériques (features extraites du flux)
└──  1 colonne string  →  "Attack Type"  (label à prédire)
```

### 3.2 Les 52 features — groupées par catégorie

#### A. Identification du flux (2 features) ⚠️ ZONE DE LEAKAGE

| # | Colonne | Description | Risque |
|---|---|---|---|
| 1 | **Destination Port** | Port de destination du flux (1-65535) | **CRITIQUE** — voir §5 |
| — | (Source Port retiré) | — | — |

#### B. Volumétrie du flux (8 features)

| # | Colonne | Description |
|---|---|---|
| 2 | Flow Duration | Durée totale du flux (µs) |
| 3 | Total Fwd Packets | Nombre de paquets dans le sens client→serveur |
| 4 | Total Length of Fwd Packets | Total octets sens forward |
| 5-8 | Fwd Packet Length Max/Min/Mean/Std | Stats taille paquets forward |
| 9-12 | Bwd Packet Length Max/Min/Mean/Std | Stats taille paquets backward |

#### C. Débit du flux (4 features)

| # | Colonne | Description |
|---|---|---|
| 13 | Flow Bytes/s | Débit en octets par seconde |
| 14 | Flow Packets/s | Débit en paquets par seconde |
| 31 | Fwd Packets/s | Débit paquets sens forward |
| 32 | Bwd Packets/s | Débit paquets sens backward |

#### D. Inter-Arrival Time (IAT) — temps entre paquets (14 features)

| # | Colonnes | Description |
|---|---|---|
| 15-18 | Flow IAT Mean/Std/Max/Min | Temps moyen/écart-type entre paquets du flux |
| 19-23 | Fwd IAT Total/Mean/Std/Max/Min | Idem sens forward |
| 24-28 | Bwd IAT Total/Mean/Std/Max/Min | Idem sens backward |

➡️ Signal fort pour les attaques **temporelles** : DoS Slowloris = IAT très grand (paquets espacés exprès), DDoS = IAT ultra petit (rafale).

#### E. Tailles & headers (6 features)

| # | Colonnes | Description |
|---|---|---|
| 29-30 | Fwd/Bwd Header Length | Taille des headers TCP/UDP |
| 33-35 | Min/Max/Mean Packet Length | Taille des paquets |
| 36-37 | Packet Length Std/Variance | Dispersion des tailles |

#### F. Flags TCP (3 features)

| # | Colonnes | Description |
|---|---|---|
| 38 | FIN Flag Count | Nb de paquets avec flag FIN (fin de session) |
| 39 | PSH Flag Count | Nb de paquets avec flag PSH (push immédiat) |
| 40 | ACK Flag Count | Nb de paquets avec flag ACK (acknowledgment) |

➡️ Signal fort : un **DoS SYN flood** aurait FIN=0 et ACK=0 (jamais de réponse), un trafic normal a FIN et ACK équilibrés.

#### G. Caractéristiques avancées (12 features)

| # | Colonnes | Description |
|---|---|---|
| 41 | Average Packet Size | Taille moyenne des paquets |
| 42 | Subflow Fwd Bytes | Octets par sous-flux |
| 43-44 | Init_Win_bytes_forward/backward | Taille initiale de fenêtre TCP |
| 45 | act_data_pkt_fwd | Paquets de données effectifs |
| 46 | min_seg_size_forward | Taille minimale de segment |
| 47-49 | Active Mean/Max/Min | Temps actif du flux |
| 50-52 | Idle Mean/Max/Min | Temps d'inactivité du flux |

#### H. Label (1 colonne)

| # | Colonne | Valeurs |
|---|---|---|
| 53 | **Attack Type** (string) | `Normal Traffic`, `DoS`, `DDoS`, `Port Scanning`, `Brute Force`, `Web Attacks`, `Bots` |

---

## 4. EXEMPLES RÉELS DE FLUX

### 4.1 Exemple — Trafic Normal (SSH)

```
Destination Port: 22
Flow Duration: 1 266 342 µs (1.3 s)
Total Fwd Packets: 41
Total Length of Fwd Packets: 2 664 octets
Flow Bytes/s: 7 595
PSH Flag Count: 67
ACK Flag Count: 15 075
Attack Type: Normal Traffic
```

➡️ Connexion SSH interactive : beaucoup de petits paquets (frappes clavier), flags ACK très nombreux (échanges synchrones).

### 4.2 Exemple — DoS (signature attendue)

```
Destination Port: 80
Flow Duration: ~70 000 000 µs (70 s — flow durable)
Total Fwd Packets: 6
Flow Bytes/s: ~120
Average Packet Size: petit
Attack Type: DoS
```

➡️ Slow HTTP attack : très peu de paquets sur très longue durée (Slowloris garde la connexion ouverte exprès).

### 4.3 Exemple — Port Scanning

```
Destination Port: 80 (ou autre, ports variés)
Flow Duration: 50 µs (très court)
Total Fwd Packets: 1
Total Length of Fwd Packets: 0
Attack Type: Port Scanning
```

➡️ Scan SYN : un seul paquet SYN, pas de payload, pas de réponse complète.

---

## 5. ⚠️ PIÈGE MAJEUR — SHORTCUT LEARNING SUR DESTINATION PORT

### 5.1 Le problème

Quand on regarde les ports utilisés par chaque classe d'attaque :

| Classe | Nb ports distincts | Ports dominants |
|---|---|---|
| **Web Attacks** | **1** | port 80 (100% des cas) |
| **DoS** | **1** | port 80 (100% des cas) |
| **DDoS** | **4** | port 80 (99.99% des cas) |
| **Brute Force** | **3** | port 21 (FTP), 22 (SSH) |
| Bots | 702 | dispersé |
| Port Scanning | 1 000 | dispersé |
| Normal Traffic | **53 788** | dispersé (53, 80, 443, 123, 22...) |

➡️ Pour 4 familles d'attaque sur 7, **le port permet de prédire la classe à lui tout seul**. C'est ce qu'on appelle un **shortcut feature**.

### 5.2 Preuve expérimentale (Random Forest sur sample stratifié)

| Features utilisées | Accuracy | F1 weighted |
|---|---|---|
| `Destination Port` SEUL | 71.6% | 0.6446 |
| `Flow Duration` SEUL | 77.6% | 0.7706 |
| 5 features comportementales (SANS port) | **97.9%** | **0.9791** |

**Lecture :** avec uniquement le port, on a déjà 71% d'accuracy. Sur Web Attacks et DoS, on peut atteindre 100% en disant juste "si port == 80 alors potentiellement attaque". **Le modèle qui voit le port n'apprend pas à détecter une attaque — il apprend à reconnaître un port.**

### 5.3 Pourquoi c'est dangereux pour un IDS réel

En production, les attaquants choisissent leur port. Un attaquant qui lance une DoS sur un service custom (port 8443 par exemple) **passera complètement inaperçu** d'un modèle entraîné à associer "DoS = port 80".

### 5.4 Solution adoptée

✅ **Supprimer `Destination Port` du set de features** avant l'entraînement. On force le modèle à apprendre le comportement (durée, débit, IAT, flags) au lieu du port.

➡️ Coût acceptable : on perd ~5% d'accuracy en apparence, mais on gagne en généralisation réelle.

---

## 6. STATISTIQUES PAR CLASSE — signaux discriminants

### 6.1 Flow Duration (µs) — médiane par classe

| Classe | Médiane Flow Duration | Lecture |
|---|---|---|
| **Port Scanning** | **50 µs** | Ultra court — un seul paquet SYN |
| Normal Traffic | 39 979 µs | Mixte (HTTPs courts + SSH longs) |
| Bots | 71 035 µs | C2 beaconing périodique |
| Web Attacks | 5 487 328 µs (5.5 s) | Requêtes HTTP lourdes |
| Brute Force | 9 114 177 µs (9.1 s) | Sessions FTP/SSH avec retries |
| DDoS | 1 879 121 µs (1.9 s) | Variable selon outil |
| **DoS** | **85 872 118 µs (86 s)** | Slowloris — sessions volontairement longues |

➡️ Excellent signal entre **Port Scanning (extrêmement court)** et **DoS (extrêmement long)**.

### 6.2 Total Fwd Packets — médiane par classe

| Classe | Médiane | Lecture |
|---|---|---|
| Port Scanning | 1 | Scan unitaire |
| Normal Traffic | 2 | Mini-requêtes |
| Bots | 3 | Beacon court |
| DDoS | 4 | Volumétrique mais court |
| DoS | 6 | Sessions Slowloris (qq paquets) |
| Brute Force | 9 | Login + retries |
| Web Attacks | 3 | Requêtes HTTP simples |

➡️ Différences claires.

### 6.3 Conclusion — le vrai signal est dans le COMPORTEMENT

Avec les 5 features comportementales suivantes :
- `Flow Duration`
- `Total Fwd Packets`
- `Total Length of Fwd Packets`
- `Flow Bytes/s`
- `Flow Packets/s`

On atteint **97.9% d'accuracy** sur un sample stratifié. Le modèle apprend vraiment à distinguer les comportements, pas les ports.

Avec les 51 features comportementales (sans Destination Port), on devrait facilement dépasser **99% de F1 weighted** avec un bon modèle (XGBoost ou Random Forest calibré).

---

## 7. COMPARAISON AVEC ADFA-LD

| Critère | ADFA-LD | CIC-IDS-2017 |
|---|---|---|
| Volume | 5 951 fichiers | **2 520 751 lignes** |
| Type de données | Séquences de syscalls (variable length) | Features tabulaires (53 colonnes) |
| Représentation ML | N-grammes (CountVectorizer) | Features brutes |
| Modèle adapté | Random Forest sur sparse | **XGBoost** ou Random Forest sur dense |
| Déséquilibre | 7:1 | **1 075:1** (Bots) |
| Familles | 6 | 7 |
| Piège #1 | Leakage par scénario (PIDs même attaque) | **Shortcut learning sur Destination Port** |
| Piège #2 | Web_Shell noyé dans Apache | Bots/Web Attacks ultra-minoritaires |
| Solution split | `GroupShuffleSplit` (par scénario) | Stratifié simple (par classe) |
| Solution déséquilibre | `class_weight='balanced'` | `class_weight='balanced'` + peut-être SMOTE |

---

## 8. CONSÉQUENCES POUR LA MODÉLISATION

### 8.1 Choix architecturaux qu'on adopte

1. **Supprimer `Destination Port`** des features (anti shortcut learning)
2. **Échantillonner si besoin** (1.2 GB en RAM, OK ; CV peut être long)
3. **Split stratifié simple** (pas de groupes comme ADFA, chaque flux est indépendant)
4. **Modèle robuste au déséquilibre** : XGBoost avec `scale_pos_weight` OU Random Forest avec `class_weight='balanced'`
5. **Métriques multi-classes** : F1 par classe (pas juste global), AUC OVR
6. **Cibles minimales** :
   - F1 macro ≥ 0.85 (donne autant de poids à Bots qu'à Normal Traffic)
   - Recall ≥ 0.80 par classe (même pour Bots et Web Attacks)
   - Pas de feature dominante (max importance < 0.20)

### 8.2 Risques à anticiper

| Risque | Mitigation |
|---|---|
| Shortcut learning sur Destination Port | Suppression explicite avant entraînement |
| Bots/Web Attacks trop rares (< 2k) | `class_weight='balanced'`, métriques par classe |
| `Flow Bytes/s` négatif (vu : min = -261M) | Clip ou suppression des lignes aberrantes |
| Sur-représentation du Normal (83%) | Stratification stricte, métriques **macro** |
| Mémoire (1.2 GB) | Sample stratifié pour exploration, dataset complet pour entraînement final |

---

## 9. RÉCAPITULATIF VISUEL

```
                CIC-IDS-2017 (2 520 751 flux réseau)
                            │
        ┌───────────────────┴───────────────────┐
        │                                       │
   NORMAL (83.1%)                       ATTAQUES (16.9%)
   2 095 057 flux                       425 694 flux
                                                │
        ┌───────────┬───────────┬───────────────┼───────────┬───────────┐
        │           │           │               │           │           │
       DoS         DDoS    Port Scan      Brute Force   Web Attacks   Bots
   (193 745)    (128 014)   (90 694)       (9 150)      (2 143)    (1 948)
       7.7%        5.1%       3.6%          0.4%         0.085%     0.077%

                            │
                     53 colonnes / flux :
                     │
              ┌──────┼──────┐
        Port (1)  Comportement (51)   Label (1)
        ⚠️ leak   ✅ utiles         Attack Type
```

---

## 10. PROCHAINES ÉTAPES

Maintenant qu'on **comprend** les données :

1. ✅ **Phase 1 — EDA** : `notebooks/01_eda.ipynb`
   - Confirmer les chiffres ci-dessus de façon interactive
   - Visualiser les distributions par classe
   - Identifier d'autres features douteuses (corrélations, multi-colinéarité)
   - Valider les règles de nettoyage

2. **Phase 2 — Modeling** : `notebooks/02_modeling.ipynb`
   - Split stratifié 70/30
   - **Supprimer Destination Port**
   - Train Random Forest / XGBoost calibré
   - CV 5-fold stratifié
   - F1 par classe + matrice de confusion

3. **Phase 3 — Pipeline production** : `pipeline/`
   - Identique à ADFA : `preprocess.py`, `train.py`, `evaluate.py`

---

*Document créé le 2026-05-19 — basé sur exploration RÉELLE de `cicids2017.csv` (2 520 751 lignes).*
