# EXPLICATION_DATA — Dataset SIEM Windows (APT29 / OTRF Mordor)

**Auteur :** Reda — UIR Cybersécurité (PFE 2026)
**Dataset :** APT29 / Cozy Bear — emulation MITRE ATT&CK / OTRF Mordor
**Stockage local :** `siem_windows/data/raw/{day1,day2}/*.json`
**Stats extraites le :** 2026-05-20 (`results/eda/raw_stats.json`)

Ce document décrit **A→Z** les données utilisées par le modèle `siem_windows`, avec **les chiffres réels** obtenus en streaming sur les deux JSON bruts (script `scripts_aux/extract_raw_stats.py`). Toute déduction est sourcée par un chiffre, pas par une intuition.

---

## 1. Origine et contexte threat intelligence

### 1.1 D'où viennent ces données ?

- **Acteur émulé :** APT29 (alias *Cozy Bear*, *The Dukes*) — groupe APT lié au SVR russe, actif depuis 2008. Connu pour des campagnes furtives contre des cibles gouvernementales et industrielles (DNC 2016, SolarWinds 2020, COVID vaccine research 2020).
- **Cadre d'émulation :** [MITRE ATT&CK Evaluations Round 2 (2020)](https://attackevals.mitre.org/APT29/) — première campagne d'évaluation organisée par MITRE Engenuity, scénario de 2 jours rejouant les TTPs documentés d'APT29.
- **Capteurs :** logs Windows natifs collectés via *Windows Event Forwarding* (WEF) sur un lab AD de 4 machines, agrégés par *Open Threat Research Forge / Mordor* sous forme de JSON Lines.
- **Sources de logs :**
  - Sysmon (`Microsoft-Windows-Sysmon/Operational`)
  - Security (`Security` — fusion à faire avec `security`, cf §3.3)
  - PowerShell (`Microsoft-Windows-PowerShell/Operational` + `Windows PowerShell`)
  - Auxiliaires : Firewall, WMI-Activity, TerminalServices, System

### 1.2 Pourquoi ce dataset est défendable en PFE

| Critère | Réponse |
|---|---|
| Reproductible publiquement ? | OK — MITRE + OTRF publient l'emulation plan + les playbooks |
| Labels disponibles ? | OK — Plan d'émulation horodaté : on connaît quand chaque TTP est joué |
| Bruit légitime présent ? | OK — Les events Sysmon des 4 machines incluent l'activité de fond Windows normale |
| Multi-host ? | OK — 4 hostnames (SCRANTON, NASHUA, NEWYORK, UTICA) |
| Multi-source de logs ? | OK — Sysmon + Security + PowerShell + WMI |
| Compatible threat hunting réel ? | OK — Tous les events ont un mapping EventID standard portable Splunk / Elastic |

Le dataset est **publié sous licence libre**, **horodaté**, **multi-source** et **multi-host**. Trois qualités rares pour un dataset de détection Windows. Sa limitation principale : **émulation contrôlée** (~68 min, pas une vraie attaque en production) — cf. §10.

---

## 2. Volumétrie brute

| | **Day 1** | **Day 2** | **Total** |
|---|---:|---:|---:|
| Fichier | `apt29_evals_day1_manual_2020-05-01225525.json` | `apt29_evals_day2_manual_2020-05-02035409.json` | — |
| Taille disque | 368 MB | 1.6 GB | 1.97 GB |
| Lignes JSON | **196 081** | **587 286** | **783 367** |
| JSON malformés | 0 | 0 | **0** (parse propre à 100 %) |
| Plage horaire UTC | `02:55:26` → `03:28:20` | `07:54:05` → `08:29:23` | — |
| **Durée réelle** | **33 min** | **35 min** | **~68 min de capture** |
| Hostnames distincts | 4 | 4 | 4 (mêmes machines) |
| EventIDs distincts | 165 | 172 | ~180 (union) |

**À retenir :** Day 1 et Day 2 ne sont **pas** des journées entières — ce sont deux sessions de ~½ heure jouées le **même jour** (2 mai 2020), à 5 heures d'intervalle. Le nom "Day 1 / Day 2" vient du plan d'émulation MITRE (deux phases distinctes du scénario APT29).

### 2.1 Pourquoi Day 2 est 3× plus volumineux ?

Day 2 (587k events) = **3.0 × Day 1** (196k events) malgré une durée quasi identique.

**Explication :** Day 1 = phase "Spray & Pray" (reconnaissance + first foothold sur SCRANTON, peu d'extensions latérales). Day 2 = phase "Low & Slow" (post-exploitation profonde, dump LSASS, lateral movement, persistence, exfil) → l'attaquant active **bien plus de processus** et de chargements DLL/Registry pour chaque action.

Distribution **par hostname** (très révélatrice) :

| Hostname | Events Day 1 | Events Day 2 | Δ | Lecture |
|---|---:|---:|---:|---|
| **UTICA** | 11 971 | **480 297** | **×40** | Cible principale Day 2 — host pivot pour le lateral movement + LSASS dump |
| SCRANTON | **131 119** | 66 419 | ÷2 | First foothold Day 1, baisse une fois compromise |
| NEWYORK | 23 935 | 29 207 | ≈ | Activité stable (probable DC) |
| NASHUA | 29 056 | 11 363 | ÷2.5 | Activité administrative en background |

➡️ **UTICA = signal très fort en Day 2.** Si on incluait `Hostname` comme feature, le modèle apprendrait trivialement "UTICA = attaque". **C'est exactement pour ça qu'on droppe `Hostname` avant le scaler** (cf. §6.2 Anti-leakage).

---

## 3. Anatomie des EventIDs (que regarde le modèle ?)

### 3.1 Top 20 des EventIDs observés (Day 1 + Day 2)

Format `EventID — Day 1 / Day 2` :

| EID | Sémantique | Day 1 | Day 2 | Statut métier |
|---:|---|---:|---:|---|
| **12** | Sysmon — Registry object created/deleted | 61 152 | **162 895** | T1547 Persistence |
| **10** | Sysmon — ProcessAccess (handle vers autre process) | 39 286 | 99 219 | T1003 Credential Dumping (LSASS) |
| **13** | Sysmon — Registry value Set | 17 542 | **101 231** | T1547 Persistence (Run/RunOnce) |
| **7** | Sysmon — Image Loaded (DLL) | 20 259 | 32 012 | T1574 DLL Hijacking |
| **800** | PowerShell — Pipeline Execution Details | 5 113 | **68 990** | T1059.001 (×13) |
| **4103** | PowerShell — Module Logging | 5 080 | 59 547 | T1059.001 |
| 4658 | Security — Handle closed | 10 973 | 11 164 | bruit FS |
| 4656 | Security — Handle requested | 5 497 | 5 640 | bruit FS |
| 4690 | Security — Handle duplicated | 5 471 | 5 558 | bruit FS |
| 4663 | Security — Object accessed | 5 337 | 5 259 | bruit FS |
| 5156 | Firewall — Allowed connection | 3 163 | 3 771 | T1071 réseau |
| 11 | Sysmon — FileCreate | 1 653 | 5 481 | T1059 drop payload |
| 3 | Sysmon — NetworkConnect | 1 230 | 2 187 | T1071 C2 |
| **4688** | Security — Process creation | **460** | (présent) | T1059 commande clé |
| 1 | Sysmon — ProcessCreate | 450 | (présent) | doublon Sysmon de 4688 |

Les EID en **gras** sont ceux que **notre modèle compte explicitement** (`cnt_<eid>`) car porteurs de signal MITRE.

### 3.2 Le top 5 du modèle : 4 sur 5 sont des EID **Sysmon**

Le quatuor `12 / 13 / 10 / 7` (Registry + ProcessAccess + Image Loaded) représente à lui seul **plus de 70 %** du volume total. C'est cohérent avec la philosophie de détection :
- **Sysmon = télémétrie profonde du système** (chaque process / DLL / registry tracé)
- **Security = audit AD léger** (logons, handles, mais peu de détails)

**Implication forte :** un environnement sans Sysmon (juste Security log Windows par défaut) **ne pourrait pas reproduire les résultats de ce modèle**. Documenté comme limite §10.

### 3.3 Piège des Channels (à corriger absolument)

```
"Security"     ← capitalisé : 28 627 (D1) + 27 207 (D2) = 55 834
"security"     ← minuscule  : 12 375 (D1) + 22 854 (D2) = 35 229
```

→ **Le même channel, deux casses différentes.** Si on filtre `Channel == 'Security'`, on **rate 38.7 % des events Security** (35k sur 91k). Le code `preprocess.py` actuel ne gère pas ce problème. **Correction obligatoire** dans le nouveau pipeline (`df['Channel'] = df['Channel'].str.casefold()` ou regex avant tout filtrage).

---

## 4. Empreinte temporelle (étiquetage & split)

### 4.1 Découpage horaire — pourquoi on peut splitter Day 1 vs Day 2

| Jour | Début UTC | Fin UTC | Durée |
|---|---|---|---|
| Day 1 | 02:55:26 | 03:28:20 | **32 min 54 s** |
| Day 2 | 07:54:05 | 08:29:23 | **35 min 18 s** |

Pas de chevauchement → **split temporel `Day 1 → train, Day 2 → test` ne fuit aucune information**. C'est la stratégie validée dans `PLAN_GLOBAL_SIEM.md` et qu'on conserve.

### 4.2 Choix de la granularité de fenêtre (décision-clé)

Quatre tailles possibles, voici ce que ça donne en **réel** :

| Granularité | Day 1 | Day 2 | Total | Verdict |
|---|---:|---:|---:|---|
| **1 minute × host** | 136 | 144 | **280** | **RETENU** (~120 train / 80 test après filtre `≥ 5 events`) |
| 5 minutes × host | 28 | 32 | 60 | trop peu (CV 5-fold = 12 samples/fold) |
| 30 secondes × host | ~260 | ~280 | ~540 | trop granulaire (bruit) |
| Session entière | 4 hosts | 4 hosts | 8 | inutile |

**Choix retenu : fenêtre de 1 minute × hostname.** Décision pragmatique d'ingénieur data :
- 280 fenêtres brutes → ~200 après filtre `len(group) ≥ 5` (les minutes ultra-creuses sont du bruit)
- Day 1 train ≈ 110-130, Day 2 test ≈ 75-90 → CV 5-fold viable (~20-25 samples/fold)
- Aligné avec le `preprocess.py` existant (on évite de regénérer 2 GB de logs pour un changement de fenêtre)
- **Trade-off assumé :** on s'écarte du PLAN_GLOBAL_SIEM (qui demandait 5 min) pour des raisons statistiques. Documenté dans `PLAN.md`.

---

## 5. Signatures d'attaque détectables (rules-based labelling)

Toutes les valeurs ci-dessous sont **les occurrences réelles** trouvées par regex/conditions dans les deux JSON :

| Règle | Indice MITRE | Day 1 | Day 2 | Total | Utilité comme label |
|---|---|---:|---:|---:|---|
| `CommandLine` contient `-enc` (PowerShell encodé) | T1059.001 | 5 | 28 | **33** | rare, fort signal |
| `CommandLine` contient `downloadstring` / `iex (` | T1059.001 | 6 | 22 | **28** | OK |
| `CommandLine` contient `mimikatz` | T1003 | 0 | 3 | **3** | trop rare seul mais distinctif |
| Sysmon EID 10 vers `lsass.exe` | T1003.001 | 326 | 592 | **918** | pivot — LSASS handle access |
| `TargetObject` matche `\Run\` ou `\RunOnce\` | T1547.001 | 2 | 4 | **6** | OK |
| `schtasks /create` dans CommandLine | T1053.005 | 0 | 0 | **0** | **règle inutile sur ce dataset** |
| EID 4625 (failed logon) | T1110 brute-force | 0 | 0 | **0** | **règle inutile** (pas de tentative bruyante) |

### 5.1 Lecture forte : `schtasks /create` et `4625` sont **inactifs**

Le `preprocess.py` actuel inclut une règle `brute_force_score >= 5` (= `cnt_4625 >= 5`) qui **n'étiquette jamais rien** sur ce dataset car il y a **0 event 4625** au total. Cette règle vient d'un copier-coller du template général — elle est inerte ici.

**Action corrective :** la garder dans le code pour la portabilité (datasets futurs incluant du brute-force) mais documenter qu'elle ne contribue pas au labelling APT29.

### 5.2 Le signal dominant pour le labelling = **LSASS access (EID 10)**

918 events Sysmon EID 10 ciblent `lsass.exe`. **Mais attention :** la plupart sont du bruit légitime (svchost.exe, lsm.exe, csrss.exe accèdent à LSASS pour des raisons système). Il faut filtrer sur **les sources non-système** pour avoir un signal propre (`SourceImage` ∉ chemins `\windows\system32\…`). Ce raffinement sera dans le `io_utils.label_window()`.

### 5.3 Densité du signal d'attaque

Sur les ~200 fenêtres-minute finales attendues, on s'attend à **~30-60 fenêtres positives** (attaque) selon les règles ci-dessus, soit **15-30 %** de positifs. **Déséquilibre modéré** (similaire à ADFA-LD 7:1) → gérable avec `class_weight='balanced'`.

---

## 6. Features comportementales projetées (futures colonnes du DataFrame)

### 6.1 Liste cible (~35 features)

| Catégorie | Features | Source |
|---|---|---|
| **Volumétrie** | `total_events`, `events_per_minute`, `distinct_eventids`, `entropy_eventids` | comptage fenêtre |
| **Comptages EID** | `cnt_1`, `cnt_3`, `cnt_7`, `cnt_8`, `cnt_10`, `cnt_11`, `cnt_12`, `cnt_13`, `cnt_22` | Sysmon |
| | `cnt_4103`, `cnt_4104`, `cnt_4624`, `cnt_4625`, `cnt_4648`, `cnt_4672`, `cnt_4688`, `cnt_4697`, `cnt_4698`, `cnt_4702`, `cnt_4768`, `cnt_4769`, `cnt_4771`, `cnt_4776` | Security/PS |
| **Scores composites** | `brute_force_score`, `lateral_move_score`, `persistence_score`, `execution_score`, `kerberos_score` | sommes pondérées |
| **Ratios** | `logon_failure_ratio`, `system32_image_ratio` | dérivés |

Total visé : **31 à 36 colonnes numériques** (selon présence effective de certains EID).

### 6.2 Anti-leakage : ce qu'on **ne garde pas**

| Feature dropée | Raison |
|---|---|
| `Hostname` | UTICA → modèle apprend "UTICA = attaque" Day 2 |
| `window` | identifiant temporel → split train/test trivialement séparable |
| `day` | label-leakage direct |
| `technique` (si capturée) | label-leakage direct |
| `SePrivilegeList` | mention spécifique dans PLAN_GLOBAL_SIEM (apparaît systématiquement après EID 4672 = priv use) |
| `LogonType=10` direct | passé par un ratio `rdp_logon_ratio` |
| `ScriptBlockText` brut | trop précis (texte d'attaque pur) → on n'utilise que des comptages/longueurs |

**Critère final :** aucune feature ne doit avoir d'importance > 25 % (sinon = shortcut).

---

## 7. Qualité des données (nettoyage à prévoir)

| Vérification | Résultat | Action |
|---|---|---|
| Lignes JSON malformées | 0 / 783 367 | aucune |
| Events sans `@timestamp` | rare (<<1 %) | drop |
| Events sans `Hostname` | absent | n/a |
| Channel = casse mixte (Security vs security) | détecté | `.casefold()` |
| EventID stocké en `int` ou `str` selon ligne | détecté | cast `str(ev.get('EventID'))` |
| Fenêtres < 5 events | ~30 % attendues | filtrer (`if len(group) < 5: continue`) |
| Doublons train↔test post-features | à mesurer Phase 4 | `df.drop_duplicates()` si > 1 % |

---

## 8. Pièges et leçons à retenir avant le code

1. **Channel `Security` / `security` doivent être fusionnés** — sinon 38 % du signal Security est ignoré.
2. **`Hostname` est interdit dans les features** — UTICA explose Day 2 (×40), c'est un shortcut.
3. **Les règles `schtasks` et `4625` du template sont inertes** ici → ne pas s'attendre à ce qu'elles labelisent.
4. **`@timestamp` peut manquer** sur quelques events de bordure → `errors='coerce'` puis `dropna`.
5. **Fenêtre 1 min est un compromis** : statistiquement viable, sémantiquement plus bruyant qu'une fenêtre 5 min. Documenté.
6. **Day 2 = 3× Day 1** → si on faisait `train_test_split` aléatoire, on biaiserait le modèle. **Split temporel Day1/Day2 obligatoire.**
7. **Capteur principal = Sysmon** : 70 %+ du volume. Sans Sysmon en production, le modèle est inopérant.
8. **Le LSASS access (EID 10 → lsass.exe)** est le signal d'attaque le plus fréquent (918 events) — il sera le pivot du labelling et probablement la feature dominante.

---

## 9. Récapitulatif décisionnel pour la Phase 1 / Phase 2

| Question | Réponse décidée |
|---|---|
| Combien de samples ? | ~200 fenêtres après filtre `len(group) ≥ 5` |
| Format de stockage intermédiaire ? | Parquet (déjà installé via venv) |
| Granularité ? | **1 minute × hostname** |
| Split ? | **Temporel** Day 1 → train / Day 2 → test |
| Features ? | ~35 colonnes : comptages EID + scores composites + ratios + entropie |
| Labels ? | Règles MITRE : PS encoded/download, Mimikatz, LSASS access EID 10 → lsass.exe, Registry Run/RunOnce |
| Modèle ? | RandomForest balanced (200, 15, 5) + StandardScaler — cf `PLAN.md` |
| Anti-leakage actif ? | Drop Hostname/window/day/technique + dedup train↔test post-features |
| Cible métrique ? | F1 binaire ≥ 0.78, Recall ≥ 0.80, AUC ≥ 0.85, Gap CV-test < 0.10 |

---

## 10. Limites assumées du dataset (à dire au jury)

1. **Émulation, pas attaque réelle.** Les TTPs sont rejouées de façon scriptée → moins de variabilité comportementale qu'un vrai APT29 in-the-wild.
2. **Durée courte** (~68 min total) → peu de stationnarité, peu de "normal sleeping" entre actions.
3. **Sysmon requis** : 70 %+ du signal vient de Sysmon. Sans Sysmon, le modèle n'est pas portable.
4. **Pas de brute-force** dans ce dataset → la règle `cnt_4625` est inactive (documenté).
5. **Seulement 4 hosts** → généralisation à un parc d'entreprise (1000+ machines) non démontrée.
6. **Pas de chiffrement / exfil dans le scope** au sens réseau → on ne capture pas la partie *Command & Control* depuis Internet.
7. **Émulation 2020** → des techniques 2024+ (ex. EDR-evasion via Bring-Your-Own-Driver) ne sont pas représentées.

**À mentionner spontanément en soutenance** — un modèle 100 % honnête commence par lister ses limites.

---

## 11. Artefacts produits par cette Phase 0

- `results/eda/raw_stats.json` — chiffres détaillés (script `scripts_aux/extract_raw_stats.py`)
- `EXPLICATION_DATA.md` — ce fichier
- `PLAN.md` — stratégie ML (à lire ensuite)
- `AVANCEMENT.md` — journal de bord
- `README.md` — carte du projet

---

*Document Phase 0 — siem_windows. Toutes les valeurs chiffrées proviennent d'une extraction réelle sur les 783 367 events bruts via Python en streaming. Aucune valeur n'a été inventée.*
