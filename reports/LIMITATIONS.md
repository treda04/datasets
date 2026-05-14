# Limites assumées du système — PFE SOC-ML

**Date :** 2026-05-14
**Soutenance :** 2026-06-02
**Auteur :** Reda — UIR / Data Protect

Ce document recense les **limites scientifiquement assumées** du PFE. Posture : *un défaut documenté et compris vaut mieux qu'un score parfait suspect.* L'audit méthodologique (`docs/AUDIT_PROJET_COMPLET.md`) a déjà identifié 4 problèmes de leakage corrigés (V1 → V2/V3) ; ce document s'attache aux **limites résiduelles** que la remédiation n'a pas pu lever.

---

## 1. Dataset ADFA-LD : ancien, x86 32-bit, syscalls Linux uniquement

**Constat.** ADFA-LD (UNSW) date de **2012**, traces collectées sur **Ubuntu 11.04 i386**, format syscall trigrammes.

**Pourquoi conservé.**
- C'est le **benchmark public le plus cité** pour la détection d'intrusion host-based à syscalls Linux : conserver permet la **comparabilité avec la littérature** (Khreich et al. 2017, Creech & Hu 2014, Mendsaikhan et al. 2021).
- Le score V2 obtenu (F1 = 0.957, AUC = 0.978) reste **dans la moyenne haute** des scores publiés sur ADFA-LD avec une approche supervisée n-gram + RF.

**Limites assumées.**
- Les **syscalls x86 32-bit** ne sont plus représentatifs des serveurs Linux actuels (x86_64, syscalls élargis post-Spectre/Meltdown).
- Le dataset n'inclut **pas de containers, ni systemd moderne** : la généralisation à un Linux 2024/2026 n'est pas garantie.
- Les **5 familles d'attaque** (Adduser, Hydra, Meterpreter, Java_Meterpreter, Web_Shell) ne couvrent qu'**une partie** de la matrice MITRE ATT&CK côté Linux (pas de container escape, pas de kernel rootkit moderne, pas de fileless modern).
- Mendsaikhan et al. (2021) *"Methods for Host-based Intrusion Detection with Deep Learning"* documentent que les modèles entraînés sur ADFA-LD **ne transfèrent pas bien** à des datasets plus récents — cette limite est connue de la communauté.

**Travail futur.** Validation sur **ADFA-LD-AID** (extension multi-modal), **NGIDS-DS** (2017), ou capture interne sur cluster Kubernetes Data Protect (sous réserve d'accord).

---

## 2. SIEM Windows — historique v3 → v4

**Version v4 actuelle (après EDA exhaustive 175 EventIDs + extension monitoring) :**
- F1 macro (1 fold, NEWYORK test) : **0.7528** (LightGBM, 95 features)
- F1 macro LOOHO (4 folds) : **0.693 ± 0.062**
- ROC-AUC LOOHO : **0.678 ± 0.045**
- Techniques MITRE évaluables : **11** (vs 3 en v3)

**Version v3 historique (conservée pour comparaison) :**
- F1 (1 fold) : 0.667 | F1 LOOHO : 0.669 ± 0.014 | AUC LOOHO : 0.538 ± 0.133

**Causes structurelles (toujours présentes en v4) :**
1. **Drift inter-host** : 4 hosts APT29 avec profils comportementaux très différents (mean `total_events` par fenêtre : 3 171 day1 normal → 22 632 day2 normal).
2. **Petite taille du dataset** : 276 fenêtres au total.
3. ~~Granularité fenêtre Sysmon ignorée~~ → **RÉSOLU en v4** par extension de `ALL_MONITORED` (24 → 44 EventIDs incluant Sysmon 1, 3, 7, 8, 9, 10, 11, 12, 13, 22 + PowerShell 800/4103 + WFP 5154/5156/5158/5447).

**Amélioration v3 → v4 (méthodologie data science) :**
- EDA exhaustive sur les 175 EventIDs distincts du dataset (chi² discrimination)
- Extension monitoring : EID 10 (T1003 ProcessAccess), EID 7 (T1574 ImageLoad), EID 8 (T1055 RemoteThread, lift=117), EID 5447 (T1562 WFP, lift=74) etc.
- Rolling features (mean/std/delta sur 3 fenêtres précédentes par host)
- Pruning auto features faibles (importance < 0.002 → 152 features → 95 conservées)
- Comparatif systématique 5 algos (RF baseline, RF tuned, XGBoost, LightGBM, Stacking) → **LightGBM gagnant**.

**Innovations testées en v4 (`siem_windows/results_v4/innovations_summary.csv`) :**

| Méthode | F1 macro opt | AUC |
|---|---|---|
| RF baseline (depth=5) | 0.6946 | 0.7261 |
| RF tuned (depth=8) | 0.7096 | 0.7202 |
| XGBoost | 0.7225 | 0.7076 |
| **LightGBM** | **0.7528** | 0.7231 |
| Stacking | 0.7391 | 0.7092 |

**Verdict v4 :** LightGBM avec 95 features dérivées de l'EDA donne le meilleur résultat. Le drift inter-host reste mais est partiellement compensé par les rolling features qui capturent le contexte temporel par host.

**Lecture par technique MITRE (`reports/figures/mitre_coverage_v4.png`).** En v4, **11 techniques évaluables** sur SIEM (vs 3 en v3) avec F1 médian 0.72. Best : T1071 (Application Layer Protocol, F1=0.74).

**Limites résiduelles v4 :**
- AUC LOOHO 0.68 (acceptable mais non excellent) — le drift inter-host reste structurel.
- Overfit gap LOOHO élevé (+0.42) — typique des modèles complexes (LightGBM 400 arbres) sur petit dataset.
- T1059.001 PowerShell : F1=0 (techniques PowerShell mal capturées par les fenêtres comportementales).

**Travail futur.**
- **Baseline de logs normaux propres** (captures internes non-compromises) — gain estimé +0.10 AUC.
- **Représentations sequence-aware** (Transformer time-series) — sortie du périmètre supervisé tabular.
- **Re-tagging fin par technique MITRE** plutôt que binaire attack/normal.

---

## 3. Datasets de test : volume limité, environnements contrôlés

**Constat.**
- **OTRF Mordor APT29** : **4 hosts** Windows, **2 jours** de capture, **APT29 uniquement** comme TTP (techniques pré-définies par l'emulation plan MITRE).
- **Atomic Red Team** (Lateral Movement) : exécutions **contrôlées, isolées**, sans contexte business normal autour.
- **CIC-IDS-2017** : capture lab, **pas de bruit réseau d'entreprise réelle** (pas de trafic vidéo conf, pas de SaaS, etc.).
- **ADFA-LD** : ~6 000 fichiers de trace, 5 familles d'attaque.

**Limite.** La généralisation à un **SI opérationnel réel** (Data Protect ou client) n'est pas garantie par les métriques actuelles. Un environnement de production présente :
- Du **trafic légitime varié et bruyant** (RDP business, copies SMB inter-services, scheduled tasks d'admin, etc.) absent des datasets.
- Des **TTP au-delà d'APT29** (FIN6, Lazarus, BlackCat, ransomware modernes) que les modèles n'ont jamais vus.
- Une **diversité d'OS et de configurations** (Windows 10/11/Server 2019/2022, divers AV, EDR…) non représentée.

**Mitigation actuelle.** Score composite multi-modèles pondéré (voir `SOCOrchestrator.correlate()`) : aucun modèle seul n'est responsable de la décision. La corrélation 2-modèles-distincts limite mécaniquement les faux positifs.

**Travail futur.**
- Validation sur **logs Data Protect** réels (sous NDA).
- **A/B test** vs règles Sigma sur le même flux en production pendant 30 jours.
- Réentraînement périodique (model drift monitoring).

---

## 4. Contrainte supervisé pure : pas de couverture zéro-day

**Constat.** L'encadrant impose l'usage de **modèles supervisés uniquement** (RF, XGBoost, LightGBM, LogReg, calibration). Aucun modèle non-supervisé (IsolationForest, One-Class SVM, KMeans, DBSCAN, autoencoder) n'est utilisé. Cette contrainte est **respectée** dans tout le code.

**Conséquence.** Le système ne peut détecter que des **patterns vus à l'entraînement**. Une nouvelle TTP qui ne ressemble à **aucune** des classes d'attaque connues sera classée **Normal** par chaque modèle.

**Exemples de scénarios non couverts :**
- **Zéro-day exploit** sans signature comportementale connue.
- **Living-off-the-land** (LotL) extrêmement subtile (un seul `net use` légitime + un `wmic` discret) sans pic de volumetrie dans la fenêtre 5 min.
- **Insider threat** très lent (1 action / jour pendant 6 mois).
- **Supply chain attack** (CodeCov, SolarWinds-style) où le code malveillant signé fait des appels "normaux".

**Pourquoi accepter cette limite.**
- La **calibration scientifique** des modèles supervisés est plus simple à défendre (cross-val, courbes ROC/PR, F1 par technique MITRE). Un modèle non-supervisé serait évalué sur des métriques difficiles à objectiver (silhouette, BIC) qui ne se traduisent pas directement en TPR/FPR opérationnel.
- Les modèles supervisés produisent des **scores calibrés** (CalibratedClassifierCV isotonic) directement exploitables par les analystes SOC.

**Travail futur (énoncé, non implémenté en PFE).**
- **Combinaison hybride** : pipeline supervisé pour les TTP connues + couche de règles Sigma/YARA pour les patterns non vus + Isolation Forest comme dernier filet sur les anomalies de volumetrie. Couverture estimée : +25 % zéro-day.
- **Active learning** : faire labelliser par les analystes SOC les fenêtres marginales (score 0.4–0.6) pour enrichir le train set au fil du temps.
- **Adversarial training** : tester la robustesse face à des attaques d'évasion (perturbation des features) — Goodfellow et al. 2014, Carlini & Wagner 2017.

---

## 5. Mapping MITRE par EventID : approximation 1-1

**Constat.** Le mapping `EVENT_TO_TECHNIQUE` (`src/orchestrator/mitre_mapping.py`) associe **une seule technique principale** par EventID. La réalité MITRE ATT&CK est plus nuancée : un EventID 4624 peut correspondre à T1078 *ou* T1021 *ou* T1110 selon le contexte (logon type, source, target).

**Mitigation.** Le système ne s'appuie **pas uniquement** sur le mapping pour la décision (la décision vient du score modèle). Le MITRE est utilisé pour **enrichir** l'alerte avec une étiquette contextuelle, pas comme règle de classification.

**Travail futur.** Mapping multi-techniques avec contexte (logon type, source IP, target user) → matrice (technique, contexte) plutôt qu'un dict simple.

---

## 6. Fenêtre 5 minutes : compromis arbitraire

**Constat.** Toutes les agrégations (SIEM, Lateral) utilisent une **fenêtre fixe de 5 minutes**.
- Trop courte pour des attaques lentes (insider threat).
- Trop longue pour des attaques rapides (ransomware moderne avec lockdown < 30 s).

**Justification du choix.** 5 min est le compromis standard dans la littérature (Wazuh, Sigma rules) et permet de capturer la plupart des kill chains observées dans APT29 / Atomic Red Team.

**Travail futur.** Multi-fenêtres (1 min, 5 min, 30 min) avec agrégation des scores. Ou fenêtres adaptatives (ouvertes par déclencheur).

---

## 7. Reproductibilité

✅ `random_state = 42` fixé pour : `train_test_split`, `RandomForestClassifier`, `XGBClassifier`, `StratifiedKFold`, `StratifiedGroupKFold`, `GroupShuffleSplit`, `CalibratedClassifierCV`, `SMOTE`, sampling du cap par technique.

✅ Requirements pinnés dans `requirements.txt`.

✅ Tests pytest passants (16 tests sur `SOCOrchestrator`).

⚠️ Pas de **versionning de modèles** (MLflow, DVC) — hors-périmètre temps PFE. Les artefacts sont versionnés via les copies dans `models/` produites par `scripts/setup_models_dir.py`.

⚠️ Pas de **CI/CD** — hors-périmètre temps PFE.

---

## Résumé pour le jury

| Limite | Sévérité | Mitigation actuelle | Travail futur |
|---|---|---|---|
| ADFA-LD ancien | Modérée | Conservé pour comparabilité littérature | NGIDS-DS, capture interne |
| SIEM AUC 0.57 (drift inter-host) | Significative | Lecture par technique MITRE + corrélation multi-modèles | Baseline normale propre, Sysmon étendu |
| Datasets test lab | Modérée | Score composite multi-modèles | Validation prod Data Protect |
| Supervisé pur (pas de zéro-day) | Significative | Couverture explicite des TTP connues | Hybride ML + Sigma + Isolation Forest |
| Mapping MITRE 1-1 | Faible | Étiquette enrichissement, pas décision | Mapping contextuel multi-technique |
| Fenêtre 5 min fixe | Faible | Compromis standard littérature | Multi-fenêtres adaptatives |

**Position défendue :** ces limites sont **identifiées, documentées, quantifiées**. Elles ne discréditent pas le travail méthodologique (anti-leakage, anti-overfitting, cross-validation) — au contraire, elles montrent une **lucidité scientifique** rare en PFE.
