# Plan de Déploiement ELK + Démonstration — PFE SOC-ML

**Document pour reprise du travail (utilisable par Gemini, Claude ou Copilot).**

> Ce plan est **auto-contenu** : il décrit l'état actuel du projet, l'architecture cible, les étapes d'implémentation détaillées, et le scénario d'attaques pour la démo soutenance.

---

## 1. ÉTAT ACTUEL DU PROJET

### 1.1 Contexte

PFE Cybersécurité — Soutenance le 2 juin 2026. L'étudiant a développé un **système SOC ML supervisé** combinant 3 modèles ML couvrant 3 surfaces d'attaque, avec orchestrateur Python + stack ELK (Elasticsearch + Logstash + Kibana) + Kafka.

### 1.2 Les 3 modèles ML livrés

| Modèle | Surface | Algorithme | F1 test | AUC | Dataset entraînement |
|---|---|---|---:|---:|---|
| **cicids** | Réseau / NetFlow | XGBoost (7 classes) | 0.967 macro | 0.9998 | CIC-IDS-2017 (685 MB) |
| **adfa** | Host Linux / syscalls | RandomForest + Calibrated isotonic | 0.864 | 0.985 | ADFA-LD (5 951 fichiers) |
| **siem** | Host Windows / events | RandomForest balanced + tuning seuil F2 | 0.759 | 0.950 | OTRF Mordor APT29 (783k events) |

**Note importante :** une 4ème surface (lateral_movement / Atomic Red Team) a été explorée puis écartée pour cause de dataset insuffisant. Décision documentée dans `RAPPORT_ENCADRANT_V2.md`.

### 1.3 Structure du projet

```
~/datasets/
├── adfa_ld/                  # Dataset 2 + modèle entraîné (saved_models/v2_final/)
├── cicids2017/               # Dataset 1 + modèle entraîné (saved_models/v1_final/)
├── siem_windows/             # Dataset 3 + modèle entraîné (saved_models/v1_final/)
├── models/                   # ⭐ Modèles centralisés pour orchestrateur
│   ├── cicids/{model,manifest,threshold}.{pkl,json}
│   ├── adfa/{model,vectorizer,manifest,threshold}.{pkl,json}
│   └── siem/{model,scaler,feature_names,manifest,threshold}.{pkl,json}
├── src/orchestrator/
│   ├── soc_orchestrator.py    # Classe SOCOrchestrator (routing + correlation)
│   └── mitre_mapping.py       # EventID -> technique MITRE
├── live_detection/
│   ├── soc_router.py          # ⭐ Service principal Kafka -> ML -> Kafka
│   └── README_QUICKSTART.md
├── scripts/
│   ├── setup_models_dir.py    # Prépare models/ depuis les 3 datasets
│   └── simulate_attack.py     # Simulateur kill chain pour test
├── tests/test_orchestrator.py # 15 tests pytest passants
├── integration/
│   ├── logstash/pipeline/main.conf
│   ├── elasticsearch/mapping.json
│   └── kibana/dashboard.ndjson
├── docker-compose.yml         # Stack ELK + Kafka (alternative)
└── requirements.txt
```

### 1.4 Environnement matériel

- **Ubuntu VM** : ELK (Elasticsearch + Kibana + Logstash) + Kafka installés et configurés. **Le code Python tournera sur cette même VM.**
- **Windows 10** : poste cible avec Sysmon installé + Winlogbeat configuré pour pousser vers Kafka sur Ubuntu.
- **Windows Server 2022** : DC avec Sysmon installé + Winlogbeat.
- **Kali Linux** : poste attaquant pour scénarios réseau.

### 1.5 Architecture cible

```
[W10 + WS2022 + Sysmon + Winlogbeat]
              |
              | TCP 9092
              v
+======================== Ubuntu VM ===========================+
|  Kafka (raw_events topic)                                    |
|       |                                                      |
|       +--> soc_router.py (3 modèles ML)                      |
|              |                                               |
|              +--> Kafka (alerts, critical_alerts)            |
|                       |                                      |
|                       +--> Logstash --> Elasticsearch        |
|                                              |               |
|                                              +--> Kibana SOC |
+==============================================================+

[Kali Linux]
    |
    | (attaques réseau)
    v
[NetFlow capture] --> Kafka --> soc_router (cicids model)
```

### 1.6 Démarche méthodologique attendue

**Ne pas implémenter directement sur ELK.** Suivre **3 phases progressives** :
- Phase 1 : test isolé ML (sans Kafka, sans ELK)
- Phase 2 : intégration ELK avec events synthétiques
- Phase 3 : attaques réelles + démo soutenance

Chaque phase doit être validée avant de passer à la suivante.

---

## 2. PHASE 1 — TEST ISOLÉ ML (1h)

**Objectif :** prouver que les 3 modèles ML chargent et prédisent correctement sur Ubuntu, sans dépendance externe.

### 2.1 Préparer l'environnement Python

```bash
cd ~/datasets

# Installation Python 3.11 si absent
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3-pip

# Création venv
python3.11 -m venv .venv
source .venv/bin/activate

# Dépendances
pip install --upgrade pip
pip install -r requirements.txt
pip install kafka-python
```

**Validation :**
```bash
python -c "import joblib, numpy, pandas, sklearn, xgboost, lightgbm, kafka; print('OK')"
# Attendu : OK
```

### 2.2 Préparer le dossier `models/`

```bash
python scripts/setup_models_dir.py
```

**Sortie attendue :**
```
=== Setup models/ : ~/datasets/models ===
  [+] cicids   OK -> models/cicids (3 fichiers)
        - model.pkl
        - manifest.json
        - threshold.json (=0.500)
  [+] adfa     OK -> models/adfa (5 fichiers)
        - model.pkl
        - vectorizer.pkl
        - threshold.json (=0.400)
  [+] siem     OK -> models/siem (6 fichiers)
        - model.pkl
        - scaler.pkl
        - feature_names.json
        - threshold.json (=0.300)

Résultat : 3/3 modeles installes.
```

### 2.3 Test orchestrateur

```bash
python -c "
import sys; sys.path.insert(0, '.')
from src.orchestrator.soc_orchestrator import SOCOrchestrator
orch = SOCOrchestrator(models_dir='models')
print('Modeles charges :', sorted(orch.bundles.keys()))
print('Routing windows_event :', orch.route({'source': 'windows_event'}))
print('Routing netflow :', orch.route({'source': 'netflow'}))
print('Routing linux_syscall :', orch.route({'source': 'linux_syscall'}))
"
```

**Attendu :**
```
Modeles charges : ['adfa', 'cicids', 'siem']
Routing windows_event : siem
Routing netflow : cicids
Routing linux_syscall : adfa
```

### 2.4 Tests pytest

```bash
python -m pytest tests/test_orchestrator.py -v
# Attendu : 15 passed
```

### 2.5 Test prédiction synthétique

```bash
python -c "
import sys, time; sys.path.insert(0, '.')
from src.orchestrator.soc_orchestrator import SOCOrchestrator
from live_detection.soc_router import compute_window_features

orch = SOCOrchestrator(models_dir='models')

# Simuler une fenêtre suspecte (LSASS handle + PowerShell encoded)
events = [{'EventID': '10', 'TargetImage': 'lsass.exe', 'SourceImage': 'powershell.exe'}] * 8
events += [{'EventID': '4688', 'CommandLine': 'powershell -enc xxxx'}] * 4
events += [{'EventID': '12'}] * 3
feat = compute_window_features(events)

event = {'event_id': 'TEST', 'source': 'windows_event', 'host': 'DC-WS2022',
         'timestamp': time.time(), 'features': feat}
pred = orch.predict(event)
print(pred)
"
```

**Attendu :** un dict avec `model='siem'`, `score`, `is_attack` et `mitre_technique`.

### ✅ Critère de sortie Phase 1
- 3 modèles chargés sans erreur
- 15/15 tests pytest passent
- Prédiction synthétique retourne un dict valide

---

## 3. PHASE 2 — INTÉGRATION ELK AVEC EVENTS SYNTHÉTIQUES (2h)

**Objectif :** prouver que la chaîne Kafka → soc_router → Logstash → Elasticsearch → Kibana fonctionne, en utilisant des events synthétiques (pas encore d'attaques réelles).

### 3.1 Vérifier Kafka et créer les topics

```bash
# Vérifier que Kafka tourne
sudo systemctl status kafka       # si install native
# OU
docker ps | grep kafka            # si docker-compose

# Lister les topics existants
kafka-topics --bootstrap-server localhost:9092 --list

# Créer les 3 topics si absents
kafka-topics --create --topic raw_events --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
kafka-topics --create --topic alerts --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
kafka-topics --create --topic critical_alerts --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
```

### 3.2 Lancer le SOC Router

**Dans un terminal dédié (utiliser `tmux` ou `screen` pour le laisser tourner) :**

```bash
cd ~/datasets
source .venv/bin/activate
python live_detection/soc_router.py
```

**Sortie attendue :**
```
=== SOC Router Service - demarrage ===
Kafka broker        : localhost:9092
Kafka topic IN      : raw_events
Modeles charges     : ['adfa', 'cicids', 'siem']
Service pret. En attente d'events sur raw_events...
```

### 3.3 Configurer Logstash pour `alerts` → Elasticsearch

Créer le fichier `/etc/logstash/conf.d/soc-alerts.conf` :

```
input {
  kafka {
    bootstrap_servers => "localhost:9092"
    topics => ["alerts", "critical_alerts"]
    codec => json
    group_id => "logstash-soc-alerts"
    decorate_events => true
  }
}

filter {
  if [@metadata][kafka][topic] == "critical_alerts" {
    mutate { add_field => { "alert_type" => "critical" } }
  } else {
    mutate { add_field => { "alert_type" => "individual" } }
  }
  if [timestamp] {
    date { match => ["timestamp", "UNIX"] target => "@timestamp" }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "soc-alerts-%{+YYYY.MM.dd}"
  }
}
```

Redémarrer Logstash :
```bash
sudo systemctl restart logstash
sudo tail -f /var/log/logstash/logstash-plain.log
# Attendre "Pipeline started successfully"
```

### 3.4 Préparer Kibana

1. Ouvrir `http://<IP_UBUNTU>:5601`
2. **Stack Management → Index Patterns → Create index pattern**
   - Pattern : `soc-alerts-*`
   - Time field : `@timestamp`
3. **Discover** → vérifier que l'index est trouvé (vide pour le moment)

### 3.5 Test end-to-end avec simulateur

Dans un **3ème terminal** :

```bash
cd ~/datasets
source .venv/bin/activate
python scripts/simulate_attack.py
```

**Le simulateur pousse 4 étapes d'attaque synthétiques pendant ~60s.**

**Dans le terminal du SOC Router** : on doit voir des lignes comme :
```
ALERTE host=DC-WS2022 model=siem score=0.85 mitre=T1059
ALERTE host=DC-WS2022 model=siem score=0.92 mitre=T1003
```

**Dans Kibana Discover** : refresh → les documents alertes doivent apparaître avec :
- `model: "siem"`
- `host: "DC-WS2022"`
- `mitre_technique: "T1059" / "T1003" / "T1547"`
- `is_attack: true`

### ✅ Critère de sortie Phase 2
- Kafka topics opérationnels
- soc_router log montre "ALERTE..." pendant le simulateur
- Au moins 3 documents `is_attack=true` dans Kibana

---

## 4. PHASE 3 — ATTAQUES RÉELLES + DÉMO SOUTENANCE (1-2h)

**Objectif :** prouver que le système détecte de vraies attaques lancées sur les machines Windows / Kali.

### 4.1 Prérequis Windows

Sur **W10 et WS2022**, vérifier :
1. **Sysmon installé** avec config SwiftOnSecurity :
   ```cmd
   sysmon64.exe -i sysmonconfig.xml -accepteula
   sysmon64.exe -m   # Vérifier qu'il tourne
   ```

2. **PowerShell Module Logging + Script Block Logging activés** (via GPO `gpedit.msc`) :
   - Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell
   - "Turn on Module Logging" → Enabled (module names = `*`)
   - "Turn on PowerShell Script Block Logging" → Enabled

3. **Winlogbeat installé et configuré** pour pousser vers Kafka sur Ubuntu :
   ```yaml
   # winlogbeat.yml
   winlogbeat.event_logs:
     - name: Microsoft-Windows-Sysmon/Operational
     - name: Security
     - name: Microsoft-Windows-PowerShell/Operational
     - name: Windows PowerShell

   output.kafka:
     hosts: ["<IP_UBUNTU>:9092"]
     topic: "raw_events"
     codec.json:
       pretty: false
   ```

   Démarrer Winlogbeat :
   ```cmd
   .\winlogbeat.exe -e
   ```

### 4.2 Vérifier que les events arrivent dans Kafka

Sur Ubuntu :
```bash
kafka-console-consumer --topic raw_events --bootstrap-server localhost:9092 --max-messages 5
# Doit afficher 5 events JSON depuis Windows
```

Si rien n'arrive : vérifier
- Firewall Windows (port sortant 9092 ouvert)
- Firewall Ubuntu : `sudo ufw allow 9092`
- `Winlogbeat` log : `Get-Content "C:\ProgramData\winlogbeat\Logs\winlogbeat-*.ndjson" -Tail 20`

### 4.3 Atomic Red Team — installation et préparation

Sur **W10** (machine attaquante, ou directement WS2022) :

```powershell
# Installer Atomic Red Team via PowerShell (en tant qu'admin)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

**Pour voir les techniques disponibles :**
```powershell
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
```

### 4.4 SCÉNARIO DE DÉMO — Kill Chain APT (12 minutes filmées)

**Setup :** soc_router.py tourne, Kibana ouvert sur Discover, Winlogbeat actif.

#### Étape 1 — Baseline (1 min)
Sur W10, laisser quelques actions normales se faire :
```powershell
Get-Process
Get-Service
notepad.exe
```
→ Aucune alerte dans Kibana. **Démontre que le modèle ne génère pas de FP.**

#### Étape 2 — Initial Access : PowerShell encoded (T1059.001) (1 min)
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
```
**Attendu Kibana** : 1 alerte `model=siem, mitre_technique=T1059`

#### Étape 3 — Credential Access : LSASS dump (T1003.001) (2 min)
```powershell
# Atomic technique T1003.001 - Test 4 (comsvcs.dll)
Invoke-AtomicTest T1003.001 -TestNumbers 4 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 4
```
**Attendu Kibana** : 1 alerte `model=siem, mitre_technique=T1003`
**Note** : si Defender bloque, désactiver le temps de la démo.

#### Étape 4 — Persistence : Registry Run (T1547.001) (1 min)
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```
**Attendu Kibana** : 1 alerte `model=siem, mitre_technique=T1547`

#### Étape 5 — Lateral Movement : PSRemoting depuis W10 vers WS2022 (2 min)
```powershell
# Sur W10, en tant qu'admin du domaine
Invoke-AtomicTest T1021.006 -TestNumbers 1
# OU manuellement :
Enter-PSSession -ComputerName WS2022 -Credential admin
```
**Attendu Kibana** :
- 1 alerte `model=siem` (4624 type 3 + 4648 events)
- **1 corrélation CRITICAL** (>=2 alertes même host < 5 min) car siem a déjà alerté à l'étape 2-3-4 sur le même host

#### Étape 6 — Scan réseau depuis Kali (T1046) (1 min)
**Sur Kali Linux :**
```bash
nmap -sS -p 1-1000 <IP_WIN10>
nmap -sV --script vuln <IP_WIN10>
```
**Attendu Kibana** : si NetFlow capturé, alerte `model=cicids` (Port Scanning)
**Note** : nécessite un capteur NetFlow (softflowd ou nfdump) sur Ubuntu.

#### Étape 7 — Brute force depuis Kali (T1110) (1 min)
```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://<IP_WIN10>
# OU
crackmapexec smb <IP_WIN10> -u admin -p wordlist.txt
```
**Attendu** : si capture, alerte `model=cicids` (Brute Force). Sinon, Win10 va générer EID 4625 → `model=siem`.

### 4.5 Capture des résultats pour la vidéo

À la fin du scénario, tu dois avoir dans Kibana :
- ✅ Au moins 4 alertes `is_attack=true` du modèle `siem`
- ✅ Au moins 1 corrélation `alert_type=critical`
- ✅ Mapping MITRE visible (T1003, T1059, T1547)
- ✅ Timeline montrant les alertes dans l'ordre chronologique

**Screenshots à prendre :**
1. Vue Kibana Discover avec toutes les alertes filtrées par `is_attack=true`
2. Vue détaillée d'une corrélation CRITICAL avec ses techniques MITRE
3. Timeline (Visualize → Line Chart) des alertes par minute

---

## 5. LISTE COMPLÈTE DES ATTAQUES POUR LA DÉMO

### 5.1 Attaques Atomic Red Team (Windows)

| Étape | Technique MITRE | Atomic Test | Modèle qui détecte | Commande |
|---|---|---|---|---|
| 1 | T1059.001 PowerShell | T1059.001 #1 | siem | `Invoke-AtomicTest T1059.001 -TestNumbers 1` |
| 2 | T1003.001 LSASS Memory | T1003.001 #4 (comsvcs.dll) | siem | `Invoke-AtomicTest T1003.001 -TestNumbers 4` |
| 3 | T1547.001 Registry Run | T1547.001 #1 | siem | `Invoke-AtomicTest T1547.001 -TestNumbers 1` |
| 4 | T1053.005 Scheduled Task | T1053.005 #1 | siem | `Invoke-AtomicTest T1053.005 -TestNumbers 1` |
| 5 | T1021.006 PSRemoting | T1021.006 #1 | siem | `Invoke-AtomicTest T1021.006 -TestNumbers 1` |
| 6 | T1078 Valid Accounts | manuel | siem (via 4624 type 3) | `runas /user:DOMAIN\admin cmd` |
| 7 | T1136.001 Create Account | T1136.001 #1 | siem | `Invoke-AtomicTest T1136.001 -TestNumbers 1` |
| 8 | T1218.011 Rundll32 | T1218.011 #1 | siem | `Invoke-AtomicTest T1218.011 -TestNumbers 1` |

### 5.2 Attaques depuis Kali Linux (Réseau)

| Étape | Technique MITRE | Outil | Modèle qui détecte | Commande |
|---|---|---|---|---|
| 1 | T1046 Network Service Scan | nmap | cicids | `nmap -sS -p 1-65535 <IP>` |
| 2 | T1110 Brute Force RDP | hydra | cicids OR siem (4625) | `hydra -l Administrator -P passwords.txt rdp://<IP>` |
| 3 | T1110 Brute Force SSH | hydra | cicids OR adfa | `hydra -l root -P passwords.txt ssh://<IP>` |
| 4 | T1499 DoS | hping3 | cicids | `hping3 --flood -p 80 <IP>` |
| 5 | T1190 Web App Exploit | sqlmap / wpscan | cicids | `sqlmap -u "http://<IP>/page?id=1"` |
| 6 | T1059.004 Reverse Shell | msfvenom + nc | siem (via Sysmon) | `nc -lvp 4444` + payload |

### 5.3 Scénario minimal (5 min, le plus filmable)

Si tu n'as pas le temps de tout faire, voici le scénario minimal qui produit une démo convaincante :

```powershell
# Sur W10 (1 minute)
Invoke-AtomicTest T1059.001 -TestNumbers 1            # PowerShell encoded
Start-Sleep 30
Invoke-AtomicTest T1003.001 -TestNumbers 4            # LSASS dump
Start-Sleep 30
Invoke-AtomicTest T1547.001 -TestNumbers 1            # Registry Run
Start-Sleep 30
Invoke-AtomicTest T1021.006 -TestNumbers 1            # PSRemoting
```

→ 4 alertes du modèle `siem` + 1 corrélation CRITICAL en 2-3 minutes.

---

## 6. CHECKLIST FINALE DE VALIDATION

Avant la soutenance, vérifier que **tous** ces points sont OK :

### Phase 1 (Test ML isolé)
- [ ] `python scripts/setup_models_dir.py` → 3/3 modèles
- [ ] `SOCOrchestrator(models_dir='models')` charge ['adfa', 'cicids', 'siem']
- [ ] `pytest tests/test_orchestrator.py` → 15/15 passent
- [ ] Prédiction synthétique retourne un dict valide

### Phase 2 (Intégration ELK)
- [ ] Kafka topics `raw_events`, `alerts`, `critical_alerts` existent
- [ ] `soc_router.py` démarre et affiche "Service pret"
- [ ] Logstash log "Pipeline started successfully"
- [ ] Kibana index pattern `soc-alerts-*` créé
- [ ] `simulate_attack.py` génère des alertes visibles dans Kibana

### Phase 3 (Démo réelle)
- [ ] Sysmon installé sur W10 et WS2022
- [ ] PowerShell logging GPO activé
- [ ] Winlogbeat installé et pousse vers Kafka Ubuntu
- [ ] `kafka-console-consumer` montre des events réels arriver
- [ ] Atomic Red Team installé et fonctionnel
- [ ] Au moins 1 attaque test (T1059.001) détectée dans Kibana
- [ ] Au moins 1 corrélation CRITICAL générée

### Avant la soutenance
- [ ] Vidéo de démo enregistrée (5-10 min)
- [ ] Screenshots Kibana sauvegardés (timeline + détail alertes + MITRE)
- [ ] Slides incluant les chiffres : F1, AUC, leakage des 3 modèles
- [ ] Discours préparé pour question "pourquoi pas 4 modèles ?" (réponse : lateral écarté pour dataset insuffisant — preuve de rigueur)

---

## 7. TROUBLESHOOTING

| Problème | Cause probable | Solution |
|---|---|---|
| `setup_models_dir.py` dit "AUCUNE SOURCE TROUVEE" | Modèle `.pkl` absent dans `saved_models/` | Vérifier `find . -name "model.pkl"` |
| `SOCOrchestrator` lève FileNotFoundError | `models/` n'existe pas | Lancer `setup_models_dir.py` |
| `soc_router.py` ne démarre pas, erreur Kafka | Kafka pas démarré ou port bloqué | `sudo systemctl status kafka`, `netstat -tlnp \| grep 9092` |
| Aucun event dans Kafka depuis Windows | Winlogbeat ne pousse pas | Vérifier firewall + winlogbeat logs + `kafka-console-consumer` |
| Aucune alerte dans Kibana | Logstash pas configuré ou index pattern manquant | `tail -f /var/log/logstash/logstash-plain.log` |
| Atomic Red Team ne s'installe pas | Defender bloque | Désactiver Defender temporairement |
| Mimikatz/LSASS dump bloqué | Defender en temps réel | Désactiver protection temps réel sur W10 |
| `nmap` depuis Kali ne génère pas d'alerte | Pas de capteur NetFlow sur Ubuntu | Soit installer softflowd, soit utiliser Winlogbeat EID 5156 |

---

## 8. RÉFÉRENCES UTILES

- **Atomic Red Team** : https://github.com/redcanaryco/atomic-red-team
- **Invoke-AtomicRedTeam** : https://github.com/redcanaryco/invoke-atomicredteam
- **Sysmon SwiftOnSecurity config** : https://github.com/SwiftOnSecurity/sysmon-config
- **Winlogbeat Kafka output** : https://www.elastic.co/guide/en/beats/winlogbeat/current/kafka-output.html
- **MITRE ATT&CK Enterprise** : https://attack.mitre.org/

---

## 9. CONTACT & SUPPORT

Tout le code et la documentation sont auto-contenus dans `~/datasets/`. Les rapports clés à consulter :
- `RAPPORT_ENCADRANT_V2.md` — vue d'ensemble pour encadrant
- `live_detection/README_QUICKSTART.md` — guide pas-à-pas du SOC Router
- `siem_windows/EXPLICATION_MODELS.md` — détail du modèle SIEM
- `adfa_ld/EXPLICATION_MODELS.md` — détail du modèle ADFA
- `cicids2017/EXPLICATION_MODELS.md` + `AUDIT_RAPPORT.md` — CIC-IDS + audit leakage

---

**Fin du plan de déploiement.** Ce document doit être suffisant pour permettre à un assistant (Gemini, Claude, Copilot) ou à l'étudiant lui-même de finir l'implémentation sans dépendance externe.
