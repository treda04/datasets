# SOC Router — Quickstart

Service Python qui consomme les events Windows depuis Kafka, applique les 4 modèles ML, et publie les alertes vers Kibana.

---

## Prérequis

```bash
pip install kafka-python joblib numpy pandas scikit-learn xgboost lightgbm pyarrow
```

---

## Architecture

```
[Windows machines + Sysmon]
         |
         v (Winlogbeat ou simulateur)
[Kafka topic: raw_events]
         |
         v
[soc_router.py]   <-- CE SERVICE
   |- Charge 3 modèles ML (models/ : cicids, adfa, siem)
   |- Buffer events par hostname/minute
   |- Extraction 33 features Windows
   |- Prédiction via SOCOrchestrator
   |- Corrélation multi-modèles
         |
         +---> [Kafka topic: alerts]          (toutes les fenêtres)
         +---> [Kafka topic: critical_alerts] (corrélations CRITICAL)
                       |
                       v
              [Logstash → Elasticsearch → Kibana]
```

---

## Étape 1 — Préparer le dossier `models/`

L'orchestrateur attend les 4 modèles centralisés dans `models/` :

```bash
python scripts/setup_models_dir.py
```

Sortie attendue :
```
[+] cicids   OK -> models/cicids
[+] adfa     OK -> models/adfa
[+] siem     OK -> models/siem  (threshold=0.300)
Resultat : 3/3 modeles installes.
```

---

## Étape 2 — Démarrer Kafka

Via docker-compose (depuis la racine du projet) :

```bash
docker-compose up -d
```

Vérifier que Kafka tourne :
```bash
docker ps | grep kafka
```

Créer les topics si pas déjà fait :
```bash
docker exec -it kafka kafka-topics.sh --create --topic raw_events \
    --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
docker exec -it kafka kafka-topics.sh --create --topic alerts \
    --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
docker exec -it kafka kafka-topics.sh --create --topic critical_alerts \
    --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1
```

---

## Étape 3 — Lancer le SOC Router

```bash
python live_detection/soc_router.py
```

Sortie attendue :
```
=== SOC Router Service - demarrage ===
Kafka broker        : localhost:9092
Kafka topic IN      : raw_events
Kafka topic OUT     : alerts
Kafka topic CRIT    : critical_alerts
Modeles charges     : ['adfa', 'cicids', 'siem']
Service pret. En attente d'events sur raw_events...
```

Le service tourne maintenant et attend les events.

---

## Étape 4 — Tester (sans vrai lab Windows)

Dans un autre terminal :

```bash
python scripts/simulate_attack.py
```

Cela pousse une kill chain APT synthétique en ~60 s :
1. Baseline (events normaux)
2. PowerShell encoded → T1059.001
3. LSASS handle access → T1003.001
4. Remote login signals (EID 4624 type 3 + 4648) — détectés via lateral_move_score (feature SIEM)
5. Registry Run persistence → T1547.001

**Sortie attendue côté SOC Router** :
```
ALERTE host=DC-WS2022 model=siem score=0.85 mitre=T1059
ALERTE host=DC-WS2022 model=siem score=0.92 mitre=T1003
CRITICAL host=DC-WS2022 models=['siem'] mitre=['T1003','T1059']
STATS uptime=120s in=58 norm=58 windows=4 alerts=3 crit=1
```

---

## Étape 5 — Tester avec un vrai lab Windows (production)

### Sur WS2022 / Win11 :

1. Installer Sysmon avec config SwiftOnSecurity :
   ```cmd
   sysmon64.exe -i sysmonconfig.xml
   ```

2. Activer PowerShell Module Logging + Script Block Logging via GPO :
   ```
   Computer Configuration → Administrative Templates → Windows Components → 
   Windows PowerShell → "Turn on Module Logging" + "Turn on PowerShell Script Block Logging"
   ```

3. Installer Winlogbeat avec cette config minimale (`winlogbeat.yml`) :
   ```yaml
   winlogbeat.event_logs:
     - name: Microsoft-Windows-Sysmon/Operational
     - name: Security
     - name: Microsoft-Windows-PowerShell/Operational

   output.kafka:
     hosts: ["<IP_serveur_kafka>:9092"]
     topic: "raw_events"
     codec.json:
       pretty: false
   ```

4. Démarrer Winlogbeat :
   ```cmd
   winlogbeat.exe -e
   ```

### Vérifier les logs en streaming dans Kafka :
```bash
docker exec -it kafka kafka-console-consumer.sh \
    --topic raw_events --bootstrap-server localhost:9092 --max-messages 5
```

### Exécuter le scénario kill chain réel sur le lab :

```powershell
# 1. PowerShell encoded
$cmd = "Get-Process | Where Name -like 'lsass*'"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -enc $enc

# 2. PSRemoting Lateral
Enter-PSSession -ComputerName DC-WS2022 -Credential admin

# 3. LSASS dump (sur le DC)
$lsass = Get-Process lsass
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump $($lsass.Id) C:\temp\lsass.dmp full

# 4. Registry Run persistance
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
                 -Name "Updater" -Value "powershell.exe -nop"
```

---

## Étape 6 — Visualiser dans Kibana

1. Importer le dashboard depuis `integration/kibana/dashboard.ndjson` via Kibana UI
2. Aller sur `http://localhost:5601`
3. Vérifier les visualisations :
   - **Timeline alertes** (par minute)
   - **Heatmap MITRE** (techniques détectées)
   - **Top hosts** (machines compromises)
   - **CRITICAL correlations** (alertes multi-modèles)

---

## Configuration avancée

Toutes les variables sont configurables via env :

| Variable | Default | Rôle |
|---|---|---|
| `KAFKA_BROKER` | `localhost:9092` | Broker Kafka |
| `KAFKA_TOPIC_IN` | `raw_events` | Topic events bruts |
| `KAFKA_TOPIC_OUT` | `alerts` | Topic alertes |
| `KAFKA_TOPIC_CRIT` | `critical_alerts` | Topic corrélations |
| `MODELS_DIR` | `models` | Chemin des modèles |
| `WINDOW_MINUTES` | `1` | Granularité des fenêtres |
| `CORRELATION_SECONDS` | `300` | Fenêtre corrélation multi-modèles |
| `FLUSH_INTERVAL` | `60` | Intervalle de flush des fenêtres |
| `LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING |

Exemple :
```bash
KAFKA_BROKER=192.168.94.132:9092 LOG_LEVEL=DEBUG python live_detection/soc_router.py
```

---

## Troubleshooting

| Erreur | Solution |
|---|---|
| `MODELS_DIR introuvable` | Lance d'abord `python scripts/setup_models_dir.py` |
| `Kafka broker indisponible` | Vérifie `docker ps` + `docker-compose up -d` |
| `Aucune alerte n'arrive` | Vérifie que Winlogbeat envoie bien (kafka-console-consumer) |
| `predict() failed` | Augmente `LOG_LEVEL=DEBUG` pour voir le détail |
| `Modèle X manquant` | `setup_models_dir.py` n'a pas trouvé le pkl — vérifier saved_models/ |

---

## Fichiers liés

| Fichier | Rôle |
|---|---|
| `live_detection/soc_router.py` | **Service principal** |
| `scripts/setup_models_dir.py` | Prépare `models/` depuis les 4 datasets |
| `scripts/simulate_attack.py` | Test sans vrai lab (envoie events synthétiques) |
| `src/orchestrator/soc_orchestrator.py` | Classe `SOCOrchestrator` |
| `src/orchestrator/mitre_mapping.py` | Mapping EventID → technique MITRE |
| `docker-compose.yml` | Stack ELK + Kafka |
| `integration/` | Configs Logstash + Elasticsearch + Kibana |
