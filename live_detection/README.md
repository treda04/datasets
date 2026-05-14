# live_detection/ — Consommateur Kafka + Inférence ML (Production)

## Rôle
Service de détection en temps réel. Consomme les événements Windows depuis Kafka,
applique les 4 modèles ML, et publie les alertes vers un topic dédié.

## Architecture du Flux

```
Windows 10
(Sysmon + Winlogbeat)
       │
       ▼
Kafka Broker (192.168.94.132)
Topic: windows-raw-logs
       │
       ▼
live_detection.py          ← CE SERVICE
  ├── Parsing JSON
  ├── Extraction features
  ├── Inférence ML (4 modèles)
  └── Score d'alerte agrégé
       │
       ▼
Kafka Topic: ml-alerts
       │
       ▼
Logstash Pipeline
       │
       ▼
Elasticsearch: ml-detections-*
       │
       ▼
Kibana Dashboard SOC
```

## Fichiers
```
live_detection/
├── live_detection.py      ← Service principal (Kafka consumer + inférence)
└── README.md              ← Ce fichier
```

## Configuration Kafka
Éditer les constantes en haut de `live_detection.py` :
```python
KAFKA_BROKER    = "192.168.94.132:9092"
TOPIC_INPUT     = "windows-raw-logs"
TOPIC_ALERTS    = "ml-alerts"
ALERT_THRESHOLD = 0.65    # Score ML minimum pour générer une alerte
BATCH_SIZE      = 50      # Événements traités par batch
WINDOW_SIZE     = 500     # Taille de la fenêtre glissante par host
```

## Lancer le Service
```bash
# Depuis datasets/
python live_detection/live_detection.py
```

## Performances Attendues
- Latence par événement : < 100ms
- Throughput : > 500 événements/seconde
- Format alertes : JSON structuré avec score ML, MITRE ATT&CK tag, timestamp

## Format d'une Alerte
```json
{
  "timestamp": "2026-05-04T14:23:00Z",
  "host": "DESKTOP-PC1",
  "ml_score": 0.87,
  "model_scores": {
    "siem_windows": 0.87,
    "adfa_ld": 0.12,
    "cicids": 0.45,
    "lateral_movement": 0.71
  },
  "alert_level": "HIGH",
  "mitre_tactic": "Credential Access",
  "mitre_technique": "T1003",
  "top_features": ["count_4625_5min=45", "logon_failure_ratio=0.92"],
  "event_ids_in_window": [4625, 4625, 4648, 4672],
  "raw_event_count": 48
}
```
