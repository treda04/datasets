# integration/ — Pipeline ELK Complet

## Rôle
Ingestion des alertes ML depuis Kafka, enrichissement, indexation Elasticsearch,
et webhook vers TheHive pour la gestion des incidents.

## Structure
```
integration/
├── logstash/
│   └── ml-alerts-pipeline.conf    ← Pipeline Logstash (Kafka → ES)
├── elasticsearch/
│   └── ml-detections-mapping.json ← Mapping de l'index ml-detections-*
├── kibana/
│   └── dashboard_soc.ndjson       ← Dashboard Kibana (import manuel)
└── README.md
```

## Déploiement

### 1. Elasticsearch — Créer l'index
```bash
curl -X PUT "localhost:9200/ml-detections-000001" \
  -H 'Content-Type: application/json' \
  -d @integration/elasticsearch/ml-detections-mapping.json
```

### 2. Logstash — Lancer le pipeline
```bash
# Copier le fichier de config vers le dossier Logstash
cp integration/logstash/ml-alerts-pipeline.conf /etc/logstash/conf.d/

# Redémarrer Logstash
sudo systemctl restart logstash
```

### 3. Kibana — Dashboard SOC
```
Kibana → Management → Saved Objects → Import
Sélectionner : integration/kibana/dashboard_soc.ndjson
```

## Flux Complet
```
live_detection.py
  → Kafka topic: ml-alerts
    → Logstash ml-alerts-pipeline.conf
      → Elasticsearch: ml-detections-*
        → Kibana Dashboard SOC
        → TheHive (si score > 0.85, via webhook)
```

## Webhook TheHive
Le pipeline Logstash envoie automatiquement une requête HTTP POST à TheHive
si `ml_score >= 0.85`. Format de l'alerte conforme à l'API TheHive v4.
