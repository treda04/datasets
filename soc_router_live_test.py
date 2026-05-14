import json
import joblib
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone
import warnings

warnings.filterwarnings("ignore")

# ==========================================
# 1. IMPORTS DE TES PROPRES SCRIPTS
# ==========================================
# On importe tes fonctions V4 exactement là où elles sont
from siem_windows.preprocessing.preprocess_siem_v4 import (
    parse_event, 
    extract_features_from_window
)

class SOCRouterLiveEngine:
    def __init__(self, artifacts_dir: str):
        self.artifacts_dir = Path(artifacts_dir)
        print(f"🔄 Démarrage du SOC Router (Modèle : {self.artifacts_dir.name})")
        
        # Chargement du modèle (.pkl)
        model_path = list(self.artifacts_dir.glob("*.pkl"))[0]
        self.model = joblib.load(model_path)
        
        # Chargement des colonnes
        with open(self.artifacts_dir / "feature_columns.json", "r") as f:
            self.feature_cols = json.load(f)
            
        # Chargement du seuil
        threshold_file = self.artifacts_dir / "siem_threshold.json"
        self.threshold = 0.5
        if threshold_file.exists():
            with open(threshold_file, "r") as f:
                data = json.load(f)
                self.threshold = data.get("threshold", 0.5)
                
        self.event_buffer = [] # Tampon pour stocker la fenêtre en cours
        
        print(f"✅ Moteur prêt ! Seuil d'alerte strict : {self.threshold:.3f}\n")

    def process_raw_log(self, raw_log_json: str):
        """Reçoit un log texte JSON, le parse, et gère la fenêtre."""
        try:
            event = json.loads(raw_log_json)
        except json.JSONDecodeError:
            return None

        # Étape 1: Parsing de l'événement avec TA fonction
        parsed_event = parse_event(event)
        if not parsed_event:
            return None

        # Ajout au buffer
        self.event_buffer.append(parsed_event)

        # Étape 2: Condition de déclenchement (ex: toutes les 15 actions)
        if len(self.event_buffer) >= 15:
            print(f"⏳ [Fenêtre pleine] Analyse de {len(self.event_buffer)} événements...")
            
            # Étape 3: Extraction des caractéristiques MITRE avec TA fonction
            features = extract_features_from_window(self.event_buffer)
            host = self.event_buffer[0]["host"]
            
            # Vider le buffer pour la prochaine fenêtre
            self.event_buffer = []
            
            # Étape 4: Inférence ML
            return self._predict_and_alert(features, host)
            
        return None

    def _predict_and_alert(self, features: dict, host: str):
        """Fait passer les caractéristiques dans le modèle."""
        df_input = pd.DataFrame([features])
        
        # Ajout des colonnes manquantes (si on n'a pas pu calculer de rolling features en live)
        for col in self.feature_cols:
            if col not in df_input.columns:
                df_input[col] = 0.0
                
        # Réorganisation stricte
        X_live = df_input[self.feature_cols].fillna(0).values
        
        # Prédiction !
        proba = self.model.predict_proba(X_live)[0][1]
        is_alert = bool(proba >= self.threshold)
        
        # Construction du payload final pour le SIEM
        payload = {
            "timestamp_detection": datetime.now(timezone.utc).isoformat(),
            "host": host,
            "soc_decision": "🚨 ALERTE CRITIQUE (APT29)" if is_alert else "✅ Normal (Drop)",
            "ml_confidence_score": round(proba, 4),
            "threshold_used": self.threshold,
            "mitre_powershell_score": features.get("powershell_score", 0),
            "mitre_registry_score": features.get("registry_mod_score", 0)
        }
        return payload

# ==========================================
# 🧪 BANC DE TEST LOCAL
# ==========================================
if __name__ == "__main__":
    print("=== 🛡️ TEST D'INTÉGRATION : DE LOG BRUT À L'ALERTE ===\n")
    
    # On pointe vers tes artefacts V4
    ARTIFACTS_DIR = "siem_windows/saved_models_v4" 
    router = SOCRouterLiveEngine(ARTIFACTS_DIR)
    
    print("📡 Simulation de l'ingestion d'une attaque 'Living off the Land'...\n")
    
    # On simule 15 logs envoyés par Sysmon/Winlogbeat
    for i in range(16):
        # On crée un faux log très suspect (PowerShell + Exécution)
        fake_log = json.dumps({
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "winlog": {
                "computer_name": "DESKTOP-REDA-ADMIN",
                "event_id": 4104 if i % 2 == 0 else 1 # EventID 4104 = PS Script Block
            }
        })
        
        # Le routeur ingère le log
        result = router.process_raw_log(fake_log)
        
        # Si le routeur a craché une décision
        if result:
            print("\n📤 DÉCISION DU SOC ROUTER :")
            print(json.dumps(result, indent=2, ensure_ascii=False))