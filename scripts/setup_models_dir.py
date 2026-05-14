"""Construit models/ avec la structure attendue par SOCOrchestrator
(en copiant les artefacts existants, sans toucher aux originaux).

Structure produite :
    models/cicids/{model.pkl, scaler.pkl, features.json}
    models/adfa/{model.pkl, vectorizer.pkl, features.json, threshold.json}
    models/siem/{model.pkl, scaler.pkl, features.json, threshold.json}
    models/lateral/{model.pkl, scaler.pkl, features.json, threshold.json}
"""
import json
import shutil
from pathlib import Path

ROOT = Path(".")
DEST = ROOT / "models"

COPY_MAP = {
    "cicids": {
        "model.pkl":          "cicids2017/saved_models/xgb_model_v2.pkl",
        "scaler.pkl":         "cicids2017/saved_models/cicids_scaler.pkl",
        "features.json":      "cicids2017/saved_models/feature_columns.json",
        "label_encoder.pkl":  "cicids2017/saved_models/cicids_label_encoder.pkl",
    },
    "adfa": {
        "model.pkl":          "adfa_ld/saved_models/rf_adfa_model_v2.pkl",
        "vectorizer.pkl":     "adfa_ld/saved_models/adfa_vectorizer.pkl",
        "features.json":      "adfa_ld/saved_models/feature_columns.json",
        "threshold.json":     "adfa_ld/saved_models/adfa_threshold.json",
    },
    "siem": {
        # v4 : LightGBM, 95 features, 44 EventIDs monitorés
        "model.pkl":          "siem_windows/saved_models_v4/rf_siem_model.pkl",
        "scaler.pkl":         "siem_windows/saved_models_v4/siem_scaler.pkl",
        "features.json":      "siem_windows/saved_models_v4/feature_columns.json",
        "threshold.json":     "siem_windows/saved_models_v4/siem_threshold.json",
    },
    "lateral": {
        "model.pkl":          "lateral_movement/saved_models/rf_lateral_model.pkl",
        "scaler.pkl":         "lateral_movement/saved_models/lateral_scaler.pkl",
        "features.json":      "lateral_movement/saved_models/feature_columns.json",
        "threshold.json":     "lateral_movement/saved_models/lateral_threshold.json",
    },
}


def main():
    DEST.mkdir(exist_ok=True)
    for key, files in COPY_MAP.items():
        sub = DEST / key
        sub.mkdir(exist_ok=True)
        for target_name, src_path in files.items():
            src = ROOT / src_path
            dst = sub / target_name
            if not src.exists():
                print(f"  [skip] {src} introuvable")
                continue
            shutil.copy2(src, dst)
            print(f"  OK  {key}/{target_name}  <- {src_path}")

        # Pour CIC-IDS pas de threshold (multi-classe), on en crée un par défaut
        thr_file = sub / "threshold.json"
        if not thr_file.exists():
            with thr_file.open("w") as fh:
                json.dump({"threshold": 0.5, "method": "default",
                           "f1_at_threshold": None}, fh)
            print(f"  OK  {key}/threshold.json (créé)")

    print(f"\n[OK] models/ prêt -> {DEST.resolve()}")


if __name__ == "__main__":
    main()
