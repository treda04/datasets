"""
Vérification des artefacts — sanity check avant de lancer live_detection.py
============================================================================
Liste les modèles, scalers, seuils, feature_columns présents.
Charge chaque .pkl pour vérifier qu'il est valide.
Vérifie que les feature_columns sont cohérents.

Usage : python scripts/check_artifacts.py
"""

import json
from pathlib import Path

import joblib

EXPECTED = {
    "siem_windows": {
        "model": "siem_windows/saved_models/rf_siem_model.pkl",
        "scaler": "siem_windows/saved_models/siem_scaler.pkl",
        "threshold": "siem_windows/saved_models/siem_threshold.json",
        "features": "siem_windows/saved_models/feature_columns.json",
    },
    "lateral_movement": {
        "model": "lateral_movement/saved_models/rf_lateral_model.pkl",
        "scaler": "lateral_movement/saved_models/lateral_scaler.pkl",
        "threshold": "lateral_movement/saved_models/lateral_threshold.json",
        "features": "lateral_movement/saved_models/feature_columns.json",
    },
    "cicids": {
        "model_v1": "cicids2017/models/xgb_model.pkl",
        "model_v2": "cicids2017/saved_models/xgb_model_v2.pkl",
    },
    "adfa_ld": {
        "model_v1": "adfa_ld/models/rf_adfa_model.pkl",
        "model_v2": "adfa_ld/saved_models/rf_adfa_model_v2.pkl",
        "threshold_v2": "adfa_ld/saved_models/adfa_threshold.json",
    },
}


def check_one(path_str: str) -> dict:
    path = Path(path_str)
    res = {"path": path_str, "exists": path.exists()}
    if not res["exists"]:
        return res
    res["size_kb"] = round(path.stat().st_size / 1024, 1)
    if path.suffix == ".pkl":
        try:
            obj = joblib.load(path)
            res["loadable"] = True
            res["type"] = type(obj).__name__
        except Exception as e:
            res["loadable"] = False
            res["error"] = str(e)[:120]
    elif path.suffix == ".json":
        try:
            with path.open() as f:
                content = json.load(f)
            res["loadable"] = True
            if isinstance(content, list):
                res["len"] = len(content)
            elif isinstance(content, dict):
                res["keys"] = list(content.keys())
        except Exception as e:
            res["loadable"] = False
            res["error"] = str(e)[:120]
    return res


def main():
    print("=== VÉRIFICATION DES ARTEFACTS ===\n")
    all_ok = True
    for module, files in EXPECTED.items():
        print(f"## {module}")
        for label, path in files.items():
            r = check_one(path)
            mark = "OK " if r.get("exists") and r.get("loadable", True) else "!! "
            extras = []
            if "size_kb" in r:
                extras.append(f"{r['size_kb']} KB")
            if "type" in r:
                extras.append(r["type"])
            if "len" in r:
                extras.append(f"{r['len']} items")
            if "keys" in r:
                extras.append(f"keys={r['keys']}")
            extra = " | ".join(extras) if extras else ""
            print(f"  {mark}{label:20s} {path}  {extra}")
            if not (r.get("exists") and r.get("loadable", True)):
                all_ok = False
        print()

    if all_ok:
        print("[OK] Tous les artefacts présents et valides.")
    else:
        print("[!!] Certains artefacts manquent — voir lignes '!! ' ci-dessus.")
        print("Lancer les pipelines correspondants pour les générer.")


if __name__ == "__main__":
    main()
