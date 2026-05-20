"""
Setup models/ dir — copie les 4 modeles depuis leurs dossiers respectifs
=========================================================================

Usage :
    python scripts/setup_models_dir.py

Lit :
    cicids2017/saved_models/v2_final/      -> models/cicids/
    adfa_ld/saved_models/v2_final/         -> models/adfa/
    siem_windows/saved_models/v1_final/    -> models/siem/
    lateral_movement/saved_models/v1_final/-> models/lateral/

Pour chaque modele, copie : model.pkl, scaler.pkl, feature_names.json,
manifest.json + cree un threshold.json a partir du manifest.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"

# Pour chaque modele, on cherche dans plusieurs candidats (v2 d'abord, sinon v1)
# NB : 3 modeles supervises retenus pour le PFE (lateral_movement ecarte
# pour cause de dataset insuffisant — voir RAPPORT_ENCADRANT_V2.md)
SOURCE_CANDIDATES = {
    "cicids":  [ROOT / "cicids2017"       / "saved_models" / "v2_final",
                ROOT / "cicids2017"       / "saved_models" / "v1_final"],
    "adfa":    [ROOT / "adfa_ld"          / "saved_models" / "v2_final",
                ROOT / "adfa_ld"          / "saved_models" / "v1_final"],
    "siem":    [ROOT / "siem_windows"     / "saved_models" / "v1_final"],
}

# Pour ADFA, le vectorizer est au niveau parent (saved_models/, pas v2_final/)
EXTRA_FALLBACKS = {
    "adfa": ROOT / "adfa_ld" / "saved_models",
}


def find_source(key: str) -> Path | None:
    """Retourne le 1er dossier candidat qui contient model.pkl."""
    for cand in SOURCE_CANDIDATES.get(key, []):
        if (cand / "model.pkl").exists():
            return cand
    # Fallback : on accepte un dossier qui contient un .pkl quelconque
    for cand in SOURCE_CANDIDATES.get(key, []):
        if cand.exists() and any(cand.glob("*.pkl")):
            return cand
    return None


SOURCES = [(k, find_source(k)) for k in ["cicids", "adfa", "siem"]]


def setup_one(key: str, src: Path | None) -> bool:
    dst = MODELS_DIR / key
    dst.mkdir(parents=True, exist_ok=True)

    if src is None or not src.exists():
        print(f"  [!] {key:8s} AUCUNE SOURCE TROUVEE (cherche dans : "
              f"{[str(c) for c in SOURCE_CANDIDATES.get(key, [])]})")
        return False

    # Mapper les fichiers source -> destination attendue par l'orchestrateur
    copied = []
    for fname in ["model.pkl", "scaler.pkl", "feature_names.json",
                   "manifest.json", "threshold_scan.csv"]:
        sp = src / fname
        if sp.exists():
            shutil.copy2(sp, dst / fname)
            copied.append(fname)

    # ADFA : vectorizer aussi (peut etre dans src/ ou dans src.parent/)
    for fname in ["vectorizer.pkl", "vectorizer.joblib",
                  "vectorizer_v2.pkl", "vectorizer_v2.joblib"]:
        sp = src / fname
        if not sp.exists():
            # fallback : niveau parent
            sp_parent = src.parent / fname
            if sp_parent.exists():
                sp = sp_parent
        if sp.exists():
            # Toujours sauvegarder sous le nom "vectorizer.pkl" (attendu par l'orch)
            shutil.copy2(sp, dst / "vectorizer.pkl")
            copied.append(f"{fname} -> vectorizer.pkl")
            break

    # ADFA fallback : si pas de model.pkl dans v2_final/, prendre rf_adfa_v2.pkl
    if not (dst / "model.pkl").exists() and key == "adfa":
        for fname in ["rf_adfa_v2.pkl", "rf_adfa.pkl"]:
            sp = src.parent / fname
            if sp.exists():
                shutil.copy2(sp, dst / "model.pkl")
                copied.append(f"{fname} -> model.pkl (fallback)")
                break

    # Cleanup : si l'ancien dossier models/lateral existe encore, on le retire
    legacy_lateral = MODELS_DIR / "lateral"
    if legacy_lateral.exists():
        shutil.rmtree(legacy_lateral)

    # Alias : l'orchestrateur cherche features.json OU feature_names.json
    if (dst / "feature_names.json").exists() and not (dst / "features.json").exists():
        shutil.copy2(dst / "feature_names.json", dst / "features.json")
        copied.append("features.json (alias)")

    # Extraire le seuil depuis manifest.json -> threshold.json
    manifest_p = dst / "manifest.json"
    if manifest_p.exists():
        m = json.loads(manifest_p.read_text(encoding="utf-8"))
        threshold = (
            m.get("decision_threshold")
            or m.get("threshold")
            or m.get("config", {}).get("decision_threshold")
            or 0.5
        )
        (dst / "threshold.json").write_text(
            json.dumps({"threshold": float(threshold)}, indent=2),
            encoding="utf-8",
        )
        copied.append(f"threshold.json (={threshold:.3f})")

    print(f"  [+] {key:8s} OK -> {dst} ({len(copied)} fichiers)")
    for c in copied:
        print(f"        - {c}")
    return True


def main():
    print(f"=== Setup models/ : {MODELS_DIR} ===")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    ok = 0
    for key, src in SOURCES:
        if setup_one(key, src):
            ok += 1

    print()
    print(f"Resultat : {ok}/{len(SOURCES)} modeles installes.")
    if ok < len(SOURCES):
        print("Avertissement : certains modeles sont manquants.")
        print("Verifie que tu as bien fait tourner les pipelines correspondants.")
        sys.exit(1)

    print()
    print("Modeles prets. Tu peux maintenant lancer :")
    print("    python live_detection/soc_router.py")


if __name__ == "__main__":
    main()
