"""
Démo live SOC-ML — rejoue data/demo/attack_scenario.jsonl.

Affiche en console les alertes au fur et à mesure, puis tableau récap
des corrélations CRITICAL en fin de run.

Usage :
    python scripts/run_demo.py
    python scripts/run_demo.py --speed 10   # 10x plus vite (recommandé démo)
    python scripts/run_demo.py --speed 0    # instantané (debug)
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.orchestrator import SOCOrchestrator  # noqa: E402

SCENARIO = Path("data/demo/attack_scenario.jsonl")
MODELS = Path("models")
OUTPUT = Path("data/demo/run_output.jsonl")


def color(text, code):
    return f"\033[{code}m{text}\033[0m"


def fmt_alert(p):
    sev = "ATK" if p["is_attack"] else "ok "
    color_code = "31" if p["is_attack"] else "37"  # rouge / gris
    score = f"{p['score']:.2f}" if p["score"] is not None else "?"
    mitre = p.get("mitre_technique") or "-"
    return color(
        f"  [{sev}] {p['model']:8s} score={score} host={p['host']:18s} "
        f"MITRE={mitre:10s}",
        color_code,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--speed", type=float, default=10,
                        help="Vitesse de replay (0 = instantané, 1 = temps réel, "
                             "10 = 10x plus vite)")
    parser.add_argument("--scenario", default=str(SCENARIO))
    parser.add_argument("--models", default=str(MODELS))
    parser.add_argument("--output", default=str(OUTPUT))
    args = parser.parse_args()

    print(color("=" * 70, "36"))
    print(color("  SOC-ML — Demo Live (orchestrateur 4 modèles supervisés)",
                "36;1"))
    print(color("=" * 70, "36"))
    orch = SOCOrchestrator(args.models)
    print(f"Modèles chargés : {list(orch.bundles.keys())}\n")

    events = [json.loads(l) for l in Path(args.scenario).read_text(
        encoding="utf-8").splitlines() if l.strip()]
    print(f"Scénario : {len(events)} events, "
          f"durée {events[-1]['timestamp'] - events[0]['timestamp']:.1f}s\n")
    print(color("--- Replay (vitesse %sx) ---" % args.speed, "33"))

    predictions = []
    t_base_real = time.time()
    t_base_event = events[0]["timestamp"]

    n_atk = 0
    last_phase = None
    for ev in events:
        # Wait pour replay réaliste
        if args.speed > 0:
            elapsed_event = ev["timestamp"] - t_base_event
            elapsed_real = time.time() - t_base_real
            target_real = elapsed_event / args.speed
            sleep_for = target_real - elapsed_real
            if sleep_for > 0:
                time.sleep(sleep_for)

        phase = ev.get("phase")
        if phase and phase != last_phase:
            print(color(f"\n>>> Phase : {phase.upper()}", "35;1"))
            last_phase = phase

        try:
            p = orch.predict(ev)
        except Exception as e:
            print(f"  [ERR] {e}")
            continue
        predictions.append(p)
        if p["is_attack"]:
            n_atk += 1
            print(fmt_alert(p))

    print(color(f"\n--- Replay terminé : {n_atk} alertes /  "
                f"{len(events)} events ---\n", "33"))

    # Corrélation
    print(color("=== CORRÉLATION MULTI-MODÈLES ===", "36;1"))
    criticals = orch.correlate(predictions, window_seconds=300)
    if not criticals:
        print("  Aucune corrélation CRITICAL (< 2 modèles distincts par host)")
    else:
        for c in criticals[:10]:  # top 10
            print(color(
                f"  [CRITICAL] host={c['host']:18s} "
                f"models={c['models_triggered']} "
                f"techniques={c['mitre_techniques']} "
                f"score_max={c['max_score']:.2f}",
                "31;1",
            ))
        if len(criticals) > 10:
            print(f"  ... +{len(criticals) - 10} autres corrélations")

    # Sauvegarde JSONL complet
    OUTPUT_PATH = Path(args.output)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as fh:
        for p in predictions:
            fh.write(json.dumps(p, ensure_ascii=False) + "\n")
        for c in criticals:
            fh.write(json.dumps({"type": "correlated", **c},
                                 ensure_ascii=False) + "\n")
    print(f"\nLog complet : {OUTPUT_PATH}")

    # Résumé final
    print(color("\n=== RÉSUMÉ ===", "36;1"))
    print(f"  Events traités        : {len(predictions)}")
    print(f"  Alertes (is_attack)   : {n_atk}")
    print(f"  Corrélations CRITICAL : {len(criticals)}")
    by_model = {}
    for p in predictions:
        if p["is_attack"]:
            by_model[p["model"]] = by_model.get(p["model"], 0) + 1
    print(f"  Par modèle            : {by_model}")


if __name__ == "__main__":
    main()
