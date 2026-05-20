"""Phase 4 — audit anti-leakage (mesure doublons internes + leakage train↔test).

Sortie : results/final/audit_leakage.json
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pipeline.io_utils import PROCESSED_DIR, RESULTS_DIR  # noqa: E402


def main():
    X_train = np.load(PROCESSED_DIR / "X_train.npy")
    X_test = np.load(PROCESSED_DIR / "X_test.npy")
    y_train = np.load(PROCESSED_DIR / "y_train.npy")
    y_test = np.load(PROCESSED_DIR / "y_test.npy")

    df_tr = pd.DataFrame(X_train).round(6)  # round avant hash (sinon float jitter)
    df_te = pd.DataFrame(X_test).round(6)

    n_train_dup = int(df_tr.duplicated().sum())
    n_test_dup = int(df_te.duplicated().sum())

    train_hashes = pd.util.hash_pandas_object(df_tr, index=False).values
    test_hashes = pd.util.hash_pandas_object(df_te, index=False).values
    train_set = set(train_hashes.tolist())
    n_leak = int(sum(1 for h in test_hashes if h in train_set))

    # Détail par classe : combien de positifs/négatifs du test sont des doublons train ?
    n_leak_positive = int(sum(
        1 for h, y in zip(test_hashes, y_test) if (y == 1 and h in train_set)
    ))
    n_leak_negative = int(sum(
        1 for h, y in zip(test_hashes, y_test) if (y == 0 and h in train_set)
    ))

    audit = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "duplicates_train": {
            "count": n_train_dup,
            "ratio": round(n_train_dup / len(X_train), 4) if len(X_train) else 0.0,
        },
        "duplicates_test": {
            "count": n_test_dup,
            "ratio": round(n_test_dup / len(X_test), 4) if len(X_test) else 0.0,
        },
        "leakage_train_to_test": {
            "count": n_leak,
            "ratio": round(n_leak / len(X_test), 4) if len(X_test) else 0.0,
            "by_class": {
                "positive_overlap": n_leak_positive,
                "negative_overlap": n_leak_negative,
            },
        },
        "thresholds": {
            "duplicates_train_max": 0.05,
            "duplicates_test_max": 0.05,
            "leakage_max": 0.01,
        },
        "verdict": {
            "duplicates_train_ok": (n_train_dup / max(1, len(X_train))) < 0.05,
            "duplicates_test_ok": (n_test_dup / max(1, len(X_test))) < 0.05,
            "leakage_ok": (n_leak / max(1, len(X_test))) < 0.01,
        },
    }
    audit["verdict"]["overall_ok"] = all(audit["verdict"][k] for k in
        ["duplicates_train_ok", "duplicates_test_ok", "leakage_ok"])

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "audit_leakage.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")

    print("=== AUDIT ANTI-LEAKAGE ===")
    print(f"  Train (n={audit['n_train']})")
    print(f"    doublons internes : {n_train_dup} ({audit['duplicates_train']['ratio']*100:.2f} %)")
    print(f"  Test  (n={audit['n_test']})")
    print(f"    doublons internes : {n_test_dup} ({audit['duplicates_test']['ratio']*100:.2f} %)")
    print(f"  Leakage train -> test : {n_leak} ({audit['leakage_train_to_test']['ratio']*100:.2f} %)")
    print(f"    dont positifs : {n_leak_positive}")
    print(f"    dont negatifs : {n_leak_negative}")
    print()
    print("Verdict :")
    for k, v in audit["verdict"].items():
        print(f"  {'[OK]' if v else '[KO]'} {k}")


if __name__ == "__main__":
    main()
