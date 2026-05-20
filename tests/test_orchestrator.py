"""Tests pytest pour SOCOrchestrator.
Lancer depuis la racine du projet :
    pytest tests/test_orchestrator.py -v
"""
import json
import sys
from pathlib import Path

import pytest

# Permet l'import depuis src/ sans installation
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.orchestrator import SOCOrchestrator
from src.orchestrator.mitre_mapping import event_id_to_technique


MODELS_DIR = Path(__file__).parent.parent / "models"


@pytest.fixture(scope="module")
def orch():
    """Instance unique pour tous les tests."""
    return SOCOrchestrator(MODELS_DIR)


# ─────────────────────────────────────────────────────────────────────
# Test 1 — Routing correct selon source
# ─────────────────────────────────────────────────────────────────────
class TestRouting:
    def test_route_netflow(self, orch):
        ev = {"source": "netflow", "event_id": "1"}
        assert orch.route(ev) == "cicids"

    def test_route_linux_syscall(self, orch):
        ev = {"source": "linux_syscall", "event_id": "2"}
        assert orch.route(ev) == "adfa"

    def test_route_windows_event(self, orch):
        ev = {"source": "windows_event", "event_id": "3"}
        assert orch.route(ev) == "siem"

    def test_route_invalid_source(self, orch):
        with pytest.raises(ValueError):
            orch.route({"source": "unknown", "event_id": "x"})


# ─────────────────────────────────────────────────────────────────────
# Test 2 — Corrélation déclenche sur 2 modèles distincts + même host + < 5min
# ─────────────────────────────────────────────────────────────────────
class TestCorrelation:
    def test_correlation_triggers_when_two_models_same_host(self, orch):
        alerts = [
            {"event_id": "1", "host": "PC1", "timestamp": 1000.0,
             "model": "siem", "score": 0.95, "is_attack": True,
             "mitre_technique": "T1059"},
            {"event_id": "2", "host": "PC1", "timestamp": 1100.0,
             "model": "adfa", "score": 0.88, "is_attack": True,
             "mitre_technique": "T1078"},
        ]
        corr = orch.correlate(alerts, window_seconds=300)
        assert len(corr) == 1
        assert corr[0]["host"] == "PC1"
        assert corr[0]["severity"] == "CRITICAL"
        assert set(corr[0]["models_triggered"]) == {"siem", "adfa"}
        assert "T1059" in corr[0]["mitre_techniques"]
        assert "T1078" in corr[0]["mitre_techniques"]

    def test_no_correlation_if_same_model(self, orch):
        # Même modèle 2x sur même host : pas de corrélation (besoin >= 2 distincts)
        alerts = [
            {"event_id": "1", "host": "PC1", "timestamp": 1000.0,
             "model": "siem", "score": 0.95, "is_attack": True,
             "mitre_technique": "T1059"},
            {"event_id": "2", "host": "PC1", "timestamp": 1050.0,
             "model": "siem", "score": 0.92, "is_attack": True,
             "mitre_technique": "T1068"},
        ]
        corr = orch.correlate(alerts, window_seconds=300)
        assert corr == []

    def test_no_correlation_if_outside_window(self, orch):
        # 2 modèles différents mais hors fenêtre 5 min
        alerts = [
            {"event_id": "1", "host": "PC1", "timestamp": 1000.0,
             "model": "siem", "score": 0.95, "is_attack": True,
             "mitre_technique": "T1059"},
            {"event_id": "2", "host": "PC1", "timestamp": 2000.0,
             "model": "adfa", "score": 0.88, "is_attack": True,
             "mitre_technique": "T1078"},
        ]
        corr = orch.correlate(alerts, window_seconds=300)
        assert corr == []

    def test_correlation_ignores_non_attack(self, orch):
        # Une des 2 n'est pas une attack : pas de corrélation
        alerts = [
            {"event_id": "1", "host": "PC1", "timestamp": 1000.0,
             "model": "siem", "score": 0.95, "is_attack": True,
             "mitre_technique": "T1059"},
            {"event_id": "2", "host": "PC1", "timestamp": 1100.0,
             "model": "adfa", "score": 0.30, "is_attack": False,
             "mitre_technique": None},
        ]
        corr = orch.correlate(alerts, window_seconds=300)
        assert corr == []


# ─────────────────────────────────────────────────────────────────────
# Test 3 — Pas de corrélation si hosts différents
# ─────────────────────────────────────────────────────────────────────
class TestNoCorrelationDifferentHosts:
    def test_no_correlation_if_hosts_differ(self, orch):
        alerts = [
            {"event_id": "1", "host": "PC1", "timestamp": 1000.0,
             "model": "siem", "score": 0.95, "is_attack": True,
             "mitre_technique": "T1059"},
            {"event_id": "2", "host": "PC2", "timestamp": 1050.0,
             "model": "adfa", "score": 0.88, "is_attack": True,
             "mitre_technique": "T1078"},
        ]
        corr = orch.correlate(alerts, window_seconds=300)
        assert corr == []


# ─────────────────────────────────────────────────────────────────────
# Tests additionnels — predict + run_stream
# ─────────────────────────────────────────────────────────────────────
class TestPredict:
    def test_predict_siem_window(self, orch):
        # Construit un event SIEM avec features attendues par le modèle
        siem_bundle = orch.bundles["siem"]
        features = {c: 0.0 for c in siem_bundle.feature_columns}
        # Simule une fenêtre suspecte
        features["total_events"] = 500
        features["events_per_minute"] = 100
        features["cnt_4688"] = 50  # T1059
        features["execution_score"] = 50

        ev = {
            "event_id": "evt001", "source": "windows_event",
            "host": "PC1", "timestamp": 1700000000.0,
            "features": features,
        }
        out = orch.predict(ev)
        assert out["model"] == "siem"
        assert out["score"] is not None
        assert 0.0 <= out["score"] <= 1.0
        assert isinstance(out["is_attack"], bool)
        # cnt_4688 > 0 -> doit déduire T1059
        assert out["mitre_technique"] == "T1059"

    def test_predict_unknown_source_raises(self, orch):
        with pytest.raises(ValueError):
            orch.predict({"source": "voodoo", "event_id": "x"})


class TestMitreMapping:
    def test_event_4625_to_t1110(self):
        assert event_id_to_technique(4625)[0] == "T1110"

    def test_event_4688_to_t1059(self):
        assert event_id_to_technique(4688)[0] == "T1059"

    def test_event_unknown(self):
        assert event_id_to_technique(99999) is None


class TestRunStream:
    def test_run_stream_writes_jsonl(self, orch, tmp_path):
        siem_bundle = orch.bundles["siem"]
        base_feats = {c: 0.0 for c in siem_bundle.feature_columns}

        stream = [
            {"event_id": f"e{i}", "source": "windows_event",
             "host": "PC1", "timestamp": 1700000000.0 + i,
             "features": {**base_feats, "total_events": 10 + i}}
            for i in range(5)
        ]
        out = tmp_path / "stream.jsonl"
        summary = orch.run_stream(stream, out)

        assert out.exists()
        lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) >= 5
        first = json.loads(lines[0])
        assert "score" in first
        assert summary["n_events"] == 5
