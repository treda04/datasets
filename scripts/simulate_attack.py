"""
Simulateur d'attaque — pousse des events Sysmon synthetiques dans Kafka
=========================================================================

Permet de tester le SOC Router SANS avoir un vrai lab Windows.
Genere une kill chain APT 4 etapes en ~60s.

Usage :
    # 1. Lance le SOC Router dans un terminal :
    python live_detection/soc_router.py

    # 2. Dans un autre terminal, lance ce simulateur :
    python scripts/simulate_attack.py

    # 3. Verifie dans le terminal du SOC Router que les alertes sont detectees
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
import uuid
from datetime import datetime, timezone

try:
    from kafka import KafkaProducer
except ImportError:
    print("[!] kafka-python manquant. Run: pip install kafka-python")
    sys.exit(1)

KAFKA_BROKER = os.environ.get("KAFKA_BROKER", "localhost:9092")
KAFKA_TOPIC = os.environ.get("KAFKA_TOPIC_IN", "raw_events")
HOSTNAME = os.environ.get("HOSTNAME_FAKE", "DC-WS2022")


def make_event(event_id: int, **kwargs) -> dict:
    """Forge un event Winlogbeat synthetique."""
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "winlog": {
            "event_id": event_id,
            "channel": kwargs.get("channel", "Microsoft-Windows-Sysmon/Operational"),
            "computer_name": HOSTNAME,
            "event_data": {
                "CommandLine": kwargs.get("cmd", ""),
                "ScriptBlockText": kwargs.get("script", ""),
                "TargetImage": kwargs.get("target_img", ""),
                "TargetObject": kwargs.get("target_obj", ""),
                "SourceImage": kwargs.get("source_img", ""),
                "LogonType": kwargs.get("logon_type", ""),
            },
        },
        "message": kwargs.get("msg", ""),
    }


def step_baseline_noise(producer, n: int = 20):
    """20 events Sysmon normaux (bruit de fond Windows)."""
    print(f"[~] Baseline : {n} events normaux...")
    for _ in range(n):
        eid = random.choice([12, 12, 12, 7, 13, 7, 12, 4658])
        producer.send(KAFKA_TOPIC, make_event(
            eid, source_img="C:\\windows\\system32\\svchost.exe",
        ))
    producer.flush()


def step_powershell_encoded(producer):
    """Etape 1 : PowerShell encoded -> T1059.001."""
    print("[1] PowerShell encoded (T1059.001)...")
    for _ in range(5):
        producer.send(KAFKA_TOPIC, make_event(
            4688,
            channel="Security",
            cmd="powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=",
            msg="A new process has been created",
        ))
    for _ in range(8):
        producer.send(KAFKA_TOPIC, make_event(
            4103,
            channel="Microsoft-Windows-PowerShell/Operational",
            script="Get-Process; Invoke-Expression $cmd",
        ))
    producer.flush()


def step_lsass_dump(producer):
    """Etape 2 : LSASS handle access -> T1003.001."""
    print("[2] LSASS handle access (T1003.001)...")
    for _ in range(15):
        producer.send(KAFKA_TOPIC, make_event(
            10,
            target_img="C:\\Windows\\System32\\lsass.exe",
            source_img="C:\\Users\\admin\\powershell.exe",
        ))
    producer.flush()


def step_lateral_signals(producer):
    """Etape 3 : Signaux remote login (capture par SIEM Windows).
    Note : le modele lateral_movement a ete ecarte du projet. Les events
    remote (4624 type 3, 4648) restent detectables par SIEM Windows via
    la feature lateral_move_score.
    """
    print("[3] Remote login signals (4624 type 3 + 4648)...")
    for _ in range(3):
        producer.send(KAFKA_TOPIC, make_event(
            4624,
            channel="Security",
            logon_type="3",
            msg="An account was successfully logged on (network)",
        ))
    for _ in range(2):
        producer.send(KAFKA_TOPIC, make_event(
            4648,
            channel="Security",
            msg="A logon was attempted using explicit credentials",
        ))
    producer.flush()


def step_registry_persistence(producer):
    """Etape 4 : Registry Run -> T1547.001."""
    print("[4] Registry Run persistence (T1547.001)...")
    for _ in range(4):
        producer.send(KAFKA_TOPIC, make_event(
            13,
            target_obj="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        ))
    producer.flush()


def main():
    print(f"=== Simulateur attaque - Kafka {KAFKA_BROKER} topic={KAFKA_TOPIC} ===")
    print(f"=== Hostname simule : {HOSTNAME} ===\n")
    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER],
        value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
    )

    # Phase 1 : baseline (1 minute de bruit)
    step_baseline_noise(producer, n=15)
    time.sleep(10)

    # Phase 2 : kill chain
    step_powershell_encoded(producer)
    time.sleep(10)
    step_lsass_dump(producer)
    time.sleep(10)
    step_lateral_signals(producer)
    time.sleep(10)
    step_registry_persistence(producer)
    time.sleep(5)

    # Phase 3 : retour au calme
    print("[~] Retour au calme : 10 events normaux...")
    step_baseline_noise(producer, n=10)

    producer.flush()
    producer.close()
    print("\n=== Termine. Verifie les alertes dans le SOC Router. ===")
    print("Attentes :")
    print("  - 1 alerte SIEM Windows (T1059.001 PS encoded)")
    print("  - 1 alerte SIEM Windows (T1003.001 LSASS)")
    print("  - 1 alerte SIEM Windows (T1547.001 Registry)")
    print("  - 1 correlation CRITICAL (>=2 alertes meme host < 5 min)")


if __name__ == "__main__":
    main()
