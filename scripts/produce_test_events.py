"""
Producer Kafka de test — simule des events Windows pour valider le pipeline
============================================================================
Génère des events Windows (mix normal + attaque brute force) et les envoie
sur le topic windows-raw-logs pour valider que live_detection.py les
consomme correctement et émet des alertes.

Usage :
    python scripts/produce_test_events.py --mode normal   # 100 events sains
    python scripts/produce_test_events.py --mode attack   # simule brute force
    python scripts/produce_test_events.py --mode mixed    # mix réaliste
"""

import argparse
import json
import random
import time
from datetime import datetime, timezone

from kafka import KafkaProducer

KAFKA_BROKER = "localhost:9092"
TOPIC = "windows-raw-logs"
HOSTS = ["DESKTOP-PC1", "DESKTOP-PC2", "DESKTOP-PC3"]


def mk_event(host: str, event_id: int) -> dict:
    """Format Winlogbeat minimaliste."""
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "host": {"name": host},
        "winlog": {
            "event_id": event_id,
            "computer_name": host,
            "channel": "Security",
        },
        "event": {"code": str(event_id)},
    }


def produce_normal(producer, n: int = 100):
    print(f"[NORMAL] Envoi de {n} events normaux...")
    normal_ids = [4624, 4634, 4647, 4672, 4688]
    for i in range(n):
        ev = mk_event(random.choice(HOSTS), random.choice(normal_ids))
        producer.send(TOPIC, ev)
        if i % 10 == 0:
            print(f"  {i}/{n}")
        time.sleep(0.1)
    producer.flush()


def produce_attack(producer, host: str = "DESKTOP-PC1", n_failures: int = 50):
    """Simule un brute force : N échecs (4625) + quelques 4771 + un succès."""
    print(f"[ATTACK] Brute force sur {host} : {n_failures} échecs en rafale...")
    for i in range(n_failures):
        ev = mk_event(host, 4625)
        producer.send(TOPIC, ev)
        time.sleep(0.05)
    # Quelques Kerberos pre-auth failed
    for i in range(10):
        ev = mk_event(host, 4771)
        producer.send(TOPIC, ev)
        time.sleep(0.1)
    # Logon réussi (l'attaquant a trouvé le mot de passe)
    producer.send(TOPIC, mk_event(host, 4624))
    # Special privileges
    producer.send(TOPIC, mk_event(host, 4672))
    # Process creation suspicieux
    producer.send(TOPIC, mk_event(host, 4688))
    producer.flush()
    print("  Attaque envoyée — surveiller alertes Kafka topic ml-alerts")


def produce_mixed(producer):
    """Bruit normal puis attaque puis bruit normal."""
    produce_normal(producer, n=30)
    print("\n[GAP] Pause 5s...\n")
    time.sleep(5)
    produce_attack(producer, host="DESKTOP-PC2", n_failures=40)
    print("\n[GAP] Pause 5s...\n")
    time.sleep(5)
    produce_normal(producer, n=20)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["normal", "attack", "mixed"],
                        default="mixed")
    parser.add_argument("--broker", default=KAFKA_BROKER)
    args = parser.parse_args()

    producer = KafkaProducer(
        bootstrap_servers=args.broker,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    if args.mode == "normal":
        produce_normal(producer)
    elif args.mode == "attack":
        produce_attack(producer)
    else:
        produce_mixed(producer)

    producer.close()
    print("\n[OK] Producteur terminé.")


if __name__ == "__main__":
    main()
