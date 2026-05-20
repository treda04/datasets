"""Phase 0 — extraction de statistiques réelles sur les 2 JSON bruts APT29.

Streaming ligne à ligne (Day 2 fait 1.6 GB) → on ne charge JAMAIS le tout
en mémoire. Sortie : results/eda/raw_stats.json (chiffres réutilisables dans
EXPLICATION_DATA.md).
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
RAW = {
    "day1": BASE / "data" / "raw" / "day1" / "apt29_evals_day1_manual_2020-05-01225525.json",
    "day2": BASE / "data" / "raw" / "day2" / "apt29_evals_day2_manual_2020-05-02035409.json",
}
OUT = BASE / "results" / "eda" / "raw_stats.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

# Règles MITRE simplifiées (les mêmes que celles du PLAN_GLOBAL_SIEM template)
RX_PS_ENC = re.compile(r"\s-e(nc|c)?\s", re.IGNORECASE)
RX_PS_DL = re.compile(r"(downloadstring|iex\s*\(|invoke-expression|downloadfile)", re.IGNORECASE)
RX_MIMI = re.compile(r"mimikatz", re.IGNORECASE)
RX_SCHTASKS = re.compile(r"schtasks.*\/create", re.IGNORECASE)
RX_REG_RUN = re.compile(r"\\(run|runonce)\\", re.IGNORECASE)


def parse_ts(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def process_day(day: str, path: Path) -> dict:
    print(f"[+] streaming {day} : {path.name}")
    total = 0
    bad = 0
    eid = Counter()
    chan = Counter()
    host = Counter()
    ts_min: datetime | None = None
    ts_max: datetime | None = None

    # Signatures attaque
    sig_ps_enc = 0
    sig_ps_dl = 0
    sig_mimi = 0
    sig_schtasks = 0
    sig_reg_run = 0
    sig_lsass = 0
    sig_failed_auth = 0

    # Pour estimer le nombre de fenêtres 5 min × hostname
    minute_keys: set[tuple[str, str]] = set()
    window5_keys: set[tuple[str, str]] = set()

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total += 1
            if total % 200000 == 0:
                print(f"    ... {total:>9} lignes")
            try:
                ev = json.loads(line)
            except Exception:
                bad += 1
                continue

            e_id = ev.get("EventID")
            if e_id is not None:
                eid[str(e_id)] += 1

            ch = ev.get("Channel", "")
            chan[str(ch)] += 1

            h = str(ev.get("Hostname", "?")).split(".")[0].upper()
            host[h] += 1

            ts = parse_ts(ev.get("@timestamp", ""))
            if ts is not None:
                if ts_min is None or ts < ts_min:
                    ts_min = ts
                if ts_max is None or ts > ts_max:
                    ts_max = ts
                # fenêtre minute / 5 min
                minute_keys.add((h, ts.strftime("%Y%m%d%H%M")))
                w5 = ts.replace(minute=(ts.minute // 5) * 5, second=0, microsecond=0)
                window5_keys.add((h, w5.isoformat()))

            cmd = (ev.get("CommandLine") or "") + " " + (ev.get("ScriptBlockText") or "")
            if cmd:
                if RX_PS_ENC.search(cmd):
                    sig_ps_enc += 1
                if RX_PS_DL.search(cmd):
                    sig_ps_dl += 1
                if RX_MIMI.search(cmd):
                    sig_mimi += 1
                if RX_SCHTASKS.search(cmd):
                    sig_schtasks += 1

            target_obj = (ev.get("TargetObject") or "")
            if target_obj and RX_REG_RUN.search(target_obj):
                sig_reg_run += 1

            if str(e_id) == "10":
                ti = (ev.get("TargetImage") or "").lower()
                if "lsass.exe" in ti:
                    sig_lsass += 1

            if str(e_id) == "4625":
                sig_failed_auth += 1

    duration_h = None
    if ts_min and ts_max:
        duration_h = round((ts_max - ts_min).total_seconds() / 3600.0, 2)

    return {
        "file": str(path.name),
        "total_events": total,
        "bad_json_lines": bad,
        "ts_min": ts_min.isoformat() if ts_min else None,
        "ts_max": ts_max.isoformat() if ts_max else None,
        "duration_hours": duration_h,
        "hostnames_count": len(host),
        "hostnames_top": host.most_common(10),
        "eventid_unique": len(eid),
        "eventid_top": eid.most_common(20),
        "channels_unique": len(chan),
        "channels_top": chan.most_common(10),
        "minute_windows": len(minute_keys),
        "win5_windows": len(window5_keys),
        "signatures": {
            "ps_encoded_cmd": sig_ps_enc,
            "ps_download_or_iex": sig_ps_dl,
            "mimikatz_string": sig_mimi,
            "schtasks_create": sig_schtasks,
            "registry_run_runonce": sig_reg_run,
            "process_access_lsass_eid10": sig_lsass,
            "failed_logons_eid4625": sig_failed_auth,
        },
    }


def main():
    print(f"[+] base = {BASE}")
    out = {"generated_utc": datetime.now(timezone.utc).isoformat()}
    for day, path in RAW.items():
        out[day] = process_day(day, path)

    # Agrégats croisés sommaires
    d1 = out["day1"]["total_events"]
    d2 = out["day2"]["total_events"]
    out["totals"] = {
        "events": d1 + d2,
        "ratio_day2_over_day1": round(d2 / d1, 2) if d1 else None,
        "windows_5min_day1": out["day1"]["win5_windows"],
        "windows_5min_day2": out["day2"]["win5_windows"],
        "windows_5min_total": out["day1"]["win5_windows"] + out["day2"]["win5_windows"],
    }

    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[+] OK → {OUT.relative_to(BASE)}")
    print(f"    Day1 = {d1:,} events / Day2 = {d2:,} events")
    print(f"    Fenêtres 5 min total = {out['totals']['windows_5min_total']:,}")


if __name__ == "__main__":
    main()
