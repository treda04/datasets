"""
EventID -> MITRE ATT&CK technique mapping.
Centralisé pour être réutilisé par notebooks/orchestrateur/tests.
"""

EVENT_TO_TECHNIQUE = {
    # Windows Security
    4624: ("T1078",     "Valid Accounts",                "Initial Access"),
    4625: ("T1110",     "Brute Force",                   "Credential Access"),
    4648: ("T1078.002", "Domain Accounts",               "Initial Access"),
    4661: ("T1087",     "Account Discovery",             "Discovery"),
    4672: ("T1068",     "Exploitation for Priv Esc",     "Privilege Escalation"),
    4673: ("T1068",     "Exploitation for Priv Esc",     "Privilege Escalation"),
    4688: ("T1059",     "Command and Scripting",         "Execution"),
    4689: ("T1059",     "Command and Scripting",         "Execution"),
    4696: ("T1059",     "Command and Scripting",         "Execution"),
    4697: ("T1543.003", "Windows Service",               "Persistence"),
    4698: ("T1053.005", "Scheduled Task",                "Execution"),
    4702: ("T1053.005", "Scheduled Task",                "Execution"),
    4720: ("T1136",     "Create Account",                "Persistence"),
    4726: ("T1531",     "Account Access Removal",        "Impact"),
    4728: ("T1098",     "Account Manipulation",          "Persistence"),
    4732: ("T1098",     "Account Manipulation",          "Persistence"),
    4738: ("T1098",     "Account Manipulation",          "Persistence"),
    4756: ("T1098",     "Account Manipulation",          "Persistence"),
    4768: ("T1558.003", "Kerberoasting",                 "Credential Access"),
    4769: ("T1558.003", "Kerberoasting",                 "Credential Access"),
    4770: ("T1558",     "Steal/Forge Kerberos Tickets",  "Credential Access"),
    4771: ("T1110",     "Brute Force",                   "Credential Access"),
    4773: ("T1558",     "Steal/Forge Kerberos Tickets",  "Credential Access"),
    4776: ("T1110",     "Brute Force",                   "Credential Access"),
    4798: ("T1087",     "Account Discovery",             "Discovery"),
    4799: ("T1087.002", "Domain Account Discovery",      "Discovery"),
    5140: ("T1021.002", "SMB / Admin Shares",            "Lateral Movement"),
    5145: ("T1021.002", "SMB / Admin Shares",            "Lateral Movement"),
    # Sysmon
    1:    ("T1059",     "Command and Scripting",         "Execution"),
    3:    ("T1071",     "Application Layer Protocol",    "Command and Control"),
    7:    ("T1574",     "Hijack Execution Flow",         "Persistence"),
    8:    ("T1055",     "Process Injection",             "Defense Evasion"),
    10:   ("T1003",     "OS Credential Dumping",         "Credential Access"),
    11:   ("T1105",     "Ingress Tool Transfer",         "Command and Control"),
    12:   ("T1112",     "Modify Registry",               "Defense Evasion"),
    13:   ("T1112",     "Modify Registry",               "Defense Evasion"),
    22:   ("T1071.004", "DNS",                           "Command and Control"),
    4103: ("T1059.001", "PowerShell",                    "Execution"),
    4104: ("T1059.001", "PowerShell",                    "Execution"),
}


def event_id_to_technique(event_id):
    """Retourne (technique_id, name, tactic) ou None si non mappé."""
    return EVENT_TO_TECHNIQUE.get(int(event_id))


def techniques_from_features(features, prefix="cnt_"):
    """Liste les techniques MITRE déduites des compteurs EventID > 0 d'une fenêtre."""
    techs = []
    for col, val in features.items():
        if not col.startswith(prefix) or val is None or val <= 0:
            continue
        try:
            eid = int(col[len(prefix):])
        except ValueError:
            continue
        if eid in EVENT_TO_TECHNIQUE:
            techs.append(EVENT_TO_TECHNIQUE[eid][0])
    # Déduplication conservant l'ordre
    seen = set()
    return [t for t in techs if not (t in seen or seen.add(t))]
