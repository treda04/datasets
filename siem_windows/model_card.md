# Model Card — SIEM Windows v1

## Identité
- **Nom :** rf_siem_model
- **Version :** 1.0
- **Date d'entraînement :** _à remplir après lancement de train_siem.py_
- **Auteur :** Mohamed Reda Taous (PFE UIR / Data Protect)

## Tâche
Classification binaire de fenêtres temporelles (5 min) d'événements Windows :
- Classe 0 : comportement normal
- Classe 1 : fenêtre contenant une activité APT29 (TTPs MITRE ATT&CK)

## Données d'entraînement
- **Source :** OTRF Mordor APT29 Evals Round 2
- **URL :** https://github.com/OTRF/Security-Datasets
- **Volume :** ~784k events Windows (Sysmon ~70%, Security ~15%, PowerShell ~10%)
- **Hosts :** NASHUA, SCRANTON (day1), NEWYORK, UTICA-A, UTICA-C (day2)
- **Émulation :** APT29 (G0016) — scénarios MITRE ATT&CK Eval Round 2

## Split méthodologique
- **Train :** day1 (2020-05-01 / 2020-05-02) — fenêtres temporelles glissantes 5 min, pas 1 min.
- **Test :** day2 (2020-05-02) — uniquement.
- **Pourquoi temporel :** simule la production où on entraîne sur le passé et déploie sur le futur.

## Algorithme
- `RandomForestClassifier(n_estimators=300, class_weight="balanced")`
- Wrappé dans `Pipeline(StandardScaler + RF)` puis dans `CalibratedClassifierCV(method='isotonic', cv=5)`
- Hyperparamètres choisis pour : interprétabilité (feature_importance), inférence rapide (<5 ms), robustesse au déséquilibre.

## Features (12-15 selon EventIDs présents)
Comptages par EventID (4624, 4625, 4648, 4672, 4688, ...), scores comportementaux par tactique MITRE, ratio d'échec de logon, entropie de Shannon, nb d'EventIDs distincts.
**Aucun champ contenant le label (SePrivilege*, mots-clés malware) n'est utilisé.**

## Métriques de référence (à mettre à jour après training)
- F1 (seuil calibré) : **_TBD_**
- ROC-AUC : **_TBD_**
- F1 cross-val (k=5) : **_TBD ± TBD_**

## Limites connues
1. Le label est binaire au niveau **fenêtre** (pas au niveau event individuel) → granularité limitée.
2. Les "attack windows" APT29 sont définies à partir de l'emulation plan MITRE ; un raffinement par event manuel donnerait des labels plus précis.
3. Le modèle n'a vu que les TTPs APT29 ; généralisation à d'autres groupes (APT3, FIN7) à valider.
4. Les EventIDs absents en train (e.g. 4720 si pas de création de compte) auront `cnt_4720=0` partout.

## Usage attendu
Inférence en streaming via `live_detection.py` :
1. Consommation Kafka topic `windows-raw-logs` (Winlogbeat).
2. Maintien d'une fenêtre glissante par host.
3. Inférence à chaque nouvel event (toutes les 5 min en pratique).
4. Score ≥ `threshold` → publication topic `ml-alerts`.

## Sécurité & éthique
- Le modèle peut produire des **faux positifs** ; toute alerte doit être validée par un analyste avant action.
- Pas d'apprentissage continu en production (risque de poisoning).
- Les données Mordor APT29 sont publiques (CC-BY) ; pas de PII.
