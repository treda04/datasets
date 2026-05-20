# siem_dataset/ — Dépôt de données brutes (OTRF)

Ce dossier **n'est pas un projet ML**. Il sert uniquement de **dépôt de données brutes** utilisées par les 2 modèles Windows du projet PFE :

| Sous-dossier | Contenu | Utilisé par |
|---|---|---|
| `data/otrf_datasets/datasets/compound/apt29/` | Émulation APT29 (Cozy Bear), 2 jours, ~783k events JSON | [`siem_windows/`](../siem_windows/) |
| `data/otrf_datasets/datasets/atomic/windows/lateral_movement/` | 29 attaques de mouvement latéral (Atomic Red Team) | [`lateral_movement/`](../lateral_movement/) |
| `data/otrf_datasets/datasets/atomic/windows/discovery/` | 7 ZIPs négatifs (tactique différente) | [`lateral_movement/`](../lateral_movement/) |
| `data/otrf_datasets/datasets/atomic/windows/collection/` | 1 ZIP négatif | [`lateral_movement/`](../lateral_movement/) |

**Source originale :** [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) (Roberto Rodriguez, Open Threat Research Forge).

**Pour modéliser, va voir :**
- [`../siem_windows/`](../siem_windows/) — Détection APT29 sur logs Windows host
- [`../lateral_movement/`](../lateral_movement/) — Détection mouvement latéral via Atomic Red Team
