# Soutenance PFE — Outline des slides

**Date soutenance :** 2026-06-02
**Durée :** ~20 min présentation + 10 min Q&A (à confirmer)
**Format conseillé :** 15–20 slides, 1 min / slide en moyenne

---

## Slide 1 — Titre & contexte (1 min)

**Titre :** Intégration de méthodes ML supervisées pour la détection multi-surfaces en environnement SIEM

**Sous-titre :** Audit méthodologique et système d'orchestration de 4 modèles supervisés

**Visuel :**
- Logo UIR / Data Protect
- Image SOC / écran Kibana / matrice MITRE en filigrane

**Speech (30 s) :**
> « Mon PFE chez Data Protect porte sur l'augmentation d'un SOC par une couche ML. La promesse : détecter ce que les règles statiques ratent. La contrainte : ML supervisé pur. »

---

## Slide 2 — Architecture du système (1 min 30)

**Visuel :** schéma de flux

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│ Netflow │   │ Sysmon  │   │ Linux   │   │ Identity│
│  Zeek   │   │ Windows │   │ auditd  │   │ logs AD │
└────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
     │             │             │             │
     ▼             ▼             ▼             ▼
┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────┐
│ XGBoost │  │   RF     │  │  RF +   │  │   RF +   │
│ CIC-IDS │  │  SIEM W. │  │ Calibr. │  │ Calibr.  │
│   v2    │  │   v3     │  │  ADFA   │  │ Lateral  │
└────┬────┘  └────┬─────┘  └────┬────┘  └────┬─────┘
     └─────────────┼─────────────┼─────────────┘
                   ▼             ▼
             ┌──────────────────────┐
             │   SOCOrchestrator    │
             │  route / predict /   │
             │     correlate        │
             └──────────┬───────────┘
                        ▼
                 Alertes corrélées
              (CRITICAL si ≥2 modèles)
```

**Speech :**
> « 4 surfaces complémentaires : réseau, host Windows, host Linux, identité. Chaque modèle voit sa surface ; l'orchestrateur centralise et corrèle. »

---

## Slide 3 — Méthodologie : rigueur anti-leakage (CENTRAL — 3 min)

**Visuel :** tableau V1 vs V2/V3 (feuille 5 du RAPPORT_RESULTATS.xlsx)

| Modèle | V1 — problème identifié | F1 V1 | Correctif | F1 V2/V3 |
|---|---|---|---|---|
| CIC-IDS-2017 | Shortcut `Destination Port` (imp > 0.5) | ~1.00 | Suppression ports + dérivés | 0.994 |
| ADFA-LD | Vectorizer fit sur all data | ~0.96 | fit train uniquement + GroupShuffleSplit famille | 0.957 |
| SIEM Windows | Label leakage `SePrivilege*` | ~1.00 | Features 100 % comportementales | 0.667 |
| Lateral Movement | Circularité features = label | ~1.00 | Atomic Red Team réel + split technique | 0.836 |

**Speech :**
> « Mon premier jet : F1 entre 0.96 et 1.00 — j'ai jugé ça suspect. J'ai fait un audit méthodologique formel et identifié 4 problèmes de leakage typiques de la littérature IDS-ML. Voici l'avant/après. Aucune feature ne dépasse 25 % d'importance dans les versions corrigées. »

**Argument clé :** *un F1 = 0.67 honnête vaut mieux qu'un F1 = 1.00 leaky*

---

## Slide 4 — Résultats détaillés (2 min)

**Visuel :** tableau des F1 + heatmap MITRE (`reports/figures/mitre_coverage.png`)

| Modèle | F1 | AUC | F1 CV |
|---|---|---|---|
| CIC-IDS v2 | **0.994** | — (4-class) | 1.000 |
| ADFA-LD v2 | **0.957** | 0.979 | 0.949 |
| SIEM Windows v3 | **0.667** (LOOHO 0.669 ± 0.014) | 0.573 | 0.745 |
| Lateral Movement | **0.836** | 0.694 | 0.919 |

**Heatmap MITRE :** insérer `reports/figures/mitre_coverage.png`

**Speech :**
> « Lecture par technique MITRE : SIEM atteint recall=1.0 sur T1059, T1068, T1078 — il capture toutes les attaques, à coût d'une précision modeste. Lateral Movement atteint F1 ≥ 0.9 sur 8 techniques distinctes. »

---

## Slide 5 — Démo live (3-4 min)

**Visuel :** terminal split avec :
- À gauche : `python scripts/run_demo.py --speed 5`
- À droite : timeline kill chain (reconnaissance → exfiltration)

**Speech :**
> « Démo de 60 secondes (compressée à 12 s) : un attaquant qui fait reconnaissance, brute force, exécution, mouvement latéral, élévation, exfiltration. L'orchestrateur capte la kill chain et corrèle 2 modèles distincts en alertes CRITICAL. »

**Backup :** vidéo `reports/figures/demo_recording.mp4` si la démo live foire.

---

## Slide 6 — Innovations testées (2 min)

**Visuel :** tableau d'ablation

| Modèle | Méthodes testées | Verdict |
|---|---|---|
| SIEM Windows | RF baseline, RF + host-normalized, XGBoost, Stacking | RF baseline reste optimal (F1 macro 0.609) |
| Lateral Movement | RF baseline, XGBoost tuné, LightGBM, Stacking | RF baseline reste optimal (F1 macro 0.681) |

**Speech :**
> « J'ai testé systématiquement 4 algorithmes par modèle faible. Résultat scientifique : sur des datasets de 100-300 échantillons, les gradient boosters et le stacking n'apportent rien. C'est un résultat **documenté**, pas un échec. »

---

## Slide 7 — Limites assumées (2 min)

**Visuel :** tableau résumé de `reports/LIMITATIONS.md`

| Limite | Mitigation |
|---|---|
| ADFA-LD ancien (2012) | Conservé pour comparabilité littérature |
| SIEM AUC 0.57 (drift inter-host) | Lecture par technique MITRE + corrélation multi-modèles |
| Datasets lab uniquement | Score composite multi-modèles |
| Supervisé pur (pas de zéro-day) | Couverture explicite TTP connues |

**Speech :**
> « Je liste explicitement les limites de mon système. Lucidité méthodologique > scores parfaits. »

---

## Slide 8 — Travaux futurs (1 min)

- Validation sur **logs Data Protect réels** (sous NDA)
- **Baseline normale propre** pour améliorer SIEM Windows
- **Hybride supervisé + Sigma + Isolation Forest** pour la couverture zéro-day
- **Active learning** : enrichissement progressif par les analystes SOC
- Tests d'**évasion adversariale** (Carlini & Wagner)

---

## Slide 9 — Conclusion (1 min)

3 messages clés :

1. **Méthodologie** : 4 problèmes de leakage identifiés et corrigés, scores honnêtes documentés.
2. **Système** : orchestrateur Python production-ready (16 tests pytest passants), démo live fonctionnelle, MITRE ATT&CK coverage chiffrée.
3. **Posture** : un PFE rigoureux scientifiquement bat un PFE optimiste — c'est ce que Data Protect attend.

**Repository :** lien GitHub (à publier)

---

## Annexes (slides bonus 10-15, à montrer en Q&A si demandé)

- **A1 — Cross-validation Leave-One-Host-Out détaillée** (`reports/loho_cv_results.csv`)
- **A2 — Feature importances par modèle** (4 graphes)
- **A3 — Architecture orchestrateur (UML classe SOCOrchestrator)**
- **A4 — Format alertes JSONL** (exemple de `data/demo/run_output.jsonl`)
- **A5 — Stack technique** (Python 3.11, scikit-learn, XGBoost, LightGBM, pytest, joblib)
- **A6 — Statistiques datasets** (CIC-IDS = 500k flux, OTRF APT29 = 783k events, ADFA = 1 579 traces, Atomic = 216k events)
- **A7 — Time budget réel** (5 semaines, dont 2 sur la remédiation V1→V2/V3)
- **A8 — Citations clés** : Khreich 2017 (ADFA-LD), Mendsaikhan 2021 (host-based DL), CIC-IDS-2017 paper Sharafaldin

---

## Conseils pour la répétition

- **Chronométrer 2 fois** la totalité (cible : 20 min hors démo).
- Préparer **les questions adversariales** :
  - « Pourquoi pas de deep learning ? » → contrainte supervisé + petite taille datasets
  - « Pourquoi F1=1.00 acceptable sur CIC-IDS mais suspect sur SIEM ? » → différence de feature importance distribuée vs concentrée
  - « Vous validez sur quels datasets, pas trop synthétiques ? » → voir slide 7 + LIMITATIONS.md
  - « Et si l'attaquant utilise une nouvelle TTP ? » → slide 8, hybride futur
- **Backup vidéo** prête au cas où le terminal/projecteur foire.
