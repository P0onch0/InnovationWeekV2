# IA-Sentinel

Détection d'anomalies réseau basée sur l'intelligence artificielle (Random Forest).

## Structure du projet

```
IA_Sentinel/
├── sentinel/
│   ├── src/
│   │   ├── preprocessing.py       # Prétraitement des données réseau
│   │   ├── anomaly_detection.py   # Détection d'anomalies
│   │   ├── auto_main.py           # Script principal automatisé
│   │   └── export_results.py      # Export et formatage des résultats
│   ├── logs/                      # Stockage des logs générés
│   └── data/                      # Données traitées et résultats
└── etc/
    └── systemd/
        └── system/
            └── ia-sentinel.service # Service Linux
```

## Fonctionnalités principales
- Prétraitement intelligent des logs réseau
- Détection d'anomalies par Random Forest
- Génération d'alertes et export des résultats
- Exécution automatisée et logs

## Installation
1. Cloner le dépôt
2. Installer les dépendances Python :
   ```bash
   pip install -r requirements.txt
   ```
3. Placer vos fichiers `normal.csv` et `malicious.csv` dans `sentinel/data/`

## Utilisation
Lancer le pipeline complet :
```bash
python sentinel/src/auto_main.py
```

## Dépendances principales
- pandas
- numpy
- scikit-learn
- joblib

## Service Linux
Un fichier systemd est fourni pour l'exécution continue sur Linux (`etc/systemd/system/ia-sentinel.service`).

## Auteur
Projet IA-Sentinel
