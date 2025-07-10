# IA-Sentinel

Détection d'anomalies réseau basée sur l'intelligence artificielle.

---

## Présentation

IA-Sentinel analyse automatiquement les fichiers de logs réseau (par exemple issus de Wireshark) pour détecter des comportements suspects grâce à un modèle d’IA.  
Il exporte :
- **Tous les événements réseau** dans un fichier CSV principal (`final_result.csv`)
- **Uniquement les anomalies** dans un fichier CSV dédié (`anomalies_only.csv`)

---

## Structure du projet

```
IA_Sentinel/
├── sentinel/
│   ├── src/
│   │   ├── preprocessing.py       # Prétraitement des données réseau
│   │   ├── export_results.py      # Analyse et export des résultats
│   ├── data/
│   │   ├── rf_model.joblib        # Modèle IA entraîné
│   │   └── features.txt           # Liste des variables utilisées
│   └── logs/                      # (optionnel) Stockage des logs bruts
└── etc/
    └── systemd/
        └── system/
            └── ia-sentinel.service # Service Linux (pour automatisation)
```

---

## Installation

1. **Prérequis**
   - Python 3.8 ou plus
   - Modules Python : `pandas`, `joblib`
   - Un modèle IA (`rf_model.joblib`) et un fichier de features (`features.txt`) dans `sentinel/data/`

2. **Installation des dépendances**
   - Vous pouvez installer les dépendances manuellement :
     ```bash
     pip install pandas joblib
     ```
   - **Ou** automatiquement avec le fichier `requirements.txt` fourni :
     ```bash
     pip install -r requirements.txt
     ```

---

## Utilisation

### Lancer l’analyse manuellement

```bash
python3 sentinel/src/export_results.py \
  --input /var/log/wireshark/logs/capture.csv \
  --output /var/log/wireshark/result-script/final_result.csv \
  --model sentinel/data/rf_model.joblib
```

- **--input** : chemin du fichier de logs à analyser
- **--output** : chemin du fichier où seront écrits tous les résultats
- **--model** : chemin du modèle IA (doit être dans le dossier `data/` avec `features.txt`)

### Résultats

- **final_result.csv** : toutes les lignes analysées, avec une colonne `anomalie` (0 = normal, 1 = suspect)
- **anomalies_only.csv** : uniquement les anomalies, avec :
  - `timestamp` : date et heure de l’événement
  - `src_ip` : adresse IP source
  - `dst_ip` : adresse IP de destination
  - `date_log` : date extraite du timestamp

---

## Automatisation

Pour automatiser l’analyse (ex : toutes les minutes), crée une tâche cron ou un service systemd qui lance la commande ci-dessus.

**Exemple cron (toutes les minutes)** :
```
* * * * * python3 /chemin/vers/export_results.py --input ... --output ... --model ...
```

---

## FAQ

- **Je ne vois pas d’anomalies dans `anomalies_only.csv`**  
  → Cela signifie qu’aucun comportement suspect n’a été détecté dans les logs analysés.

- **Le fichier `anomalies_only.csv` n’apparaît pas**  
  → Il sera créé automatiquement dès qu’une anomalie est détectée. Si tu veux qu’il existe même vide, demande-le à l’administrateur.

- **Je veux voir toutes les IP, même multicast/broadcast**  
  → Le script ne filtre plus ces adresses : toutes les IP sont visibles dans les exports.

- **Les IP internes (10.74.x.x) ne sont jamais marquées comme anomalies**  
  → C’est un choix de configuration pour éviter les faux positifs sur le réseau interne.

---

## Auteur

Projet IA-Sentinel