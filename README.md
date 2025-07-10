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

## Documentation technique

### Architecture logicielle

- **preprocessing.py**  
  Fonctions de nettoyage, renommage des colonnes et préparation des données réseau pour l’analyse.

- **export_results.py**  
  Script principal :  
  - Lit le fichier CSV de logs réseau  
  - Applique le modèle IA pour la détection d’anomalies  
  - Exporte les résultats dans deux fichiers CSV  
  - Peut être lancé manuellement ou automatiquement (cron, systemd)

- **data/rf_model.joblib**  
  Modèle IA entraîné (Random Forest supervisé) pour la classification des logs (normal/suspect).

- **data/features.txt**  
  Liste des variables (features) utilisées par le modèle IA.

### Pipeline de traitement

1. **Lecture du CSV de logs**  
   Le script lit un fichier CSV contenant les événements réseau.

2. **Prétraitement**  
   - Renommage des colonnes pour uniformiser les sources (Wireshark, etc.)
   - Suppression des lignes incomplètes
   - Extraction et calcul des features nécessaires à l’IA

3. **Détection d’anomalies**  
   - Application du modèle Random Forest sur les features extraites
   - Ajout d’une colonne `anomalie` (0 = normal, 1 = suspect)
   - Forçage à 0 pour les IP internes (10.74.x.x) pour éviter les faux positifs

4. **Export**  
   - Toutes les lignes dans `final_result.csv`
   - Les anomalies uniquement dans `anomalies_only.csv` (timestamp, src_ip, dst_ip, date_log)

### Fonctionnalités principales (extraits de code)

- **Prétraitement et nettoyage des logs**
    ```python
    df = clean_and_format(df)
    ```

- **Extraction des features pour l’IA**
    ```python
    df_features = extract_features(df)
    ```

- **Prédiction des anomalies**
    ```python
    y_pred = model.predict(X)
    df['anomalie'] = y_pred
    ```

- **Export des résultats**
    ```python
    export_all_logs(df_pred, args.output)
    anomalies_export.to_csv(anomalies_csv, index=False)
    ```

### Formats de fichiers

- **Entrée** :  
  CSV avec au minimum les colonnes suivantes (noms variables selon la source, renommées automatiquement) :  
  - `timestamp`, `src_ip`, `dst_ip`, `proto`, `src_port`, `dst_port`

- **Sortie** :  
  - `final_result.csv` : toutes les lignes, colonnes ci-dessus + `anomalie`
  - `anomalies_only.csv` : colonnes : `timestamp`, `src_ip`, `dst_ip`, `date_log`

### Configuration

- Les chemins des fichiers d’entrée, sortie et modèle sont configurables via les arguments du script.
- Le modèle IA et la liste des features doivent être présents dans `sentinel/data/`.

### Logs et erreurs

- Les messages d’erreur et d’information sont affichés dans la console.
- Pour l’automatisation, il est conseillé de rediriger la sortie vers un fichier log.

### Réentraîner le modèle IA

- Non inclus dans ce dépôt.  
- Pour réentraîner le modèle, il faut :  
  - Collecter des logs réseau étiquetés (normaux et malveillants)
  - Utiliser un script Python avec scikit-learn pour entraîner une nouvelle Random Forest
  - Sauvegarder le modèle avec joblib dans `data/rf_model.joblib`
  - Mettre à jour `features.txt` si besoin

---

## Auteur

Projet IA-Sentinel