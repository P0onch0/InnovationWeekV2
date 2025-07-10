# export_results.py
# Export et formatage des résultats IA-Sentinel

import pandas as pd
import datetime
import os
from preprocessing import clean_and_format, extract_features
import joblib

def export_alerts(df, output_path):
    alerts = df[df['label'] == 1]
    alerts['timestamp'] = datetime.datetime.now().isoformat()
    alerts.to_csv(output_path, index=False)
    print(f'Alertes exportées vers {output_path}')

def export_all_logs(df, output_path):
    df['export_timestamp'] = datetime.datetime.now().isoformat()
    # Si le fichier existe déjà, on écrit les nouvelles logs en haut sans relire tout le fichier
    if os.path.exists(output_path):
        # Lire l'en-tête du fichier existant
        with open(output_path, 'r', encoding='utf-8') as f:
            header = f.readline()
            old_content = f.read()
        # Convertir les nouvelles logs en CSV (sans header)
        from io import StringIO
        csv_buffer = StringIO()
        df.to_csv(csv_buffer, index=False, header=False)
        new_content = csv_buffer.getvalue()
        # Réécrire le fichier : header + nouvelles logs + ancien contenu (sans header)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(new_content)
            f.write(old_content)
        print(f'Nouvelles logs ajoutées en haut de {output_path} (sans réécriture complète)')
    else:
        df.to_csv(output_path, index=False)
        print(f'Logs complets exportés vers {output_path} (premier export)')

def predict_on_new_logs(input_path, model_path):
    print(f"Lecture du fichier : {input_path}")
    df = pd.read_csv(input_path)
    print(f"Nombre de lignes lues : {len(df)}")
    df = clean_and_format(df)
    print(f"Après clean_and_format : {len(df)} lignes")
    df = extract_features(df)
    print(f"Après extract_features : {len(df)} lignes")
    # Charger la liste des features utilisées à l'entraînement
    features_path = '../data/features.txt'
    with open(features_path, 'r') as f:
        feature_names = [line.strip() for line in f.readlines()]
    print(f"Features utilisées pour la prédiction : {feature_names}")
    # Charger le modèle entraîné
    print(f"Chargement du modèle : {model_path}")
    model = joblib.load(model_path)
    # S'assurer que toutes les features sont présentes (ajouter des colonnes vides si besoin)
    for feat in feature_names:
        if feat not in df.columns:
            df[feat] = 0
    X = df[feature_names]
    print(f"Shape X pour prédiction : {X.shape}")
    # Prédire l'anomalie (0/1)
    df['anomalie'] = model.predict(X)
    print(f"Nombre de prédictions : {len(df['anomalie'])}")
    # Exporter un CSV simple pour Grafana (timestamp, src_ip, dst_ip, proto, src_port, dst_port, anomalie)
    export_cols = []
    for col in ['timestamp', 'src_ip', 'dst_ip', 'proto', 'src_port', 'dst_port', 'anomalie']:
        if col in df.columns:
            export_cols.append(col)
    export_df = df[export_cols].copy()
    return export_df

if __name__ == "__main__":
    # Prédire sur les nouveaux logs de capture.csv
    model_path = '../data/rf_model.joblib'
    input_path = '/var/log/wireshark/logs/capture.csv'
    output_path = '/var/log/wireshark/result-script/final_results.csv'
    try:
        df_pred = predict_on_new_logs(input_path, model_path)
        export_all_logs(df_pred, output_path)
        print('Export terminé avec succès.')
    except Exception as e:
        print(f"Erreur lors du traitement : {e}")
