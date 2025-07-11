# export_results.py
# Export et formatage des résultats IA-Sentinel

import pandas as pd
import datetime
import os
from preprocessing import clean_and_format, extract_features
import joblib
import argparse

# Changer le répertoire de travail pour fiabiliser les chemins lors de l'exécution automatisée
os.chdir(os.path.dirname(os.path.abspath(__file__)))

def export_alerts(df, output_path):
    alerts = df[df['label'] == 1]
    alerts['timestamp'] = datetime.datetime.now().isoformat()
    alerts.to_csv(output_path, index=False)
    print(f'Alertes exportées vers {output_path}')

def export_all_logs(df, output_path):
    export_timestamp = datetime.datetime.now().isoformat()
    df['export_timestamp'] = export_timestamp
    df = df.fillna('')
    if os.path.exists(output_path):
        try:
            old_df = pd.read_csv(output_path)
        except Exception as e:
            print(f"Erreur de lecture du fichier existant : {e}. On repart de zéro.")
            old_df = pd.DataFrame(columns=df.columns)
        old_df = old_df.fillna('')
        for col in df.columns:
            if col not in old_df.columns:
                old_df[col] = ''
        for col in old_df.columns:
            if col not in df.columns:
                df[col] = ''
        old_df = old_df[df.columns]
        df = df[old_df.columns]
        id_cols = [col for col in df.columns if col != 'export_timestamp']
        for col in id_cols:
            df[col] = df[col].astype(str)
            old_df[col] = old_df[col].astype(str)
        if not id_cols:
            print('Aucune colonne commune pour identifier les doublons, export annulé.')
            return
        merged = pd.merge(df, old_df, on=id_cols, how='left', indicator=True)
        # Correction : on récupère les colonnes d'identification + export_timestamp depuis df
        new_rows = merged[merged['_merge'] == 'left_only'].copy()
        # On doit réinjecter la colonne export_timestamp depuis df (car elle n'est pas jointe)
        if 'export_timestamp' not in new_rows.columns:
            # On récupère la valeur depuis df en utilisant les index
            new_rows['export_timestamp'] = export_timestamp
        # Réordonner les colonnes
        new_rows = new_rows[df.columns]
        result_df = pd.concat([new_rows, old_df], ignore_index=True)
        result_df.to_csv(output_path, index=False)
        print(f'Nouvelles logs ajoutées en haut de {output_path} (sans doublons)')
    else:
        df.to_csv(output_path, index=False)
        print(f'Logs complets exportés vers {output_path} (premier export)')

def predict_on_new_logs(input_path, model_path):
    print(f"Lecture du fichier : {input_path}")
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Fichier d'entrée introuvable : {input_path}")
    df = pd.read_csv(input_path)
    print(f"Nombre de lignes lues : {len(df)}")
    df = clean_and_format(df)
    print(f"Après clean_and_format : {len(df)} lignes")
    df = extract_features(df)
    print(f"Après extract_features : {len(df)} lignes")
    # Correction : chemin absolu du features.txt et du modèle dans le dossier ../data/ par rapport à ce script
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data'))
    features_path = os.path.join(data_dir, 'features.txt')
    model_path_abs = os.path.join(data_dir, 'rf_model.joblib')
    if not os.path.exists(features_path):
        raise FileNotFoundError(f"Le fichier des features est introuvable : {features_path}.\n\nVérifiez que l'entraînement a bien été effectué et que le fichier existe dans le dossier data.\nSi besoin, relancez l'entraînement avec auto_main.py.")
    with open(features_path, 'r') as f:
        feature_names = [line.strip() for line in f.readlines()]
    print(f"Features utilisées pour la prédiction : {feature_names}")
    print(f"Chargement du modèle : {model_path_abs}")
    if not os.path.exists(model_path_abs):
        raise FileNotFoundError(f"Le modèle entraîné est introuvable : {model_path_abs}.\n\nVérifiez que l'entraînement a bien été effectué et que le fichier existe dans le dossier data.\nSi besoin, relancez l'entraînement avec auto_main.py.")
    model = joblib.load(model_path_abs)
    # S'assurer que toutes les features sont présentes (ajouter des colonnes vides si besoin)
    for feat in feature_names:
        if feat not in df.columns:
            df[feat] = 0
    X = df[feature_names]
    print(f"Shape X pour prédiction : {X.shape}")
    # Prédire l'anomalie (0/1)
    df['anomalie'] = model.predict(X)
    print(f"Nombre de prédictions : {len(df['anomalie'])}")
    print("Aperçu des adresses IP source :")
    if 'src_ip' in df.columns:
        # Exclure les IP non suspectes de l'affichage
        ip_exclues = ['10.74.16.1', '10.74.19.255']
        src_ip_affiche = df['src_ip'][~df['src_ip'].astype(str).isin(ip_exclues)]
        print(src_ip_affiche.head(10))
    else:
        print("Colonne src_ip absente du DataFrame.")
    # Forcer l'IP 10.74.16.1 et 10.74.19.255 à ne jamais être considérées comme suspectes
    if 'src_ip' in df.columns and 'anomalie' in df.columns:
        mask = df['src_ip'].astype(str).isin(['10.74.16.1', '10.74.19.255'])
        df.loc[mask, 'anomalie'] = 0
    # Forcer toutes les IP source commençant par 10.74 à ne jamais être considérées comme anomalies
    if 'src_ip' in df.columns and 'anomalie' in df.columns:
        mask_1074 = df['src_ip'].astype(str).str.startswith('10.74')
        df.loc[mask_1074, 'anomalie'] = 0
    # Supprimer ces IP des aperçus d'anomalies
    if 'src_ip' in df.columns and 'anomalie' in df.columns:
        df_anomalies = df[(df['anomalie'] == 1) & (~df['src_ip'].astype(str).isin(['10.74.16.1', '10.74.19.255']))]
    else:
        df_anomalies = df[df['anomalie'] == 1] if 'anomalie' in df.columns else df
    # Exporter un CSV simple pour Grafana (timestamp, src_ip, dst_ip, proto, src_port, dst_port, anomalie)
    export_cols = []
    for col in ['timestamp', 'src_ip', 'dst_ip', 'proto', 'src_port', 'dst_port', 'anomalie']:
        if col in df.columns:
            export_cols.append(col)
    export_df = df[export_cols].copy()
    return export_df

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Détection d'anomalies IA-Sentinel sur un fichier de log.")
    parser.add_argument('--input', type=str, default='/var/log/wireshark/logs/capture.csv', help='Chemin du fichier de log à tester')
    parser.add_argument('--output', type=str, default='/var/log/wireshark/result-script/final_result.csv', help='Chemin du fichier de sortie avec résultats')
    parser.add_argument('--model', type=str, default='rf_model.joblib', help='Chemin du modèle Random Forest')
    args = parser.parse_args()
    try:
        df_pred = predict_on_new_logs(args.input, args.model)
        print(f"[DEBUG] Colonnes du DataFrame exporté : {list(df_pred.columns)}")
        print(f"[DEBUG] Nombre de lignes à exporter : {len(df_pred)}")
        export_all_logs(df_pred, args.output)
        # Export anomalies dans un CSV dédié (timestamp, src_ip, dst_ip, date_log)
        anomalies_csv = os.path.join(os.path.dirname(args.output), 'anomalies_only.csv')
        if 'anomalie' in df_pred.columns:
            anomalies = df_pred[df_pred['anomalie'] == 1].copy()
            # Extraire la date de la log à partir du timestamp (si possible)
            if 'timestamp' in anomalies.columns:
                anomalies['date_log'] = anomalies['timestamp'].astype(str).str[:10]
            else:
                anomalies['date_log'] = ''
            anomalies_export = anomalies[['timestamp', 'src_ip', 'dst_ip', 'date_log']] if not anomalies.empty else pd.DataFrame(columns=['timestamp', 'src_ip', 'dst_ip', 'date_log'])
            anomalies_export.to_csv(anomalies_csv, index=False)
            print(f"Export des anomalies vers {anomalies_csv} terminé.")
        # Exclure les IP non suspectes de l'affichage des anomalies
        if 'src_ip' in df_pred.columns and 'anomalie' in df_pred.columns:
            df_anomalies = df_pred[(df_pred['anomalie'] == 1)]
        else:
            df_anomalies = df_pred[df_pred['anomalie'] == 1] if 'anomalie' in df_pred.columns else df_pred
        nb_anomalies = len(df_anomalies)
        print(f"Nombre d'anomalies détectées : {nb_anomalies}")
        if nb_anomalies > 0:
            print('Aperçu des anomalies détectées :')
            print(df_anomalies.head(10))
        else:
            print('Aucune anomalie détectée.')
        print('Export terminé avec succès.')
    except Exception as e:
        print(f"Erreur lors du traitement : {e}")
