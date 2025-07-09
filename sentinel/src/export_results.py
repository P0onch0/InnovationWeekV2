# export_results.py
# Export et formatage des résultats IA-Sentinel

import pandas as pd
import datetime
import os

def export_alerts(df, output_path):
    alerts = df[df['label'] == 1]
    alerts['timestamp'] = datetime.datetime.now().isoformat()
    alerts.to_csv(output_path, index=False)
    print(f'Alertes exportées vers {output_path}')

def export_all_logs(df, output_path):
    df['export_timestamp'] = datetime.datetime.now().isoformat()
    # Si le fichier existe déjà, on ajoute (append) sans écraser l'historique
    if os.path.exists(output_path):
        df.to_csv(output_path, mode='a', header=False, index=False)
    else:
        df.to_csv(output_path, index=False)
    print(f'Logs complets exportés vers {output_path}')

if __name__ == "__main__":
    # Récupérer les logs à analyser depuis le chemin /var/log/wireshark/logs/capture.csv
    df = pd.read_csv('/var/log/wireshark/logs/capture.csv')
    # Ici, il faudrait relancer le pipeline de prétraitement + détection avant export (à adapter si besoin)
    # Pour l'exemple, on suppose que df contient déjà les colonnes nécessaires
    export_alerts(df, '../logs/alerts.csv')
    export_all_logs(df, '/var/log/wireshark/result-script/all_results.csv')
