# auto_main.py
# Script principal d'orchestration IA-Sentinel

import time
import os
import sys
from preprocessing import preprocess
from anomaly_detection import train_model, predict

def main():
    # Chemin absolu basé sur le dossier du script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.abspath(os.path.join(base_dir, '../data'))
    normal_path = os.path.join(data_dir, 'normal.csv')
    malicious_path = os.path.join(data_dir, 'malicious.csv')
    preprocessed_path = os.path.join(data_dir, 'preprocessed.csv')
    model_path = os.path.join(data_dir, 'rf_model.joblib')
    # Vérification explicite des fichiers d'entrée
    if not os.path.exists(normal_path):
        print(f"Erreur : Le fichier normal.csv est introuvable à l'emplacement : {normal_path}")
        sys.exit(1)
    if not os.path.exists(malicious_path):
        print(f"Erreur : Le fichier malicious.csv est introuvable à l'emplacement : {malicious_path}")
        sys.exit(1)
    # Prétraitement
    print('Prétraitement...')
    df = preprocess(normal_path, malicious_path)
    df.to_csv(preprocessed_path, index=False)
    # Entraînement
    print('Entraînement du modèle...')
    train_model(preprocessed_path, model_path)
    # Prédiction
    print('Prédiction sur les données...')
    predict(model_path, preprocessed_path)
    print('Pipeline terminé.')

if __name__ == "__main__":
    main()
