# auto_main.py
# Script principal d'orchestration IA-Sentinel

import time
import os
from preprocessing import preprocess
from anomaly_detection import train_model, predict

def main():
    normal_path = '../data/normal.csv'
    malicious_path = '../data/malicious.csv'
    preprocessed_path = '../data/preprocessed.csv'
    model_path = '../data/rf_model.joblib'
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
