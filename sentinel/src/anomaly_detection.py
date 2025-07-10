# anomaly_detection.py
# Détection d'anomalies avec Random Forest

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

def train_model(data_path, model_path):
    df = pd.read_csv(data_path)
    if df.empty:
        print("Erreur : le jeu de données est vide après prétraitement. Vérifiez vos fichiers d'entrée.")
        return None
    # Ne garder que les colonnes numériques pertinentes pour l'entraînement
    exclude_cols = ['label', 'timestamp', 'No.', 'Length', 'src_ip', 'dst_ip']
    X = df.drop([col for col in exclude_cols if col in df.columns], axis=1)
    X = X.select_dtypes(include=[np.number])
    feature_names = list(X.columns)
    # Sauvegarder la liste des features
    with open('../data/features.txt', 'w') as f:
        for feat in feature_names:
            f.write(feat + '\n')
    y = df['label']
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    joblib.dump(model, model_path)
    print('Modèle entraîné et sauvegardé.')
    print(f'Features utilisées : {feature_names}')
    return model

def predict(model_path, data_path):
    model = joblib.load(model_path)
    df = pd.read_csv(data_path)
    # Charger la liste des features utilisées à l'entraînement
    with open('../data/features.txt', 'r') as f:
        feature_names = [line.strip() for line in f.readlines()]
    # S'assurer que toutes les features sont présentes (ajouter des colonnes vides si besoin)
    for feat in feature_names:
        if feat not in df.columns:
            df[feat] = 0
    X = df[feature_names]
    y_true = df['label']
    y_pred = model.predict(X)
    print(classification_report(y_true, y_pred))
    print(confusion_matrix(y_true, y_pred))
    return y_pred

if __name__ == "__main__":
    train_model('../data/preprocessed.csv', '../data/rf_model.joblib')
    predict('../data/rf_model.joblib', '../data/preprocessed.csv')
