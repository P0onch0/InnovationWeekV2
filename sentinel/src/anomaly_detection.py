# anomaly_detection.py
# Détection d'anomalies avec Random Forest

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

def train_model(data_path, model_path):
    df = pd.read_csv(data_path)
    X = df.drop(['label'], axis=1)
    y = df['label']
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    joblib.dump(model, model_path)
    print('Modèle entraîné et sauvegardé.')
    return model

def predict(model_path, data_path):
    model = joblib.load(model_path)
    df = pd.read_csv(data_path)
    X = df.drop(['label'], axis=1)
    y_true = df['label']
    y_pred = model.predict(X)
    print(classification_report(y_true, y_pred))
    print(confusion_matrix(y_true, y_pred))
    return y_pred

if __name__ == "__main__":
    train_model('../data/preprocessed.csv', '../data/rf_model.joblib')
    predict('../data/rf_model.joblib', '../data/preprocessed.csv')
