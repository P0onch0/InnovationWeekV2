# preprocessing.py
# Prétraitement des données réseau pour IA-Sentinel

import pandas as pd
import numpy as np
import socket
from collections import Counter

def is_multicast_or_broadcast(ip):
    try:
        if pd.isna(ip):
            return True
        ip_parts = [int(part) for part in str(ip).split('.') if part.isdigit()]
        if len(ip_parts) != 4:
            return True
        # Multicast 224.0.0.0/4, 239.0.0.0/8, Broadcast 255.255.255.255
        if ip_parts[0] >= 224 or ip == '255.255.255.255':
            return True
        return False
    except Exception:
        return True

def clean_and_format(df):
    # Renommer les colonnes pour uniformiser
    df = df.rename(columns={
        'ip.src': 'src_ip',
        'ip.dst': 'dst_ip',
        'tcp.srcport': 'src_port',
        'tcp.dstport': 'dst_port',
        'ip.proto': 'proto',
        'frame.time': 'timestamp'
    })
    # Supprimer les lignes incomplètes (au moins src_ip et dst_ip doivent exister)
    df = df.dropna(subset=['src_ip', 'dst_ip'])
    # Remplacer les ports manquants par 0
    df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0).astype(int)
    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0).astype(int)
    # Filtrer les IP de broadcast/multicast
    df = df[~df['src_ip'].apply(is_multicast_or_broadcast)]
    df = df[~df['dst_ip'].apply(is_multicast_or_broadcast)]
    return df

def load_dataset(normal_path, malicious_path):
    normal = pd.read_csv(normal_path)
    # Pour malicious.csv, label = 1 si dst_ip == 10.74.18.53, sinon 0
    malicious = pd.read_csv(malicious_path)
    malicious = clean_and_format(malicious)
    if 'dst_ip' in malicious.columns:
        malicious['label'] = malicious['dst_ip'].apply(lambda x: 1 if str(x) == '10.74.18.53' else 0)
    else:
        malicious['label'] = 0
    normal = clean_and_format(normal)
    normal['label'] = 0
    data = pd.concat([normal, malicious], ignore_index=True)
    return data

def ip_entropy(ip_series):
    def entropy(ip):
        counts = Counter(ip)
        probs = [c/len(ip) for c in counts.values()]
        return -sum(p*np.log2(p) for p in probs)
    return ip_series.astype(str).apply(entropy)

def extract_features(df):
    # Entropie sur les IP
    df['src_ip_entropy'] = ip_entropy(df['src_ip'])
    df['dst_ip_entropy'] = ip_entropy(df['dst_ip'])
    # Variabilité des ports sur la fenêtre (ici, par ligne)
    df['src_port_var'] = df['src_port']
    df['dst_port_var'] = df['dst_port']
    # Ajoutez d'autres features selon besoin
    return df

def preprocess(normal_path, malicious_path):
    df = load_dataset(normal_path, malicious_path)
    df = extract_features(df)
    return df

if __name__ == "__main__":
    # Exemple d'utilisation
    df = preprocess('../data/normal.csv', '../data/malicious.csv')
    df.to_csv('../data/preprocessed.csv', index=False)
