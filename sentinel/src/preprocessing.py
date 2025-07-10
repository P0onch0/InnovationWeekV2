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
        ip_str = str(ip)
        # Ne filtre que les IPv4, ignore les adresses MAC ou IPv6
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False  # On ne filtre pas les adresses non IPv4
        ip_parts = [int(part) for part in parts if part.isdigit()]
        if len(ip_parts) != 4:
            return False
        # Multicast 224.0.0.0/4, Broadcast 255.255.255.255
        if ip_parts[0] >= 224 or ip_str == '255.255.255.255':
            return True
        return False
    except Exception:
        return False

def clean_and_format(df):
    print(f"Colonnes lues : {list(df.columns)}")
    # Renommer les colonnes pour uniformiser (Wireshark: Source/Destination)
    df = df.rename(columns={
        'ip.src': 'src_ip',
        'ip.dst': 'dst_ip',
        'tcp.srcport': 'src_port',
        'tcp.dstport': 'dst_port',
        'ip.proto': 'proto',
        'frame.time': 'timestamp',
        'Source': 'src_ip',
        'Destination': 'dst_ip',
        'Protocol': 'proto',
        'Time': 'timestamp'
    })
    print(f"Après renommage colonnes : {len(df)} lignes")
    print(df.head(10))  # Affichage des 10 premières lignes pour debug
    # Vérifier la présence des colonnes avant dropna
    for col in ['src_ip', 'dst_ip']:
        if col not in df.columns:
            df[col] = None
    # Supprimer les lignes incomplètes (au moins src_ip et dst_ip doivent exister)
    df = df.dropna(subset=['src_ip', 'dst_ip'])
    print(f"Après dropna src_ip/dst_ip : {len(df)} lignes")
    # Remplacer les ports manquants par 0
    for port_col in ['src_port', 'dst_port']:
        if port_col not in df.columns:
            df[port_col] = 0
        df[port_col] = pd.to_numeric(df[port_col], errors='coerce').fillna(0).astype(int)
    # Filtrer les IP de broadcast/multicast
    if 'src_ip' in df.columns:
        df = df[~df['src_ip'].apply(is_multicast_or_broadcast)]
    if 'dst_ip' in df.columns:
        df = df[~df['dst_ip'].apply(is_multicast_or_broadcast)]
    print(f"Après filtre broadcast/multicast : {len(df)} lignes")
    return df

def load_dataset(normal_path, malicious_path):
    normal = pd.read_csv(normal_path)
    # Pour malicious.csv, label = 1 pour toutes les lignes
    malicious = pd.read_csv(malicious_path)
    malicious = clean_and_format(malicious)
    malicious['label'] = 1
    normal = clean_and_format(normal)
    normal['label'] = 0
    data = pd.concat([normal, malicious], ignore_index=True)
    return data

def entropy(ip):
    counts = Counter(ip)
    probs = [c/len(ip) for c in counts.values()]
    return -sum(p*np.log2(p) for p in probs)

def ip_entropy(ip_series):
    if ip_series is None or len(ip_series) == 0:
        return 0
    return ip_series.astype(str).apply(lambda ip: 0 if pd.isna(ip) else entropy(ip))

def extract_features(df):
    # Entropie sur les IP
    if 'src_ip' in df.columns:
        df['src_ip_entropy'] = ip_entropy(df['src_ip'])
    else:
        df['src_ip_entropy'] = 0
    if 'dst_ip' in df.columns:
        df['dst_ip_entropy'] = ip_entropy(df['dst_ip'])
    else:
        df['dst_ip_entropy'] = 0
    # Variabilité des ports sur la fenêtre (ici, par ligne)
    if 'src_port' in df.columns:
        df['src_port_var'] = df['src_port']
    else:
        df['src_port_var'] = 0
    if 'dst_port' in df.columns:
        df['dst_port_var'] = df['dst_port']
    else:
        df['dst_port_var'] = 0
    # Détection d'attaque par IP source aléatoire sur le port 80 (focus sur les envois vers une même dst_ip)
    if 'src_ip' in df.columns and 'dst_ip' in df.columns and 'dst_port' in df.columns:
        mask_port80 = df['dst_port'] == 80
        # Pour chaque dst_ip sur le port 80, compter le nombre d'IP source distinctes
        src_ip_count_by_dst = df[mask_port80].groupby('dst_ip')['src_ip'].nunique()
        # Seuil : si une dst_ip reçoit sur le port 80 des paquets de plus de 5 IP source différentes, c'est suspect
        seuil = 5
        dst_ip_suspectes = src_ip_count_by_dst[src_ip_count_by_dst > seuil].index
        # Nouvelle feature binaire : 1 si la ligne est un envoi vers une dst_ip suspecte sur le port 80
        df['is_ip_aleatoire_80'] = df.apply(
            lambda row: 1 if row['dst_port'] == 80 and row['dst_ip'] in dst_ip_suspectes else 0, axis=1)
        # Feature globale (pour compatibilité) : ratio d'IP source uniques sur le port 80
        unique_src_ip_80 = df[mask_port80]['src_ip'].nunique()
        total_80 = mask_port80.sum()
        ratio_ip_aleatoire_80 = unique_src_ip_80 / total_80 if total_80 > 0 else 0
        df['ip_aleatoire_80'] = ratio_ip_aleatoire_80
    else:
        df['ip_aleatoire_80'] = 0
        df['is_ip_aleatoire_80'] = 0
    # Détection d'attaque par IP source aléatoire sur tous les ports (IP source rare pour chaque couple dst_ip/dst_port)
    if 'src_ip' in df.columns and 'dst_ip' in df.columns and 'dst_port' in df.columns:
        # Compter le nombre d'occurrences de chaque (src_ip, dst_ip, dst_port)
        src_dst_port_counts = df.groupby(['src_ip', 'dst_ip', 'dst_port']).size()
        # Pour chaque ligne, vérifier si src_ip est rare pour ce couple (dst_ip, dst_port)
        def is_rare(row):
            count = src_dst_port_counts.get((row['src_ip'], row['dst_ip'], row['dst_port']), 0)
            return 1 if count < 2 else 0
        df['is_ip_aleatoire_port'] = df.apply(is_rare, axis=1)
        # Pour compatibilité, on garde la feature globale sur le port 80
        mask_port80 = df['dst_port'] == 80
        unique_src_ip_80 = df[mask_port80]['src_ip'].nunique()
        total_80 = mask_port80.sum()
        ratio_ip_aleatoire_80 = unique_src_ip_80 / total_80 if total_80 > 0 else 0
        df['ip_aleatoire_80'] = ratio_ip_aleatoire_80
    else:
        df['ip_aleatoire_80'] = 0
        df['is_ip_aleatoire_port'] = 0
    # Détection d'IP source qui n'envoie qu'un seul paquet (tous ports et destinations confondus)
    if 'src_ip' in df.columns:
        src_ip_counts = df['src_ip'].value_counts()
        unique_src_ips = src_ip_counts[src_ip_counts == 1].index
        df['is_ip_source_unique'] = df['src_ip'].apply(lambda ip: 1 if ip in unique_src_ips else 0)
    else:
        df['is_ip_source_unique'] = 0
    # Détection d'IP source rare sur chaque port (tous dst_ip confondus)
    if 'src_ip' in df.columns and 'dst_port' in df.columns:
        src_ip_port_counts = df.groupby(['src_ip', 'dst_port']).size()
        def is_rare_on_port(row):
            count = src_ip_port_counts.get((row['src_ip'], row['dst_port']), 0)
            return 1 if count < 2 else 0
        df['is_ip_source_rare_on_port'] = df.apply(is_rare_on_port, axis=1)
    else:
        df['is_ip_source_rare_on_port'] = 0
    # Détection d'une nouvelle IP source jamais vue auparavant sur un port donné (pour dst_ip dans 10.74.0.0/16)
    if 'src_ip' in df.columns and 'dst_ip' in df.columns and 'dst_port' in df.columns:
        # On ne considère que les lignes où dst_ip est dans 10.74.0.0/16
        def is_10_74(ip):
            try:
                parts = str(ip).split('.')
                return len(parts) == 4 and parts[0] == '10' and parts[1] == '74'
            except:
                return False
        mask_10_74 = df['dst_ip'].apply(is_10_74)
        # Pour chaque port, on marque comme suspecte la première apparition d'une src_ip
        seen = set()
        def is_new_src(row):
            key = (row['src_ip'], row['dst_port'])
            if not mask_10_74.loc[row.name]:
                return 0
            if key in seen:
                return 0
            seen.add(key)
            return 1
        df['is_new_src_ip_on_port_10_74'] = df.apply(is_new_src, axis=1)
    else:
        df['is_new_src_ip_on_port_10_74'] = 0
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
