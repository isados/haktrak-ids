#!/usr/bin/env python3

import sys

import pandas as pd

from utils import load_model, read_companys_dataset2018, convert_pcap_to_csv, get_configs, whatportisthis

COL_ORDER = ['Timestamp', 'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
       'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
       'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
       'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
       'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
       'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
       'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
       'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
       'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', "Label"]

PCAP_PATH = sys.argv[1]
if PCAP_PATH is None:
    raise FileNotFoundError
CSV_PATH = convert_pcap_to_csv(PCAP_PATH)

configvars = get_configs()

# Read the dataset
pd.set_option('mode.use_inf_as_na', True) # convert inf to nan
numerical_data, categorical_data = read_companys_dataset2018(
    CSV_PATH, filter=True, numdataseparate=True)

# Convert Labels to Binary Class
numerical_data.drop('Label', axis=1, inplace=True)

print("Number of samples:", numerical_data.shape[0])

# Read Pipeline from file
pipeline = load_model('hoic_knnmodel')

# print(f"Model being used: {pipeline}")
print("Start the detection...")

predictions = pipeline.predict(numerical_data)
numerical_data['Label'] = predictions
numerical_data['ProtocolName'] = numerical_data['Protocol'].map(lambda port: whatportisthis(port, "tcp"))
numerical_data.replace({"Label": {0: 'Normal', 1: 'Anomalous'}}, inplace=True)

# Save 
numerical_data = pd.concat([categorical_data, numerical_data], axis=1)
numerical_data = numerical_data[COL_ORDER]
numerical_data.to_csv(CSV_PATH, index=False)
print("\nRESULTS:", numerical_data.Label.value_counts().to_dict())
