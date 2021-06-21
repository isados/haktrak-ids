#!/usr/bin/env python3

import sys
import pickle

import pandas as pd

from utils import load_model, read_companys_dataset2018, convert_pcap_to_csv, get_configs

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
company_df = read_companys_dataset2018(CSV_PATH, extra_cols=True)

# Convert Labels to Binary Class
company_df.drop('Label', axis=1, inplace=True)

print("Removing null & repeated records...\n")
company_df.dropna(axis=0, inplace=True)

repeated_headers = company_df[(company_df.Protocol == 'Protocol')].index
company_df.drop(repeated_headers, axis=0, inplace=True)

company_df.sort_values("Timestamp", inplace=True)
non_numerical_cols = ['Timestamp', 'Dst IP', 'Src Port', 'Src IP', 'Flow ID']
non_numerical_data = company_df[non_numerical_cols]
company_df.drop(non_numerical_cols, axis=1, inplace=True)

print("Number of samples:", company_df.shape[0])

# Read Pipeline from file
pipeline = load_model('hoic_knnmodel')

# print(f"Model being used: {pipeline}")
print("Start the detection...")

predictions = pipeline.predict(company_df)
company_df['Label'] = predictions
company_df.replace({"Label": {0: 'Benign', 1: 'Anomalous'}}, inplace=True)

# Save 
company_df = pd.concat([non_numerical_data, company_df], axis=1)
company_df = company_df[COL_ORDER]
company_df.to_csv(CSV_PATH, index=False)
print("\nRESULTS:", company_df.Label.value_counts().to_dict())
