#!/usr/bin/env python3

import sys
import pickle

import pandas as pd

from utils import read_companys_dataset2018, convert_pcap_to_csv, get_configs

PCAP_PATH = sys.argv[1]
if PCAP_PATH is None:
    raise FileNotFoundError
CSV_PATH = convert_pcap_to_csv(PCAP_PATH)

configvars = get_configs()
MODEL_PATH = configvars['hoic_knnmodel_path']

# Read the dataset
pd.set_option('mode.use_inf_as_na', True) # convert inf to nan
company_df = read_companys_dataset2018(CSV_PATH)

# Convert Labels to Binary Class
company_df.drop('Label', axis=1, inplace=True)

extra_cols = ['Timestamp']
company_df.drop(extra_cols, axis=1, inplace=True)

print("Removing null & repeated records...\n")
company_df.dropna(axis=0, inplace=True)

repeated_headers = company_df[(company_df.Protocol == 'Protocol')].index
company_df.drop(repeated_headers, axis=0, inplace=True)

print("Number of samples:", company_df.shape[0])

# Read Pipeline from file
with open(MODEL_PATH, "rb") as file:
    pipeline = pickle.load(file)

# print(f"Model being used: {pipeline}")
print("Start the detection...")

predictions = pipeline.predict(company_df)
company_df['Label'] = predictions
company_df.replace({"Label": {0: 'Benign', 1: 'Anomalous'}}, inplace=True)

# Save 
company_df.to_csv(CSV_PATH, index=False)
print("\nRESULTS:", company_df.Label.value_counts().to_dict())
