#!/usr/bin/env python3

import sys
import pickle

import pandas as pd

from utils import load_model, read_companys_dataset2018, convert_pcap_to_csv, get_configs, whatportisthis

PCAP_PATH = sys.argv[1]
if PCAP_PATH is None:
    raise FileNotFoundError
CSV_PATH = convert_pcap_to_csv(PCAP_PATH)

configvars = get_configs()

# Read the dataset
pd.set_option('mode.use_inf_as_na', True) # convert inf to nan
numerical_data, categorical_data = read_companys_dataset2018(
    CSV_PATH, numdataseparate=True)

# Convert Labels to Binary Class
numerical_data.drop('Label', axis=1, inplace=True)

print("Number of samples:", numerical_data.shape[0])

# Read Pipeline from file
pipeline = load_model('hoic_knnmodel')

# print(f"Model being used: {pipeline}")
print("Start the detection...")

predictions = pipeline.predict(numerical_data)
numerical_data['Label'] = predictions
numerical_data['Protocol'] = numerical_data['Protocol'].map(lambda port: whatportisthis(port, "tcp"))
numerical_data.replace({"Label": {0: 'Normal', 1: 'Anomalous'}}, inplace=True)

# Save 
numerical_data = pd.concat([categorical_data, numerical_data], axis=1)
numerical_data.to_csv(CSV_PATH, index=False)
print("\nRESULTS:", numerical_data.Label.value_counts().to_dict())
