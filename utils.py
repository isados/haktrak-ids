import yaml
import os
import sys
from os import path
import subprocess
from socket import getservbyport

import pickle
import numpy as np
import pandas as pd
import seaborn as sns
import datetime
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report


def get_configs(config_file: str="config.yml") -> dict:
    try:
        with open(config_file, 'r', newline='') as f:
            content = yaml.load(f, Loader=yaml.Loader)
            if content is None:
                raise ValueError("Not a valid config file")
            return content
    except yaml.YAMLError as ymlexcp:
        raise ymlexcp("not sure")

# Decorator for most functions
def latest_config(func):
    def wrapper(*args, **kwargs):
        global vars
        vars = get_configs()
        return func(*args, **kwargs)
    return wrapper

@latest_config
def read_base_dataset(nickname: str="hoic") -> pd.DataFrame:
    path = vars["BaseDataset"].get(nickname, nickname) # if nickname doesn't exist, interpret nickname as path
    base_df = pd.read_csv(path)
    if nickname == "2017": # Remove whitespace and unnecesary column
        base_df.columns = base_df.columns.map(lambda x : x.strip())
        base_df.drop('Fwd Header Length.1', axis=1, inplace=True)
    return base_df

@latest_config
def check_for_valid_dataset(path):
    if os.path.exists(path):
        return path
    print("Invalid file path to dataset, switching to company's default dataset to predict on...")
    return get_configs()['CompanyDataset']['fullsize']
        
def read_companys_dataset2017(path) -> pd.DataFrame:
    base2017cols = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
       'Total Backward Packets', 'Total Length of Fwd Packets',
       'Total Length of Bwd Packets', 'Fwd Packet Length Max',
       'Fwd Packet Length Min', 'Fwd Packet Length Mean',
       'Fwd Packet Length Std', 'Bwd Packet Length Max',
       'Bwd Packet Length Min', 'Bwd Packet Length Mean',
       'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
       'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
       'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
       'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
       'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
       'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
       'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
       'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
       'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
       'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
       'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
       'Idle Std', 'Idle Max', 'Idle Min', 'Label']

    # ### Company's dataset
    path = check_for_valid_dataset(path)
    company_df = pd.read_csv(path)

    # Before processing columns
    print("Number of Base Dataset Columns:", len(base2017cols))
    print("Number of Own Dataset Columns:", len(company_df.columns))


    corrected_column_names = {'Bwd Bulk Rate Avg': 'Bwd Avg Bulk Rate',
    'Bwd Bytes/Bulk Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Init Win Bytes': 'Init_Win_bytes_backward',
    'Bwd Packet/Bulk Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Segment Size Avg': 'Avg Bwd Segment Size',
    'CWR Flag Count': 'CWE Flag Count',
    'Dst Port': 'Destination Port',
    'FWD Init Win Bytes': 'Init_Win_bytes_forward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Bulk Rate Avg': 'Fwd Avg Bulk Rate',
    'Fwd Bytes/Bulk Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Packet/Bulk Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Seg Size Min': 'min_seg_size_forward',
    'Fwd Segment Size Avg': 'Avg Fwd Segment Size',
    'Packet Length Max': 'Max Packet Length',
    'Packet Length Min': 'Min Packet Length',
    'Total Bwd packets': 'Total Backward Packets',
    'Total Fwd Packet': 'Total Fwd Packets',
    'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
    'Total Length of Fwd Packet': 'Total Length of Fwd Packets'}

    replace_func = lambda old_name: corrected_column_names.get(old_name, old_name)

    company_dfcols = company_df.columns.map(lambda x: replace_func(x))
    company_df.columns = company_dfcols
    
    company_cols_set = set(company_dfcols)

    base_cols_set = set(base2017cols)

    print("These are the fields in our own dataset that we need to drop :\n", company_cols_set - base_cols_set, "\n")

    company_df.drop(list(company_cols_set - base_cols_set), axis=1, inplace=True)
    print("Number of fields within the company's dataset:", company_df.shape[1])

    return company_df

    path = check_for_valid_dataset(path)
    company_df = pd.read_csv(path)
    if filter == True:
        # 2018 mapping
        company_to_base2018_map = {'ACK Flag Count': 'ACK Flag Cnt',
        'Average Packet Size': 'Pkt Size Avg',
        'Bwd Bulk Rate Avg': 'Bwd Blk Rate Avg',
        'Bwd Bytes/Bulk Avg': 'Bwd Byts/b Avg',
        'Bwd Header Length': 'Bwd Header Len',
        'Bwd IAT Total': 'Bwd IAT Tot',
        'Bwd Init Win Bytes': 'Init Bwd Win Byts',
        'Bwd Packet Length Max': 'Bwd Pkt Len Max',
        'Bwd Packet Length Mean': 'Bwd Pkt Len Mean',
        'Bwd Packet Length Min': 'Bwd Pkt Len Min',
        'Bwd Packet Length Std': 'Bwd Pkt Len Std',
        'Bwd Packet/Bulk Avg': 'Bwd Pkts/b Avg',
        'Bwd Packets/s': 'Bwd Pkts/s',
        'Bwd Segment Size Avg': 'Bwd Seg Size Avg',
        'CWR Flag Count': 'CWE Flag Count',
        'ECE Flag Count': 'ECE Flag Cnt',
        'FIN Flag Count': 'FIN Flag Cnt',
        'FWD Init Win Bytes': 'Init Fwd Win Byts',
        'Flow Bytes/s': 'Flow Byts/s',
        'Flow Packets/s': 'Flow Pkts/s',
        'Fwd Bulk Rate Avg': 'Fwd Blk Rate Avg',
        'Fwd Bytes/Bulk Avg': 'Fwd Byts/b Avg',
        'Fwd Header Length': 'Fwd Header Len',
        'Fwd IAT Total': 'Fwd IAT Tot',
        'Fwd Packet Length Max': 'Fwd Pkt Len Max',
        'Fwd Packet Length Mean': 'Fwd Pkt Len Mean',
        'Fwd Packet Length Min': 'Fwd Pkt Len Min',
        'Fwd Packet Length Std': 'Fwd Pkt Len Std',
        'Fwd Packet/Bulk Avg': 'Fwd Pkts/b Avg',
        'Fwd Packets/s': 'Fwd Pkts/s',
        'Fwd Segment Size Avg': 'Fwd Seg Size Avg',
        'PSH Flag Count': 'PSH Flag Cnt',
        'Packet Length Max': 'Pkt Len Max',
        'Packet Length Mean': 'Pkt Len Mean',
        'Packet Length Min': 'Pkt Len Min',
        'Packet Length Std': 'Pkt Len Std',
        'Packet Length Variance': 'Pkt Len Var',
        'RST Flag Count': 'RST Flag Cnt',
        'SYN Flag Count': 'SYN Flag Cnt',
        'Subflow Bwd Bytes': 'Subflow Bwd Byts',
        'Subflow Bwd Packets': 'Subflow Bwd Pkts',
        'Subflow Fwd Bytes': 'Subflow Fwd Byts',
        'Subflow Fwd Packets': 'Subflow Fwd Pkts',
        'Total Bwd packets': 'Tot Bwd Pkts',
        'Total Fwd Packet': 'Tot Fwd Pkts',
        'Total Length of Bwd Packet': 'TotLen Bwd Pkts',
        'Total Length of Fwd Packet': 'TotLen Fwd Pkts',
        'URG Flag Count': 'URG Flag Cnt'}
        
        # Finally replace columns
        company_df.columns = company_df.columns.map(lambda bad_col:company_to_base2018_map.get(bad_col, bad_col))

        # Order it
        company_df.sort_values("Timestamp", inplace=True)

        company_df.dropna(axis=0, inplace=True)

        repeated_headers = company_df[(company_df.Protocol == 'Protocol')].index
        company_df.drop(repeated_headers, axis=0, inplace=True)

        # Final Preprocessing step
        timestamp_series = pd.to_datetime(company_df['Timestamp'], dayfirst=True)

        # Extract records with valid idle times only.
        idle_time_cols = ['Idle Mean', 'Idle Max', 'Idle Min']
        company_df[idle_time_cols] = company_df[idle_time_cols].astype(np.float64)
        condition = (company_df['Idle Mean'] > 922547296306670) & (company_df['Idle Max'] > 922547296306670) & (company_df['Idle Min'] > 922547296306670)
        company_df = company_df[condition]

        # Convert to datetime format from Posix
        company_df[idle_time_cols] = company_df[idle_time_cols].applymap(lambda ts : datetime.datetime.fromtimestamp(ts/1000000))
        # Subtract the original timestamp from them
        company_df[idle_time_cols] = company_df[idle_time_cols].sub(timestamp_series, axis='index').applymap(lambda x: x.total_seconds())
        company_df[idle_time_cols] = company_df[idle_time_cols].fillna(0).astype(np.int64)

    if numdataseparate == True:
        extra_cols = ['Timestamp', 'Src IP', 'Src Port', 'Dst IP', 'Flow ID'] 
        categorical_data = company_df[extra_cols]
        company_df.drop(extra_cols, axis=1, inplace=True)
        return company_df, categorical_data
    else:
        return company_df

def read_companys_dataset2018(path: str = "", *, numdataseparate: bool=False, filter: bool=False):
    path = check_for_valid_dataset(path)
    company_df = pd.read_csv(path)
    if filter == True:
        # 2018 mapping
        company_to_base2018_map = {'ACK Flag Count': 'ACK Flag Cnt',
        'Average Packet Size': 'Pkt Size Avg',
        'Bwd Bulk Rate Avg': 'Bwd Blk Rate Avg',
        'Bwd Bytes/Bulk Avg': 'Bwd Byts/b Avg',
        'Bwd Header Length': 'Bwd Header Len',
        'Bwd IAT Total': 'Bwd IAT Tot',
        'Bwd Init Win Bytes': 'Init Bwd Win Byts',
        'Bwd Packet Length Max': 'Bwd Pkt Len Max',
        'Bwd Packet Length Mean': 'Bwd Pkt Len Mean',
        'Bwd Packet Length Min': 'Bwd Pkt Len Min',
        'Bwd Packet Length Std': 'Bwd Pkt Len Std',
        'Bwd Packet/Bulk Avg': 'Bwd Pkts/b Avg',
        'Bwd Packets/s': 'Bwd Pkts/s',
        'Bwd Segment Size Avg': 'Bwd Seg Size Avg',
        'CWR Flag Count': 'CWE Flag Count',
        'ECE Flag Count': 'ECE Flag Cnt',
        'FIN Flag Count': 'FIN Flag Cnt',
        'FWD Init Win Bytes': 'Init Fwd Win Byts',
        'Flow Bytes/s': 'Flow Byts/s',
        'Flow Packets/s': 'Flow Pkts/s',
        'Fwd Bulk Rate Avg': 'Fwd Blk Rate Avg',
        'Fwd Bytes/Bulk Avg': 'Fwd Byts/b Avg',
        'Fwd Header Length': 'Fwd Header Len',
        'Fwd IAT Total': 'Fwd IAT Tot',
        'Fwd Packet Length Max': 'Fwd Pkt Len Max',
        'Fwd Packet Length Mean': 'Fwd Pkt Len Mean',
        'Fwd Packet Length Min': 'Fwd Pkt Len Min',
        'Fwd Packet Length Std': 'Fwd Pkt Len Std',
        'Fwd Packet/Bulk Avg': 'Fwd Pkts/b Avg',
        'Fwd Packets/s': 'Fwd Pkts/s',
        'Fwd Segment Size Avg': 'Fwd Seg Size Avg',
        'PSH Flag Count': 'PSH Flag Cnt',
        'Packet Length Max': 'Pkt Len Max',
        'Packet Length Mean': 'Pkt Len Mean',
        'Packet Length Min': 'Pkt Len Min',
        'Packet Length Std': 'Pkt Len Std',
        'Packet Length Variance': 'Pkt Len Var',
        'RST Flag Count': 'RST Flag Cnt',
        'SYN Flag Count': 'SYN Flag Cnt',
        'Subflow Bwd Bytes': 'Subflow Bwd Byts',
        'Subflow Bwd Packets': 'Subflow Bwd Pkts',
        'Subflow Fwd Bytes': 'Subflow Fwd Byts',
        'Subflow Fwd Packets': 'Subflow Fwd Pkts',
        'Total Bwd packets': 'Tot Bwd Pkts',
        'Total Fwd Packet': 'Tot Fwd Pkts',
        'Total Length of Bwd Packet': 'TotLen Bwd Pkts',
        'Total Length of Fwd Packet': 'TotLen Fwd Pkts',
        'URG Flag Count': 'URG Flag Cnt'}
        
        # Finally replace columns
        company_df.columns = company_df.columns.map(lambda bad_col:company_to_base2018_map.get(bad_col, bad_col))

        # Order it
        company_df.sort_values("Timestamp", inplace=True)

        company_df.dropna(axis=0, inplace=True)

        repeated_headers = company_df[(company_df.Protocol == 'Protocol')].index
        company_df.drop(repeated_headers, axis=0, inplace=True)

        # Final Preprocessing step
        timestamp_series = pd.to_datetime(company_df['Timestamp'], dayfirst=True)

        # Extract records with valid idle times only.
        idle_time_cols = ['Idle Mean', 'Idle Max', 'Idle Min']
        company_df[idle_time_cols] = company_df[idle_time_cols].astype(np.float64)
        condition = (company_df[idle_time_cols]>922547296306670).all(axis=1)
        company_df = company_df[condition]

        # Convert to datetime format from Posix
        company_df[idle_time_cols] = company_df[idle_time_cols].applymap(lambda ts : datetime.datetime.fromtimestamp(ts/1000000))
        # Subtract the original timestamp from them
        company_df[idle_time_cols] = company_df[idle_time_cols].sub(timestamp_series, axis='index').applymap(lambda x: x.total_seconds())
        company_df[idle_time_cols] = company_df[idle_time_cols].fillna(0).astype(np.int64)

    if numdataseparate == True:
        extra_cols = ['Timestamp', 'Src IP', 'Src Port', 'Dst IP', 'Flow ID'] 
        categorical_data = company_df[extra_cols]
        company_df.drop(extra_cols, axis=1, inplace=True)
        return company_df, categorical_data
    else:
        return company_df

def convert_pcap_to_csv(pcap_path):
    script_path = "TCPDUMP_and_CICFlowMeter/convert_pcap_csv.sh"

    csv_folder = path.abspath("csv")
    if not path.exists(csv_folder):
        os.makedirs(csv_folder)
    csv_name = os.path.basename(os.path.splitext(pcap_path)[0])

    process_obj = subprocess.run([script_path, pcap_path, csv_folder])
    return_code = process_obj.returncode
    print(f"Return Code for `{script_path}` : {return_code}")
    if return_code > 0:
        sys.exit(return_code)

    csv_path = path.join(csv_folder, csv_name + "_ISCX.csv")
    return csv_path

# Loading/Dumping models
@latest_config
def load_model(model_name):
    model_path = vars.get(model_name)
    if model_path:
        with open(model_path, "rb") as file:
            pipeline = pickle.load(file)
        return pipeline
    else:
        return None

def save_model(model, name):
    savepath = path.join("models", name)
    with open(savepath, "wb") as file:
        pickle.dump(model, file)
    print("Saved model at :", savepath)

# EDA Functions
def get_scores_plots_stats(actual: pd.DataFrame, pred: pd.DataFrame, *, multiclass_avg='weighted', class_labels=[0,1], figsize=(10,10)) -> None:
    print(classification_report(actual, pred, target_names=class_labels))
    f, ax = plt.subplots(1, 1, figsize=figsize)
    heatmap_ax = ax
    cm = confusion_matrix(actual, pred)

    # class_labels = ['Benign', 'Anomalous']
    plot_labels = {"xticklabels": class_labels, 
               "yticklabels": class_labels}

    sns.heatmap(cm,annot=True, linewidth =0.5, linecolor ="red", fmt =".0f", ax=heatmap_ax, **plot_labels)
    heatmap_ax.set_xlabel("Predicted Labels")
    heatmap_ax.set_ylabel("Actual Labels")
    plt.show()

# Filtering functions
def whatportisthis(port: str, service_type: str='tcp') -> str:
    try:
       return getservbyport(int(port), service_type)
    except:
        return "UNA/RES"
    return None

vars = get_configs()