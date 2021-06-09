import yaml
import os
import sys
from os import path
import subprocess

import pickle
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report
from fuzzywuzzy import fuzz
from fuzzywuzzy import process


def read_base_dataset(version: str="2018") -> pd.DataFrame:
    if version == "2018":
        base_df = pd.read_csv(vars["BaseDataset"]["2018"])
    else:
        base_df = pd.read_csv(vars["BaseDataset"]["2017"])
        # Clear extra whitespace within the columns
        base_df.columns = base_df.columns.map(lambda x : x.strip())
        # Remove unnecessary column
        base_df.drop('Fwd Header Length.1', axis=1, inplace=True)
    
    return base_df

def check_for_valid_dataset(path):
    if os.path.exists(path):
        return path
    print("Invalid file path to dataset, switching to company's dataset to predict on...")
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

def read_companys_dataset2018(path) -> pd.DataFrame:
    path = check_for_valid_dataset(path)
    company_df = pd.read_csv(path)
    
    # Make Comparison
    base2018cols = ['Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Tot Fwd Pkts',
       'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
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
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label']

    # Before processing columns
    print("Number of Base Dataset Columns:", len(base2018cols))
    print("Number of Own Dataset Columns:", len(company_df.columns))

    baseset = set(base2018cols)
    companyset = set(company_df.columns)


    # Create a replacement mapping dictionary
    different_colnames = companyset - baseset

    # Pick scorer for the fuzzy matching
    scorer = fuzz.token_sort_ratio
    score_limit = 65 # Fixed value

    corrected_labels_map = {}

    for column_name in different_colnames:
        correct_name = process.extractOne(column_name, baseset, scorer=scorer)
        if correct_name[1] < score_limit:
            continue # so basically skip
        corrected_labels_map[column_name] = correct_name # add to mapping
        

    print(f"\nNumber of Columns to correct : {len(different_colnames)}")
    print(f"Number of corrected labels from `{scorer.__name__}` : {len(corrected_labels_map)}")

    names = corrected_labels_map.items()
    corrected_labels_map = dict({entry[0]: entry[1][0] for entry in names})

    # Rejected certain corrections from it
    keys = ['Flow ID', 'Dst IP', 'Bwd Packet/Bulk Avg', 'Fwd Packet/Bulk Avg', 'ECE Flag Count']
    for key in keys:
        del corrected_labels_map[key]

    # ... and add manual changes
    change = {'Bwd Packet/Bulk Avg' : 'Bwd Pkts/b Avg',
    'ECE Flag Count': 'ECE Flag Cnt',
    'Fwd Packet/Bulk Avg': 'Fwd Pkts/b Avg',
    'Total Length of Bwd Packet': 'TotLen Bwd Pkts',
    'Total Length of Fwd Packet': 'TotLen Fwd Pkts'}

    corrected_labels_map.update(change)

    # Drop columns
    extra_cols = companyset - corrected_labels_map.keys() - baseset
    company_df.drop(extra_cols, axis=1, inplace=True)

    # Finally replace columns
    company_df.columns = company_df.columns.map(lambda bad_col: corrected_labels_map.get(bad_col, bad_col))

    return company_df

def get_configs(config_file: str="config.yml") -> dict:
    try:
        with open(config_file, 'r', newline='') as f:
            return yaml.load(f, Loader=yaml.Loader)
    except yaml.YAMLError as ymlexcp:
        print(ymlexcp)
        return None

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
def load_model(model_name):
    model_path = vars.get(model_name)
    if model_path:
        with open(model_path, "rb") as file:
            pipeline = pickle.load(file)
        return pipeline
    else:
        return None

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


vars = get_configs()