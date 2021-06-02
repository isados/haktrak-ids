import yaml
import os
from os import path
import subprocess
import pandas as pd
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

    base_df = pd.read_csv(vars["BaseDataset"]["2017"])

    # Clear extra whitespace within the columns
    base_df.columns = base_df.columns.map(lambda x : x.strip())

    # Remove unnecessary column
    base_df.drop('Fwd Header Length.1', axis=1, inplace=True)

    # ### Company's dataset
    path = check_for_valid_dataset(path)
    company_df = pd.read_csv(path)

    # Before processing columns
    print("Number of Base Dataset Columns:", len(base_df.columns))
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

    base_cols_set = set(base_df.columns)

    print("These are the fields in our own dataset that we need to drop :\n", company_cols_set - base_cols_set, "\n")

    company_df.drop(list(company_cols_set - base_cols_set), axis=1, inplace=True)
    print("Number of fields within the company's dataset:", company_df.shape[1])

    return company_df

def read_companys_dataset2018(path) -> pd.DataFrame:

    base_df = pd.read_csv(vars["BaseDataset"]["2018"])
    path = check_for_valid_dataset(path)
    company_df = pd.read_csv(path)

    # Make Comparison

    # Before processing columns
    print("Number of Base Dataset Columns:", len(base_df.columns))
    print("Number of Own Dataset Columns:", len(company_df.columns))

    baseset = set(base_df.columns)
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
    corrected_labels_map = dict({entry[0]: entry[1][0] for entry in corrected_labels_map.items()})

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

    return_code = subprocess.run([script_path, pcap_path, csv_folder])
    print(return_code)

    csv_path = path.join(csv_folder, csv_name + "_ISCX.csv")
    return csv_path


vars = get_configs()