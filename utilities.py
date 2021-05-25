import pandas as pd

def read_base_dataset(dataset_path: str="CIC_IDS2017_Dataset/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv") -> pd.DataFrame:
    
    base_df = pd.read_csv(dataset_path)

    # Clear extra whitespace within the columns
    base_df.columns = base_df.columns.map(lambda x : x.strip())

    # Remove unnecessary column
    base_df.drop('Fwd Header Length.1', axis=1, inplace=True)

    return base_df

def read_companys_dataset(dataset_path: str="CompanyDataset/example.pcap_Flow.csv") -> pd.DataFrame:

    # Paths
    basedataset_path = "CIC_IDS2017_Dataset/MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

    base_df = pd.read_csv(basedataset_path)

    # Clear extra whitespace within the columns
    base_df.columns = base_df.columns.map(lambda x : x.strip())

    # Remove unnecessary column
    base_df.drop('Fwd Header Length.1', axis=1, inplace=True)

    # ### Company's dataset
    company_df = pd.read_csv(dataset_path)

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

