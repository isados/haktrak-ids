import pandas as pd

def convert_base_to_standard_dataset(basedataset_path: str) -> pd.DataFrame:
    
    sampledataset_path = "CompanyDataset/example.pcap_Flow.csv"
    base_df = pd.read_csv(basedataset_path)

    # Remove unnecessary column
    base_df.drop(' Fwd Header Length.1', axis=1, inplace=True)

    # Read sample dataset
    own_df = pd.read_csv(sampledataset_path)


    # We are going to use our own dataset as the absolute reference for the column names
    # Before processing columns
    print("Number of Base Dataset Columns:", len(base_df.columns))
    print("Number of Own Dataset Columns:", len(own_df.columns))

    # Replace the column names within the Base Dataset

    corrected_column_names = {'Avg Bwd Segment Size': 'Bwd Segment Size Avg',
    'Avg Fwd Segment Size': 'Fwd Segment Size Avg',
    'Bwd Avg Bulk Rate': 'Bwd Bulk Rate Avg',
    'Bwd Avg Bytes/Bulk': 'Bwd Bytes/Bulk Avg',
    'Bwd Avg Packets/Bulk': 'Bwd Packet/Bulk Avg',
    'CWE Flag Count': 'CWR Flag Count', ## Based on a guess
    'Destination Port': 'Dst Port',
    'Fwd Avg Bulk Rate': 'Fwd Bulk Rate Avg',
    'Fwd Avg Bytes/Bulk': 'Fwd Bytes/Bulk Avg',
    'Fwd Avg Packets/Bulk': 'Fwd Packet/Bulk Avg',
    'Fwd Header Length.1': 'Fwd Header Length',
    'Init_Win_bytes_backward': 'Bwd Init Win Bytes',
    'Init_Win_bytes_forward': 'FWD Init Win Bytes' ,
    'Max Packet Length':  'Packet Length Max',
    'Min Packet Length': 'Packet Length Min',
    'Total Backward Packets': 'Total Bwd packets',
    'Total Fwd Packets': 'Total Fwd Packet',
    'Total Length of Bwd Packets': 'Total Length of Bwd Packet',
    'Total Length of Fwd Packets': 'Total Length of Fwd Packet',
    'act_data_pkt_fwd': 'Fwd Act Data Pkts',
    'min_seg_size_forward': 'Fwd Seg Size Min'}

    replace_func = lambda old_name: corrected_column_names.get(old_name, old_name)

    basecols = base_df.columns.map(lambda x: replace_func(x.strip()))
    baseset = set(basecols)

    ownset = set(own_df.columns)

    print("These are the fields in our own dataset that we need to retain :\n", ownset - baseset, "\n")

    base_df.columns = basecols

    return base_df

