#!/usr/bin/env python3

import os
import sys
import glob
import argparse
import numpy as np
import pandas as pd
from utils import get_configs

parser = argparse.ArgumentParser()
parser.add_argument("csv", 
                    help="path to csv directory", metavar="CSV_FOLDER")
parser.add_argument("-v", "--verbose", action="store_true",
                    help="have output verbosity")
parser.add_argument("-p", "--prefix", default="",
                    help="filter by a prefix")
parser.add_argument("-c", "--columns",
                    help="mention any columns to use instead of the header in the csv")
parser.add_argument("-o", "--savepath", 
                    help="save path of merged csv")
args = parser.parse_args()

configvars = get_configs()

location = args.csv
csv_files = glob.glob(f"{location}/{args.prefix}*")
raw_values = []
for index, csv in enumerate(csv_files):
    print(f"[{index}] Processing {csv}")
    df = pd.read_csv(csv, sep=',', header=None)
    raw_values.append(df.values)

try:
    raw_array = np.concatenate(raw_values, axis=0)
    df_merged = pd.DataFrame(raw_array, columns=[args.columns])
except ValueError as e:
    print("Error: %s" % e)
    sys.exit(1)


savepath = args.savepath
if savepath is None:
    new_csvname = f"{os.path.basename(location)}_merged.csv"
    savepath = os.path.join(location, new_csvname)

df_merged.to_csv(savepath, index=False)

# Delete the remaining csv files
# for file in csv_files:
#     try:
#         os.remove(file)
#     except OSError as e:  ## if failed, report it back to the user ##
#         print ("Error: %s - %s." % (e.filename, e.strerror))
        

print("Done!")