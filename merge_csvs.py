import os
import sys
import glob
import pandas as pd
from utils import get_configs

configvars = get_configs()
root = configvars['CompanyDataset']['rootpath']
prefix_text = "2021" # Starts with current year

select_files = glob.glob(f"{root}/{prefix_text}*")
df_from_each_file = (pd.read_csv(f, sep=',') for f in select_files)
    
try:
    df_merged = pd.concat(df_from_each_file, ignore_index=True)
except ValueError as e:
    print("Error: %s" % e)
    sys.exit(1)


save_path = configvars['CompanyDataset']['fullsize']
df_merged.to_csv(save_path, index=False)

# Delete the remaining csv files
for file in select_files:
    try:
        os.remove(file)
    except OSError as e:  ## if failed, report it back to the user ##
        print ("Error: %s - %s." % (e.filename, e.strerror))
        

print("Done!")