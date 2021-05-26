import os
import glob
import pandas as pd

root = "CompanyDataset"
prefix_text = "2021" # Starts with current year

select_files = glob.glob(f"{root}/{prefix_text}*")
df_from_each_file = (pd.read_csv(f, sep=',') for f in select_files)
df_merged = pd.concat(df_from_each_file, ignore_index=True)
save_path = os.path.join(root, "merged.csv")
df_merged.to_csv(save_path, index=False)
print("Done!")