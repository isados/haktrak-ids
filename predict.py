
# ## Setup and Imports
import pandas as pd
import joblib
from utilities import read_companys_dataset2018

PATH_TO_CSV = ""
MODEL_PATH = "knnmodel.pkl"

# Read the dataset
pd.set_option('mode.use_inf_as_na', True) # convert inf to nan
company_df = read_companys_dataset2018(PATH_TO_CSV)

# Convert Labels to Binary Class
company_df.drop('Label', axis=1, inplace=True)

extra_cols = ['Timestamp']
company_df.drop(extra_cols, axis=1, inplace=True)

print("Removing null records...\n")
company_df.dropna(axis=0, inplace=True)
print("Number of samples:", company_df.shape[0])

# Read Pipeline from file
pipeline = joblib.load(MODEL_PATH)
# print(f"Model being used: {pipeline}")
print("Start the detection...")

predictions = pipeline.predict(company_df)
company_df['Label'] = predictions
company_df.replace({"Label": {0: 'Benign', 1: 'Anomalous'}}, inplace=True)
print("\nRESULTS:", company_df.Label.value_counts().to_dict())

