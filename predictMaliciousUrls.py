#!/usr/bin/env python3

import sys

import utils 

from utils import load_model
from urllib.parse import urlparse

import re

def custom_tokenizer(string):
    final = []
    tokens = [a for a in list(urlparse(string)) if a]
    for t in tokens:
        final.extend(re.compile("[.-]").split(t))
    return final

CSV_PATH = sys.argv[1]
if CSV_PATH is None:
    raise FileNotFoundError

print("Start the detection...")
# Read the dataset
urls = utils.read_base_dataset(CSV_PATH)
x = urls['URL']
pipeline = load_model('iscxurls_ridgeclassifier')
y_hat = pipeline.predict(x)

urls['Label'] = y_hat
# numerical_data.replace({"Label": {0: 'Normal', 1: 'Anomalous'}}, inplace=True)
urls.to_csv("csv/urls_with_labels.csv", index=False)

print("Number of samples:", x.shape[0])
print("RESULTS:", urls.Label.value_counts().to_dict())