#!/usr/bin/env python3

import sys
import re
import os

from urllib.parse import urlparse

import utils 


def custom_tokenizer(string):
    final = []
    tokens = [a for a in list(urlparse(string)) if a]
    for t in tokens:
        final.extend(re.compile("[.-]").split(t))
    return final

CSV_PATH = sys.argv[1]
if CSV_PATH is None:
    raise FileNotFoundError

urls = utils.read_base_dataset(CSV_PATH) # Read the dataset
x = urls.get('URL', urls.get('url'))
print("Start the detection...")
pipeline = utils.load_model('iscxurls_ridgeclassifier')
y_hat = pipeline.predict(x)

urls['Label'] = y_hat
output_filename = os.path.basename(CSV_PATH)
urls.to_csv("csv/" + output_filename, index=False)

print("Number of samples:", x.shape[0])
print("RESULTS:", urls.Label.value_counts().to_dict())