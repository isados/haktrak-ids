# HakTrak IDS
This is HakTrak's Intrusion Detection System against a myriad of attacks.

---
## Install Dependencies

[Git-LFS](https://git-lfs.github.com/) :- For managing large files; which in this case includes pickeled models. Just follow the steps at the link provided.

Pipenv :- run this command `pip install --user pipenv` to install it.

## Clone this repo
```
~> git clone --recurse-submodules git@github.com:isados/haktrak-ids.git
```

## Installation
```
~> cd haktrak-ids
~> cp example-config.yml config.yml
```
Make necessary changes to the config file and save it.
```
~> pipenv sync
```
Note : Always run the above command after pulling the latest commit from this repo

## Generate PCAP file [OPTIONAL]
This is a step needed for most prediction scripts (excluding malicious urls for now).

Here the PCAP filename could be anything you desire.
```
~> sudo tcpdump -i {interface number} -w test.pcap
```

## Prediction Scripts
For most attacks (using PCAP as input):
```
~> pipenv run ./predictDDoS.py test.pcap
```
For Malicious URL attacks (using CSV as input)
```
~> pipenv run ./predictMaliciousUrls.py test.csv
```

## Sniffing URLs
The following script stores sniffed urls as records in a CSV
```bash
sudo ./sniff-urls.py
```
###### Ensure that the CSV has a single field called `urls`

---
## Reference
[CIC-IDS 2018]("https://www.unb.ca/cic/datasets/ids-2018.html") : For description of the dataset and its fields.