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

## Generate PCAP file [OPTIONAL]
Here the PCAP name could be anything you desire.
```
~> sudo tcpdump -i {interface number} -w test.pcap
```

## Predict on PCAP on DDoS Attacks (more coming soon...)
```
~> pipenv run ./predictDDoS.py test.pcap
```

# Reference
[CIC-IDS 2018]("https://www.unb.ca/cic/datasets/ids-2018.html") : For description of the dataset and its fields.