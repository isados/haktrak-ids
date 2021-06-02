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
~> pipenv sync
```

## Generate PCAP file [OPTIONAL]
```
~> sudo tcpdump -i {interface number} -w {path_to_pcap}
```

## Predict on PCAP
```
~> pipenv run python3 predict.py {path_to_pcap}
```