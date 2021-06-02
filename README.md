# HakTrak IDS
This is HakTrak's Intrusion Detection System against a myriad of attacks.

## Clone Repo
`git clone --recurse-submodules git@github.com:isados/haktrak-ids.git`

## Install
`pip install -r requirements.txt`

## Generate PCAP File
`sudo tcpdump -i {interface number} -w name.pcap`

## Predict on PCAP
`python3 predict.py name.pcap`


