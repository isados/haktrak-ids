import subprocess
from os import path, listdir
script_path = "TCPDUMP_and_CICFlowMeter/convert_pcap_csv.sh"
pcap_folder = path.abspath("pcap")
csv_folder = path.abspath("csv")

for file in listdir(pcap_folder):
	return_code = subprocess.run([script_path, path.join(pcap_folder, file), csv_folder])
	print(return_code)