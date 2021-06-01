import subprocess
from os import path, listdir
script_path = "TCPDUMP_and_CICFlowMeter/convert_pcap_csv.sh"
folder_path = path.abspath(path.dirname(script_path))
pcap_path = path.join(folder_path, "pcap")

for file in listdir(pcap_path):
	return_code = subprocess.run([script_path, path.join(pcap_path, file), "."])
	print(return_code)