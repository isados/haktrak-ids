#!/usr/bin/env python3

import os
from datetime import datetime
from typing import Callable, Any, IO

from scapy.all import IP
from scapy.all import sniff
from scapy.layers import http
import tempfile


def UrlFileHandler(file: IO[str]) -> "Callable[[Any], None]":
	def url_sniffer(packet) -> None:
		if packet.haslayer(http.HTTPRequest):
			http_layer = packet.getlayer(http.HTTPRequest)
			ip_layer = packet.getlayer(IP)

			src_ip: str = ip_layer.fields['src']
			method: str = http_layer.fields['Method'].decode('utf-8')
			host: str = http_layer.fields['Host'].decode('utf-8')
			path: str = http_layer.fields['Path'].decode('utf-8')
			timestamp: str = datetime.now().astimezone().isoformat(timespec='microseconds')

			# Print out URL details
			# print(f'\n{timestamp} : {src_ip} — {method} — http://{host}{path}')

			# Write to csv
			data: str =f'{timestamp},http://{host}{path}\n'
			file.write(data)
		return None
	return url_sniffer
		
if __name__ == '__main__':
	try:
		DEST_FOLDER: str = 'csv/sniffed_urls'
		if os.path.exists(DEST_FOLDER) is False:
			os.makedirs(DEST_FOLDER)

		with tempfile.NamedTemporaryFile(mode='w', dir=DEST_FOLDER, prefix='urls-',
						 suffix='.csv', delete=False) as file:
			file.write("timestamp,url\n")
			print("Currently sniffing. you may browse any site... press CTRL + C to exit")
			sniff(filter='tcp', prn=UrlFileHandler(file))

	except PermissionError as perror:
		print("Permission Error: run this file as root user")
	else:
		print(f"\nCSV stored as {os.path.relpath(file.name)}")
		userid: str = str(os.getenv('SUDO_UID'))
		groupid: str = str(os.getenv('SUDO_GID'))
		os.chown(file.name, int(userid), int(groupid))