import socket
import fcntl
import struct

from scapy.all import *
from scapy.utils import rdpcap

NODE = ""

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

pkts=rdpcap("FILE2.pcap")
ip = get_ip_address('eth0')

for pkt in pkts:
	if IP in pkt:
		print pkt.summary()
		#Add Marker at Source
		if pkt[IP].src == ip:
			pkt = pkt/"gourd"
		#Add Node Number
		pkt = pkt/NODE
		#Delete Marker at Destination
		if pkt[IP].src == ip:
			pckstr = str(pkt)
			search = pckstr.find('gourd')
			if search != -1:
				route = pckstr[search:]
				pckstr = pckstr[:search]
				
	

