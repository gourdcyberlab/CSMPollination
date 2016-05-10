import socket
import fcntl
import struct
import binascii

from scapy.all import *
from scapy.utils import rdpcap
from scapy.layers.inet import IP

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def inNetwork(ip):
	ipfile = file('Device List')
	for line in ipfile:
		if ip in line:
			return True
	return False

pkts=rdpcap("FILE2.pcap")
ip = get_ip_address('eth0')
routeFile = open('Routes','w')

for pkt in pkts:
	if IP in pkt:
		del pkt.chksum
		
		#Delete Marker on Outgoing
		if inNetwork(pkt[IP].dst):
			pkt = pkt/"EDGE"
			pckstr = str(pkt)
			search = pckstr.find('gourd')
			if search != -1:
				route = pckstr[search:]
				pckstr = pckstr[:search]
				#Record the route of the packet to file
				routeFile.write(route)
				routeFile.write('\n')
			pkt = pkt.__class__(pckstr)
		
		#Create Marker on Incoming
		if inNetwork(pkt[IP].src):
			pkt = pkt/"gourd"
			pkt = pkt/"EDGE"
		
		#send(pkt)

