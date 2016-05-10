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

def get_node_id(ip):
	with open("Device List") as deviceList:
		for i, line in enumerate(deviceList,1):
			if ip in line:
				deviceList.close
				return i

pkts=rdpcap("FILE2.pcap")
ip = get_ip_address('eth0')
node = hex((get_node_id(ip)))[2:].zfill(2)
routeFile = open('Routes','w')


for pkt in pkts:
	if IP in pkt:
		del pkt.chksum
		#Add Marker at Source
		if pkt[IP].src == ip:
			pkt = pkt/"gourd"
		#Add Node Number
		pkt = pkt/node
		#Delete Marker at Destination
		if pkt[IP].dst  == ip:
			pckstr = str(pkt)
			search = pckstr.find('gourd')
			if search != -1:
				route = pckstr[search:]
				pckstr = pckstr[:search]
				#Record the route of the packet to file
				routeFile.write(route)
				routeFile.write('\n')
			pkt = pkt.__class__(pckstr)
	#send(pkt)
