import socket
import fcntl
import struct
import binascii

from scapy.all import *
from scapy.utils import rdpcap
from scapy.layers.inet import IP


def get_ip_address(ifname):						#Get IP Address
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def get_node_id(ip):							#Gets the NodeID of this node from the list of NodeIDs
	with open("Device List") as deviceList:
		for i, line in enumerate(deviceList,1):
			if ip in line:
				deviceList.close
				return i

pkts=rdpcap("FILE2.pcap")						#Seeks packets in a PCAP file. This will need to be replaced to be able to do this 'live'
ip = get_ip_address('eth0')						#Gets IP of network device executing the code
node = hex((get_node_id(ip)))[2:].zfill(2)				#Gets the NodeID
routeFile = open('Routes','w')						#Creates a file to record all the routes of packets exiting the network or ending at this node


for pkt in pkts:
	if IP in pkt:
		del pkt.chksum						#Deletes the packet's checksum. Scapy recalculates the checksum later
		#Add Marker at Source
		if pkt[IP].src == ip:					#If the packet originated at this node
			pkt = pkt/"gourd"				#Add the marker
			pkt = pkt/node					#Also add the NodeID
		#Add Node Number
		pkt = pkt/node						#If the packet is just passing through this node, add the NodeID
		#Delete Marker at Destination
		if pkt[IP].dst  == ip:					#If the packet's destination is this node
			pckstr = str(pkt)				#Create a edit-able string from the packet
			search = pckstr.find('gourd')			#Find the marker
			if search != -1:
				route = pckstr[search:]			#The route will be everything after the marker
				pckstr = pckstr[:search]		#We rewrite the packet as everything before the marker
				routeFile.write(route)			#Record the route of the packet to file
				routeFile.write('\n')
			pkt = pkt.__class__(pckstr)			#Rewrites the packet as the string we were editing
	#send(pkt)							#Sends the packet
