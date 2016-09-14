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

def inNetwork(ip):							#Test to see if IP Address is in the network
	ipfile = file('Device List')					#Device List is the file that contains all IPs in network
	for line in ipfile:
		if ip in line:
			return True
	return False

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

for pkt in pkts:							#Here is where the packets are actually altered
	if IP in pkt:
		del pkt.chksum						#Deletes the packet's checksum. Scapy recalculates the checksum later
		
		pckstr = str(pkt)					#Creates a string of the contents of the packet. We can edit this string and later save is back as the packet
		search = pckstr.find('gourd')				#Find our marker in the packet

		if search != -1:					#If the marker is already in the packet. This means the packet is not entering the network at this node
			
			if inNetwork(pkt[IP].dst):			#Checks to see if destination IP is inside or outside the network. If the destination is within the network, it doesn't exit here.
				pckstr =+ node				#Adds the NodeID to the end of the packet string.
			
			else:						#The packet exits the network here. We need to save our route info and remove it from the packet
				route = pckstr[search:]			#The route will be everything after the marker
				pckstr = pckstr[:search]		#We rewrite the packet as everything before the marker
				routeFile.write(route)			#Record the route of the packet to file
				routeFile.write('\n')
			pkt = pkt.__class__(pckstr)			#Rewrites the packet as the string we were editing

		else:							#If the marker isn't already present, we assume it enters the network at this node
				pkt = pkt/"gourd"			#Adds the marker to the packet
				pkt = pkt/"EDGE"			#Adds the string "EDGE" to the packet
		#send(pkt)						#Sends the packet			
	

'''
		#Delete Marker on Outgoing
		if inNetwork(pkt[IP].dst):				#Checks to see if destination IP is inside or outside the network
			pkt = pkt/node					#Adds the NodeID to the end of the packet
		else:							#If the destination address is outside the network
			pkt = pkt/"EDGE"				#Add the string "EDGE" to the end of the packet
			pckstr = str(pkt)				#Creates a string of the contents of the packet. We can edit this string and later save is back as the packet
			search = pckstr.find('gourd')			#Find our marker in the packet
			if search != -1:				
				route = pckstr[search:]			#The route will be everything after the marker
				pckstr = pckstr[:search]		#We rewrite the packet as everything before the marker
				routeFile.write(route)			#Record the route of the packet to file
				routeFile.write('\n')
			pkt = pkt.__class__(pckstr)			#Rewrites the packet as the string we were editing
		
		#Create Marker on Incoming
		if inNetwork(pkt[IP].src):'
			
		else:							#If the source address is from outside the network
			pkt = pkt/"gourd"				#Adds the marker to the packet
			pkt = pkt/"EDGE"				#Adds the string "EDGE" to the packet
		
		#send(pkt)						#Sends the packet
'''

