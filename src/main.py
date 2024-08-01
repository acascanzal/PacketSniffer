#To use this script, you need to use a linux OS
import socket
from sniffer import snifferFunctions


# Create a raw socket specifying the Ipv4 protocol, adn ntohs specifies to capture all the traffic (all the transport layer protocols)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

while True:
    # Receive the packet
    unprocessedData, addr= s.recvfrom(65565)
    destMac, srcMac, prot, ipHeaderData = snifferFunctions.ethernetHeader(unprocessedData)
    ttl, prot, src, target, data = snifferFunctions.ipHeader(ipHeaderData)
    print('\n Ethernet Frame:')
    print("Destination MAC: {}, Source MAC: {}, Protocol: {}".format(destMac, srcMac, prot))
    print('\n IP Header:')
    print("TTL: {}, Protocol: {}, Source: {}, Target: {}".format(ttl, prot, src, target))

