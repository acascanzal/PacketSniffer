#To use this script, you need to use a linux OS
import socket
from sniffer import snifferFunctions
from utils import printFunctions


# Create a raw socket specifying the Ipv4 protocol, adn ntohs specifies to capture all the traffic (all the transport layer protocols)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

while True:
    # Receive the packet
    unprocessedData, addr= s.recvfrom(65565)
    destMac, srcMac, ethProt, ethernetHeaderData = snifferFunctions.ethernetHeader(unprocessedData)
    
    printFunctions.printEthernetFrame(destMac, srcMac, ethProt)

    # Ipv4
    if ethProt == 8:
        ttl, ipProt, src, target, ipHeaderData = snifferFunctions.ipHeader(ethernetHeaderData)
        printFunctions.printIpHeader(ttl, ipProt, src, target)

        # ICMP
        if ipProt == 1:
            icmpType, code, checksum, data = snifferFunctions.icmpHeader(ipHeaderData)
            printFunctions.printIcmpHeader(icmpType, code, checksum)

        # TCP
        elif ipProt == 6:
            sourcePort, destPort, sequence, acknowledgment, urg, ack, psh, rst, syn, fin, data = snifferFunctions.tcpHeader(ipHeaderData)
            printFunctions.printTcpHeader(sourcePort, destPort, sequence, acknowledgment, urg, ack, psh, rst, syn, fin)

        # UDP
        elif ipProt == 17:
            sourcePort, destPort, size, data = snifferFunctions.udpHeader(ipHeaderData)
            printFunctions.printUdpHeader(sourcePort, destPort, size)

        #other
        #else:

    #else:




