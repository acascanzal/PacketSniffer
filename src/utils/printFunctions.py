oneTab = "\t\t\t"
twoTabs = "\t\t\t\t"
threeTabs = "\t\t\t\t\t"
newFrame = "\n\n\n\n\n"
def printEthernetFrame(destMac, srcMac, ethProt):
    print(newFrame+'Ethernet Frame:')
    print(oneTab+"-Destination MAC: {}, Source MAC: {}, Ethernet Protocol: {}".format(destMac, srcMac, ethProt))

def printIpHeader(ttl, ipProt, src, target):
    print(oneTab+'-IP Header:')
    print(twoTabs+"-TTL: {}, IP Protocol: {}".format(ttl, ipProt))
    print(twoTabs+"-Source: {}, Target: {}".format(src, target))

def printIcmpHeader(icmpType, code, checksum):
    print(oneTab+'-ICMP Header:')
    print(twoTabs+"-Type: {}".format(icmpType))
    print(twoTabs+"-Code: {}".format(code))
    print(twoTabs+"-Checksum: {}".format(checksum))


def printTcpHeader(sourcePort, destPort, sequence, acknowledgment, urg, ack, psh, rst, syn, fin):
    print(oneTab+'-TCP Header:')
    print(twoTabs+"-Source Port: {}, Destination Port: {}".format(sourcePort, destPort))
    print(twoTabs+"-Sequence: {}, Acknowledgment: {}".format(sequence, acknowledgment))
    print(twoTabs+"-Flags:")
    print(threeTabs+"-URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(urg, ack, psh, rst, syn, fin))

def printUdpHeader(sourcePort, destPort, size):
    print(oneTab+'-UDP Header:')
    print(twoTabs+"-Source Port: {}, Destination Port: {}".format(sourcePort, destPort))
    print(twoTabs+"-Size: {}".format(size))
