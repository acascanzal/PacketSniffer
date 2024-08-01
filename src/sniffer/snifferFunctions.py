from struct import * 
import sys
import socket


def ethernetHeader(unprocessedData):
    # Unpack the Ethernet frame in big-endian, the first 14 bytes ( 6 bytes Destination MAC, 6 bytes Source MAC, 2 bytes Protocol)
    destMac, srcMac, prot = unpack("! 6s 6s H", unprocessedData[:14])
    return getMacAddress(destMac), getMacAddress(srcMac), socket.htons(prot), unprocessedData[14:]

def getMacAddress(mac):
    # Convert the MAC address from bytes to a readable string
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])