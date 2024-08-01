from struct import * 
import sys
import socket

# Function to unpack the Ethernet frame
def ethernetHeader(unprocessedData):
    # Unpack the Ethernet frame in big-endian, the first 14 bytes ( 6 bytes Destination MAC, 6 bytes Source MAC, 2 bytes Protocol)
    destMac, srcMac, prot = unpack("! 6s 6s H", unprocessedData[:14])
    return getMacAddress(destMac), getMacAddress(srcMac), socket.htons(prot), unprocessedData[14:]

# Function to get the MAC address
def getMacAddress(mac):
    # Convert the MAC address from bytes to a readable string
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])

# Function to unpack the IP header
def ipHeader(unprocessedData):
    versionAndHeaderLength = unprocessedData[0]
    version = versionAndHeaderLength >> 4
    headerLength = (versionAndHeaderLength & 15) * 4 # Multiply by 4 because the header length is the number of 32 bits sended (being 20 bytes the minimum and 60 bytes the maximum)
    ttl, prot, src, target = unpack("! 8x B B 2x 4s 4s", unprocessedData[:20])
    return ttl, prot, getIpAddress(src), getIpAddress(target), unprocessedData[headerLength:]

# Function to get the IP address
def getIpAddress(ip):
    # Convert the IP address from bytes to a readable string
    return ".".join(map(str, ip))

# Function to unpack the ICMP header
def icmpHeader(unprocessedData):
    icmpType, code, checksum = unpack("! B B H", unprocessedData[:4])
    return icmpType, code, checksum, unprocessedData[4:]

# Function to unpack the TCP header
def tcpHeader(unprocessedData):
    sourcePort, destPort, sequence, acknowledgment, offsetAndFlags = unpack("! H H L L H", unprocessedData[:12])
    offset = (offsetAndFlags >> 12) * 4
    urg = (offsetAndFlags & 32) >> 5
    ack = (offsetAndFlags & 16) >> 4
    psh = (offsetAndFlags & 8) >> 3
    rst = (offsetAndFlags & 4) >> 2
    syn = (offsetAndFlags & 2) >> 1
    fin = offsetAndFlags & 1
    return sourcePort, destPort, sequence, acknowledgment, urg, ack, psh, rst, syn, fin, unprocessedData[offset:]