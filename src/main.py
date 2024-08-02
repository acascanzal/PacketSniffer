#To use this script, you need to use a linux OS and run the script as root


import socket
from sniffer import snifferFunctions
from utils import printFunctions
from utils import logWritingFunctions
import multiprocessing
from concurrent.futures import ThreadPoolExecutor  # Importar ThreadPoolExecutor

# Number of producer processes to process the packets and write the logs
poolWriterNumber = 50

# Number of consumer processes to create
poolVerifierNumber = 100

#Log file
logFile = open("../logs/log.json", "w")



def packetCapture(queue):
    # Create a raw socket specifying the Ipv4 protocol, adn ntohs specifies to capture all the traffic (all the transport layer protocols)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        unprocessedData, addr= s.recvfrom(65565)
        queue.put(unprocessedData)


def principalFunction(queue,processedPackets,logFile,lock):
    
    while True:

        unprocessedData = queue.get()
        
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
                packageImportantData = {
                    "destMac": destMac,
                    "srcMac": srcMac,
                    "sourcePort": sourcePort,
                    "destPort": destPort,
                    "src": src,
                    "target": target,
                    "sequence": sequence,
                    "acknowledgment": acknowledgment,
                    "urg": urg,
                    "ack": ack,
                    "psh": psh,
                    "rst": rst,
                    "syn": syn,
                    "fin": fin,
                }
                with lock:
                    logWritingFunctions.writeLog(logFile, packageImportantData)
                processedPackets.put(packageImportantData)
            # UDP
            elif ipProt == 17:
                sourcePort, destPort, size, data = snifferFunctions.udpHeader(ipHeaderData)
                printFunctions.printUdpHeader(sourcePort, destPort, size)
                # packageImportantData = {
                #     "destMac": destMac,
                #     "srcMac": srcMac,
                #     "src": src,
                #     "target": target,
                #     "sourcePort": sourcePort,
                #     "destPort": destPort,
                #     "size": size,
                # }
                # with lock:
                #     logWritingFunctions.writeLog(logFile, packageImportantData)
                
                # processedPackets.put(packageImportantData)
                

if __name__ == "__main__":
    rawPackets = multiprocessing.Queue()
    processedPackets = multiprocessing.Queue()
    lock = multiprocessing.Lock()


    #create a process to run the principal function
    snifferProcess = multiprocessing.Process(target=packetCapture, args=(rawPackets,))
    snifferProcess.start()


    #create a pool of consumer processes
    poolWritingExecutor = ThreadPoolExecutor(max_workers=poolWriterNumber)
    for _ in range(poolWriterNumber):
        poolWritingExecutor.submit(principalFunction, rawPackets, processedPackets, logFile, lock)
    

    #create a pool of verifier processes
    # poolWritingExecutor = ThreadPoolExecutor(max_workers=poolWriterNumber)
    # for _ in range(poolWriterNumber):
    #     poolWritingExecutor.submit(principalFunction, rawPackets, processedPackets, logFile, lock)
        
    snifferProcess.join()

    for _ in range(poolWriterNumber):
        rawPackets.put(None)

    for _ in range(poolVerifierNumber):
        rawPackets.put(None)


    writerPool.close()
    writerPool.join()

    # verifierPool.close()
    # verifierPool.join()
