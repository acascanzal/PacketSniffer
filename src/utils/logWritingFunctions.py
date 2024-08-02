import json
import multiprocessing

def writeLog(logFile, data):
    """
    Writes the Ethernet data to the log file.
    """
    json.dump(data, logFile)
    logFile.write("\n")
    logFile.flush()