import socket


def getDomain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except:
        domain = ip
    return domain
