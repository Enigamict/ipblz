import socket

class dnshost:
    def __init__(self, ip):
        self.ip = ip

    def dnsipback(self):
        ipconversion = socket.gethostbyname(self.ip)
        print(ipconversion)