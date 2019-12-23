import socket

class Dns: # DNS（これいる？）
    def __init__(self, hostname):
        self.hostname = hostname

    def dnsipback(self):
        ipconversion = socket.gethostbyname(self.hostname) # str型で取ってる
        print(ipconversion)

class PortScan: # ポートスキャナー TCP UDP TCP/SYN スキャンを実装(予定)
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def tcpscan(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        code = sock.connect_ex((self.ip, self.port)) # ipはstr型を取ります。portはintで
        if code == 0: # connect_exは返信が返ってきた場合0を返します。よってこの条件式
            print("{}/tcp Open".format(self.port))
        else:
            print("{}/tcp Close".format(self.port))