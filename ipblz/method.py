import socket

class Dns: # DNS（これいる？）
    def __init__(self, hostname):
        self.hostname = hostname

    def dnsipback(self):
        ipconversion = socket.gethostbyname(self.hostname) # str型で取ってる
        print(ipconversion)

class Portscan: # ポートスキャナー TCP UDP TCP/SYN スキャンを実装(予定)
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def tcpscan(self): # TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        code = sock.connect_ex((self.ip, self.port)) # ipはstr型を取ります。portはintで
        if code == 0: # connect_exは返信が返ってきた場合0を返します。よってこの条件式
            print("{}/tcp Open".format(self.port))
        else:
            print("{}/tcp Close".format(self.port))

class Ping: # PINGは男の嗜み
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
    def ping(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # rawソケットに変えているのでpingを実行する場合管理者権限が必要になる
        sock.sendto(b'\x08\x00\xf7\xff\x00\x00\x00\x00', (self.ip, self.port)) # 迫真チェックサム計算部を忘れずに

        data = sock.recv(255)

        print(data)
           
