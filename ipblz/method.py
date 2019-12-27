import socket
import time
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
    def __init__(self, ip, numbertimes):
        self.ip = ip
        self.numbertimes = numbertimes
    def send(self):
        request = 0
        reply = 0
        try:
            while True:
                request += 1
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # rawソケットに変えているのでpingを実行する場合管理者権限が必要になる
                time.sleep(1)
                sock.sendto(b'\x08\x00\xf7\xff\x00\x00\x00\x00',(self.ip, 0)) # チェックサム計算を忘れずに
                echoreply = sock.recv(255)
                if echoreply[20] == 0: # 返ってきたEchoReplyのTypeを見ている
                    reply += 1
                    print("{} done".format(self.ip))
                if request == self.numbertimes: # 指定した回数とrequestが同じになればbreak
                    print("送信した回数 = {} 受信した回数 = {}".format(request, reply))
                    break
        except KeyboardInterrupt: # Ctrl-Cでキャンセル
            print("Ctrl-C")
            print("送信した回数 = {} 受信した回数 = {}".format(request, reply))
