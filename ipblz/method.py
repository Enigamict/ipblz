import socket
import time
from header import *

class portscan: # ポートスキャナー
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
            
    def udpscan(self): # UDP がばい
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.getprotobyname('udp'))
            sock.bind(("", self.port))
            sock.sendto(bytes(1024), (self.ip, self.port))
            sock.settimeout(5)
            data = sock.recv(1024)
            if data != None:
                print("{}/udp Open".format(self.port))
        except socket.timeout:
            print("{}/udp Close".format(self.port))


class ping: # PINGは男の嗜み
    def __init__(self, host, numbertimes):
        self.ip = host
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
                sock.settimeout(60)
                echoreply = sock.recv(255)
                if echoreply[20] == 0: # 返ってきたEchoReplyのTypeを見ている
                    reply += 1
                    print("{} done".format(self.host))
                if request == self.numbertimes: # 指定した回数とrequestが同じになればbreak
                    print("送信した回数 = {} 受信した回数 = {}".format(request, reply))
                    break
        except KeyboardInterrupt: # Ctrl-Cでキャンセル
            print("Ctrl-C")
            print("送信した回数 = {} 受信した回数 = {}".format(request, reply))
        except socket.timeout: # タイムアウト処理 60秒経過でタイムアウトとなる
            print("エラーです。タイムアウト")
           
class traceroute: # 行く道は一つ
    def scan(self): # 未完成,まだ関係するパケットしか拾えない
        host = socket.gethostbyname(socket.gethostname())
        sock_icmp__protocol = socket.IPPROTO_ICMP

        terce_scan = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_icmp__protocol)

        terce_scan.bind((host, 0)) 
        terce_scan.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == "nt":
            terce_scan.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while True:
            data = terce_scan.recvfrom(65565)[0]
            # IP構造体を作成
            ip_header = IP(data[0:20])
            # ihlフィールドに基づいて計算。
            offset = ip_header.ihl * 4
            buf = data[offset:offset + sizeof(ICMP)]　# IPヘッダのサイズとICMPヘッダのサイズを計算してICMPヘッダの位置を知り、構造体に入れることに成功している。

            # ICMP構造体を作成
            icmp_header = ICMP(buf)

            # 元のtracerouteを基準に
            if icmp_header.type == 11 and icmp_header.code == 0:

                print("{},{}".format(ip_header.src_address, ip_header.dst_address))


        # Windowsの場合はプロミスキャスモードを無効
        if os.name == "nt":
            terce_scan.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
