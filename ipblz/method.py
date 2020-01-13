import socket
import time

class portscan: # ポートスキャナー TCP UDP TCP/SYN スキャンを実装(予定)
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

class ping: # PINGは男の嗜み
    def __init__(self, ip, numbertimes, ttl):
        self.ip = ip
        self.numbertimes = numbertimes
        self.ttl = ttl
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
                sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl) # 指定されたTTLをセットしている
                echoreply = sock.recv(255)
                if echoreply[20] == 0: # 返ってきたEchoReplyのTypeを見ている
                    reply += 1
                    print("TTL {} {} done".format(self.ttl, self.ip))
                if request == self.numbertimes: # 指定した回数とrequestが同じになればbreak
                    print("送信した回数 = {} 受信した回数 = {}".format(request, reply))
                    break
        except KeyboardInterrupt: # Ctrl-Cでキャンセル
            print("Ctrl-C")
            print("送信した回数 = {} 受信した回数 = {}".format(request, reply))
        except socket.timeout: # タイムアウト処理 60秒経過でタイムアウトとなる
            print("エラーです。タイムアウト")
            
class sniffer: # 悪用厳禁
    def __init__(self, protocolselect):
        self.protocolselect = protocolselect

    def scan(self): # IP ICMPのヘッダを含んだものをキャプチャする 
        host = socket.gethostbyname(socket.gethostname())
        
        if self.protocolselect == "IP": # プロトコル選択 
            protocol = socket.IPPROTO_IP
        if self.protocolselect == "ICMP":
            protocol = socket.IPPROTO_ICMP

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
        sock.bind((host, 0)) # ホストIPと結びつけ
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == "nt": # Windowsの判定
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) # 第二引数でプロミスキャスモードをON
 
        scandata = sock.recvfrom(65565)
        print("指定したプロトコル{} \n IP:{}: \n データ{}".format(self.protocolselect ,scandata[1][0], scandata[0]))
 
        if os.name == "nt":
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) # OFFにしている
