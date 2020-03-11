import socket
import time
from header import *

class udp: # UDP形式のパケットを送信開示する
    def __init__(self, host, sport, dport):
        self.host = host
        self.sport = sport
        self.dport = dport
        
    def checksum(self, host): # コード汚すぎませんか？
        adress = []
        d_adress = []
        hex_conversion_int = 0
        
        ip_src_dst_2ndbyte_slice = 0
        ip_src_dst_4ndbyte_slice = 0
        
        ip_src_byte_from_1_2 = 0
        ip_src_byte_from_3_4 = 0
        
        dst_ip_byte_from_1_2 = 0
        det_ip_byte_from_3_4 = 0
        
        host_adress = socket.gethostbyname(socket.gethostname()).split('.')
        dst_adress = self.host.split('.')
        for i in host_adress:
            hex_conversion_int = int(i)
            adress.append(hex(hex_conversion_int))
            for i in dst_adress:
                hex_conversion_int = int(i)
                d_adress.append(hex(hex_conversion_int)

        ip_src_dst_2ndbyte_slice = adress[1][2:4]
        ip_src_dst_4ndbyte_slice = adress[3][2:4]
        ip_src_byte_from_1_2 = adress[0] + ip_src_dst_2ndbyte_slice
        ip_src_byte_from_3_4 = adress[2] + ip_src_dst_4ndbyte_slice

        ip_src_dst_2ndbyte_slice = d_adress[1][2:4]
        ip_src_dst_4ndbyte_slice = d_adress[3][2:4]
        dst_ip_byte_from_1_2 = d_adress[0] + ip_src_dst_2ndbyte_slice
        dst_ip_byte_from_3_4 = d_adress[2] + ip_src_dst_4ndbyte_slice
        print(hex(int(ip_src_byte_from_1_2, base = 16) + int(ip_src_byte_from_3_4, base = 16) + int(dst_ip_byte_from_1_2, base = 16) + int(dst_ip_byte_from_3_4, base = 16)))



    def send(self): # 未完成
        try:
            src_port = self.sport.to_bytes(2, 'big')
            dst_port = self.dport.to_bytes(2, 'big')
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

            sock.sendto(b'%b%b\x00\x3a\x35\x8f' % (src_port, dstport) + bytes(50), (self.host, 0))

            sock.settimeout(5)

            data = sock.recvfrom(255)[0]

            ip_header = IP(data[0:20])

            offset = ip_header.ihl * 4

            buf = data[offset:offset + sizeof(UDP)]

            udp_header = UDP(buf)
            
            print("* -- UDP HEADER -- *")       
            print("src_port = {}".format(udp_header.source)) 
            print("dest_port = {}".format(udp_header.dest))
            print("len = {}".format(udp_header.len))
            print("check_sum = {}".format(hex(udp_header.check)))

        except socket.timeout:
            print("タイムアウト")

class ping: # PINGは男の嗜み
     def __init__(self, host, numbertimes):
        self.host = host
        self.numbertimes = numbertimes
    def send(self):
        request = 0
        reply = 0
        try:
            while True:
                request += 1

                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # rawソケットに変えているのでpingを実行する場合管理者権限が必要になる

                sock.sendto(b'\x08\x00\xf7\xff\x00\x00\x00\x00',(self.host, 0)) # 迫真チェックサム計算部を忘れずに

                time.sleep(1)

                sock.settimeout(60)
                # 構造体にはめていく
                echoreply = sock.recvfrom(255)[0]

                ip_header = IP(echoreply[0:20])

                offset = ip_header.ihl * 4

                buf = echoreply[offset:offset + sizeof(ICMP)]

                icmp_header = ICMP(buf)
                
                # echoreplyのtypeは0
                if icmp_header.type == 0:
                    reply += 1
                    print("{} = {} done TTL = {}".format(self.host, ip_header.src_address, ip_header.ttl))
                if request == self.numbertimes: # 指定した回数とrequestが同じになればbreak
                    print("{} = {} ping total".format(self.host, ip_header.src_address))
                    print("送信した回数 = {} 受信した回数 = {}".format(request, reply))
                    break
        except KeyboardInterrupt: # Ctrl-Cでキャンセル
            print("Ctrl-C")
            print("送信した回数 = {} 受信した回数 = {}".format(request, reply))
        except socket.timeout: # タイムアウト処理 60秒経過でタイムアウトとなる
            print("エラーです。タイムアウト")
           
class traceroute: # 行く道は一つ
    def scan(self): # 未完成
        host = socket.gethostbyname(socket.gethostname())
        count = 0
        judge_count = 0
        sock_icmp__protocol = socket.IPPROTO_ICMP

        terce_scan = socket.socket(socket.AF_INET, socket.SOCK_RAW, sock_icmp__protocol)

        terce_scan.bind((host, 0)) 
        terce_scan.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == "nt":
            terce_scan.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        try:
            while True:
                data = terce_scan.recvfrom(65565)[0]
                # IP構造体を作成
                ip_header = IP(data[0:20])
                # ihlフィールドに基づいて計算。
                offset = ip_header.ihl * 4
                # IPヘッダのサイズとICMPヘッダのサイズを計算してICMPヘッダの位置を知り、構造体に入れることに成功している。
                buf = data[offset:offset + sizeof(ICMP)]

                # ICMP構造体を作成
                icmp_header = ICMP(buf)

                # 元のtracerouteを基準に
                if icmp_header.type == 11 and icmp_header.code == 0:
                    judge_count += 1
                    if judge_count == 3: # 誰かいい書き方を教えてください,ここで3を基準にしているのは飛んできたTimeExceededが3つあるので重複するため
                        count += 1
                        print("{}:{}".format(count,ip_header.src_address))
                        judge_count = 0
                    
                    
        except KeyboardInterrupt: # Ctrl-C
            print("Ctrl-C")

        # Windowsの場合はプロミスキャスモードを無効
        if os.name == "nt":
            terce_scan.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
