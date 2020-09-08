import socket
import time
import os
from header import *

class udp: # UDP形式のパケットを送信開示する
    def __init__(self, host, sport, dport):
        self.host = host
        self.sport = sport
        self.dport = dport
        
    def send(self): # 未完成　チェックサム計算雑すぎる
        try:
            adress = []
            d_adress = []
            hex_conversion_int = 0
        
            ip_src_dst_2ndbyte_slice = 0
            ip_src_dst_4ndbyte_slice = 0
        
            ip_src_byte_from_1_2 = 0
            ip_src_byte_from_3_4 = 0
        
            dst_ip_byte_from_1_2 = 0
            dst_ip_byte_from_3_4 = 0

            ipaddr_sum = 0
            ip_header_udp_sum = 0
            take_out_1byte = 0
            byte_sum = 0
            bin_len = 0
            bin_subtraction = 0

            complement = 0
            complement_byte = b'\x00\x00'

            if self.checksum == "Yes":
                host_adress = socket.gethostbyname_ex(socket.gethostname())[2][1].split('.')
                dst_adress = self.host.split('.')

                for i in host_adress:
                    hex_conversion_int = int(i)
                    adress.append(hex(hex_conversion_int))
                for i in dst_adress:
                    hex_conversion_int = int(i)
                    d_adress.append(hex(hex_conversion_int))

                ip_src_dst_2ndbyte_slice = adress[1][2:4]
                ip_src_dst_4ndbyte_slice = adress[3][2:4]
                ip_src_byte_from_1_2 = adress[0] + ip_src_dst_2ndbyte_slice
                ip_src_byte_from_3_4 = adress[2] + ip_src_dst_4ndbyte_slice

                ip_src_dst_2ndbyte_slice = d_adress[1][2:4]
                ip_src_dst_4ndbyte_slice = d_adress[3][2:4]
                dst_ip_byte_from_1_2 = d_adress[0] + ip_src_dst_2ndbyte_slice
                dst_ip_byte_from_3_4 = d_adress[2] + ip_src_dst_4ndbyte_slice
                ipaddr_sum = int(ip_src_byte_from_1_2, base = 16) + int(ip_src_byte_from_3_4, base = 16) + int(dst_ip_byte_from_1_2, base = 16) + int(dst_ip_byte_from_3_4, base = 16)
                ip_header_udp_sum = ipaddr_sum + 0x0011 + 0x003a + self.sport + self.dport + 0x003a
                take_out_1byte = bin(ip_header_udp_sum & 0b01111111111111111)
                byte_sum = int(take_out_1byte, base = 2) +  0b1
                bin_len = len(bin(byte_sum)) - 2
                bin_subtraction = 2**bin_len - 1
                complement = bin_subtraction - byte_sum
                complement_byte = complement.to_bytes(2, 'big')

            else:
                pass
            
            src_port = self.sport.to_bytes(2, 'big')
            dst_port = self.dport.to_bytes(2, 'big')
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

            sock.sendto(b'%b%b\x00\x3a%b' % (src_port, dst_port, complement_byte) + bytes(50), (self.host, 0))

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
           
class pacapch:
    def __init__(self, scannumber):
        self.scannumber = scannumber

    def scan(self): 
        count = 0
        host = socket.gethostbyname_ex(socket.gethostname())[2][1]
        scan = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        scan.bind((host, 0)) 
        scan.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == "nt":
            scan.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        try:
            while True:
                count += 1
                data = scan.recvfrom(65565)[0]
                
                ip_header = IP(data[0:20])

                print("{}: IHL = {} version = {} tos = {} len = {} id = {} offset = {} TTL = {} protocol = {} checksum = {} src = {} dst = {}".format(count, ip_header.ihl, ip_header.version, ip_header.tos, ip_header.len, 
                ip_header.id, ip_header.offset, ip_header.ttl, ip_header.protocol, ip_header.sum, ip_header.src_address, ip_header.dst_address))             
                if count == self.scannumber:
                    scan.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    print("{}回のスキャン完了".format(count))
                    break
                    
        except KeyboardInterrupt: # Ctrl-C
            print("Ctrl-C")
            scan.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
class pcapparser:
    def __init__(self, filesource):
        self.filesource = filesource

    def parse(self):
        with open(self.filesource, mode='rb') as f:
            pcapfile = f.read()
        pcapfilehdr = pcap_hdr_s(pcapfile[0:24])
        pcaprecfile = pcaprec_hdr_s(pcapfile[24:4])

        print(hex(pcapfilehdr.magic_number))
        print(hex(pcaprecfile.ts_sec))
