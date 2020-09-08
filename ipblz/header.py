import struct
from ctypes import *
import socket

class UDP(Structure):
    _fields_ = [
        ("source",         c_uint16),
        ("dest",           c_uint16),
        ("len",            c_uint16),
        ("check",          c_uint16)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        self.source = socket.htons(self.source)
        self.dest = socket.htons(self.dest)
        self.len = socket.htons(self.len)
        self.check = socket.htons(self.check) # Python3.7では非推奨

class IP(Structure):
    _fields_ = [
        ("ihl",           c_uint8, 4),
        ("version",       c_uint8, 4),
        ("tos",           c_uint8),
        ("len",           c_uint16),
        ("id",            c_uint16),
        ("offset",        c_uint16),
        ("ttl",           c_uint8),
        ("protocol_num",  c_uint8),
        ("sum",           c_uint16),
        ("src",           c_uint32),
        ("dst",           c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        # ネットワークで受信したものを受け取り構造体にしている
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # この処理でIPアドレスを見やすくしている
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

class ICMP(Structure):

    _fields_ = [
        ("type",         c_uint8),
        ("code",         c_uint8),
        ("checksum",     c_uint16),
        ("unused",       c_uint16),
        ("next_hop_mtu", c_uint16)
        ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

class pcap_hdr_s(Structure):
    _fields_ = [
        ("magic_number",         c_uint32),     # /* magic number */
        ("version_major",        c_uint16),     # /* major version number */
        ("version_minor",        c_uint16),     # /* minor version number */
        ("thiszone",             c_int32),      # /* GMT to local correction */
        ("sigfigs",              c_uint32),     # /* accuracy of timestamps */
        ("snaplen",              c_uint32),     # /* max length of captured packets, in octets */
        ("network",              c_uint32)      # /* data link type*/
    ]

    def __new__(self, pcap_buffer):
        return self.from_buffer_copy(pcap_buffer)

    def __init__(self, pcap_buffer):
        pass
class pcaprec_hdr_s(Structure):
    _fields_ = [ 
        ("ts_sec",               c_uint32),        # /* timestamp seconds */
        ("ts_usec",              c_uint32),        # /* timestamp microseconds */
        ("incl_len",             c_uint32),        # /* number of octets of packet saved in file */
        ("orig_len",             c_uint32)         # /* actual length of packet */
    ]

    def __new__(self, pcap_buffer):
        return self.from_buffer_copy(pcap_buffer)

    def __init__(self, pcap_buffer):
        pass
