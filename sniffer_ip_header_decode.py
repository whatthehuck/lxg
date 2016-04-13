import socket
import threading
from multiprocessing import Process
from Tkinter import *
import os
import struct
from ctypes import *

host = "192.168.1.109"

def reverse(hex_str):
    #print 'hex:', hex_str
    hex_str = hex(hex_str)
    #print hex_str
    l = []
    temp = ''
    for i in range(0, len(hex_str), 2):
        l.append(hex_str[i:i + 2])
    
    for j in range(len(l)):
        temp = temp + l[-j]

    return temp
#---------------------------------------------------------------
class ICMP(Structure):
    _fields_ = [
        ("version", c_ubyte),
        ("service_field", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("flags", c_ubyte),
        ("offset", c_ubyte),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte, 2),
        ("checksum", c_ushort),
        ("src", c_uint, 32),
        ("dst", c_uint, 32)
    ]
    def __new__(self, socket_buffer = None):
        return_buffer = self.from_buffer_copy(socket_buffer)
        return return_buffer
    def __init__(self, socket_buffer = None):
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        print 'version:', reverse(self.version)
        print 'service_field:', reverse(self.service_field)
        print 'length:', reverse(self.len)
        print 'id:', reverse(self.id)
        print 'flags:', reverse(self.flags)
        print 'offset:', reverse(self.offset)
        print 'ttl:', reverse(self.ttl)
        print 'protocol num:', reverse(self.protocol_num)
        print 'checksum:', reverse(self.checksum)
        print 'destination address', reverse(self.src)
        print 'source address', reverse(self.dst)
        
        self.src_address = socket.inet_ntoa(struct.pack("L", self.src)[0:4])
        self.dst_address = socket.inet_ntoa(struct.pack("L", self.dst)[0:4])
        
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)
#---------------------------------------------------------------

class TCP(Structure):
    _fields_ = [
        ('version', c_ubyte),
        ('service_field', c_ubyte),
        ('total_length', c_ushort),
        ('id', c_ushort),
        ('flags', c_ubyte),
        ('offset', c_ubyte),
        ('ttl', c_ubyte),
        ('protocol', c_ubyte),
        ('ch', c_ushort),
        ('src', c_uint, 32),
        ('dst', c_uint, 32),
        ('src_port', c_ushort),
        ('dst_port', c_ushort),
        ('seq', c_uint, 32),
        ('ack', c_uint, 32),
        ('h_len', c_ubyte),
        ('flag', c_ushort),
        ('winsize', c_ushort),
        ('checksum', c_ushort),
        ('u_point', c_ushort)
    ]

    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer):

        ip_src = socket.inet_ntoa(struct.pack('L', self.src)[0:4])
        ip_dst = socket.inet_ntoa(struct.pack('L', self.dst)[0:4])

        print 'version', reverse(self.version)
        print 'service_field', reverse(self.service_field)
        print 'total_length', reverse(self.total_length)
        print 'id', reverse(self.id)
        print 'flags', reverse(self.flags)
        print 'offset', reverse(self.offset)
        print 'ttl', reverse(self.ttl)
        print 'protocol', reverse(self.protocol)
        print 'ch', reverse(self.ch)
        print 'src', ip_src
        print 'dst', ip_dst
        print 'src_port', reverse(self.src_port)
        print 'dst_port', reverse(self.dst_port)
        print 'seqnum', reverse(self.seq)
        print 'acknum', reverse(self.ack)
        print 'len', reverse(self.h_len)
        print 'syn', reverse(self.flag)
        print 'WindowSize', reverse(self.winsize)
        print 'checksum', reverse(self.checksum)
        print 'urgent_point', reverse(self.u_point)
#----------------------------END-------------------------------
#----------------------------UDP-------------------------------
class UDP(Structure):
    _fields_ = [
        ('version', c_ubyte),
        ('service_field', c_ubyte),
        ('total_length', c_ushort),
        ('id', c_ushort),
        ('flags', c_ubyte),
        ('offset', c_ubyte),
        ('ttl', c_ubyte),
        ('protocol', c_ubyte),
        ('h_checksum', c_ushort),
        ('src', c_uint, 32),
        ('dst', c_uint, 32),
        ('src_port', c_ushort),
        ('dst_port', c_ushort),
        ('length', c_ushort),
        ('checksum', c_ushort)
    ]
    
    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer = None):
        src_ip = socket.inet_ntoa(struct.pack('L', self.src)[0:4])
        dst_ip = socket.inet_ntoa(struct.pack('L', self.dst)[0:4])
        print 'version:', reverse(self.version)
        print 'service_field:', reverse(self.service_field)
        print 'total_length:', reverse(self.total_length)
        print 'id:', reverse(self.id)
        print 'flags:', reverse(self.flags)
        print 'offset:', reverse(self.offset)
        print 'ttl:', reverse(self.ttl)
        print 'protocol:', reverse(self.protocol)
        print 'h_checksum:', reverse(self.h_checksum)
        print 'src:', src_ip
        print 'dst:', dst_ip
        print 'src_port:', reverse(self.src_port)
        print 'dst_port:', reverse(self.dst_port)
        print 'length:', reverse(self.length)
        print 'checksum:', reverse(self.checksum)
#------------------------END-----------------------------------

#------------------------IGMP----------------------------------
class IGMP(Structure):
    _fields_ = [
        ('version', c_ubyte),
        ('service_field', c_ubyte),
        ('total_length', c_ushort),
        ('id', c_ushort),
        ('flags', c_ubyte),
        ('offset', c_ubyte),
        ('ttl', c_ubyte),
        ('protocol', c_ubyte),
        ('h_checksum', c_ushort),
        ('src', c_uint, 32),
        ('dst', c_uint, 32),
        ('options', c_uint, 32)
    ]

    def __new__(self, socket_buffer = None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer = None):
        src_ip = socket.inet_ntoa(struct.pack('L', self.src)[0:4])
        dst_ip = socket.inet_ntoa(struct.pack('L', self.dst)[0:4])
        
        print 'version:', reverse(self.version)
        print 'service_field:', reverse(self.service_field)
        print 'total_length:', reverse(self.total_length)
        print 'id:', reverse(self.id)
        print 'flags:', reverse(self.flags)
        print 'offset:', reverse(self.offset)
        print 'ttl:', reverse(self.ttl)
        print 'protocol:', reverse(self.protocol)
        print 'h_checksum:', reverse(self.h_checksum)
        print 'src:', src_ip
        print 'dst:', dst_ip
        print 'options:', reverse(self.options)
#------------------------END-----------------------------------

#------------------------ICMP----------------------------------
def icmp():
    if os.name == "nt":
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

#sniffer.bind((host, 0))
#sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
            print raw_buffer.encode("hex")
            ip_header = ICMP(raw_buffer[0:20])
        
            print 'length:', ip_header.len
        
            hex_raw_buffer = raw_buffer.encode("hex")
            print 'hex_raw_buffer:', hex_raw_buffer

            print 'len:', len(hex_raw_buffer)

            print 'data:', hex_raw_buffer[20 * 2 + 16 * 2:]

            print 'protocol:', ip_header.protocol
            print 'from', ip_header.src_address, 'to', ip_header.dst_address
    except KeyboardInterrupt:
        exit(0)
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

#-----------------------END-------------------------------------------


#-----------------------TCP-------------------------------------------
def tcp():
    socket_protocol = socket.IPPROTO_TCP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
#sniffer.bind((host, 0))
#sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        while True:
            raw_buffer = sniffer.recvfrom(65536)[0]
            print raw_buffer.encode("hex")
            if len(raw_buffer) < 44:
                raw_buffer = raw_buffer + (44 - len(raw_buffer)) * '0'
            tcp_header = TCP(raw_buffer[0:44])          
            #hex_raw_buffer = raw_buffer.encode("hex")
    except KeyboardInterrupt:
        exit(0)
#---------------------END--------------------------------------

def udp():
    socket_protocol = socket.IPPROTO_UDP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    try:
        while True:
            raw_buffer = sniffer.recvfrom(65536)[0]
            print raw_buffer.encode('hex')
            udp_header = UDP(raw_buffer)
    except KeyboardInterrupt:
        exit(0)
#--------------------------------------------------------------

def igmp():
    socket_protocol = socket.IPPROTO_IGMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    try:
        while True:
            raw_buffer = sniffer.recvfrom(65536)[0]
            print raw_buffer.encode('hex')
            igmp_header = IGMP(raw_buffer)
    except KeyboardInterrupt:
        exit(0)

#process_tcp = Process(target = tcp)
#process_icmp = Process(target = icmp)
#process_udp = Process(target = udp)

#igmp()
#thread_tcp.start()
#thread_icmp.start()
#thread_udp.start()

process_tcp = NONE
process_icmp = NONE
process_udp = NONE
process_igmp = NONE

def printkey(event):
    global process_tcp, process_icmp, process_udp, process_igmp
    if event.char == '1':
        if process_icmp != NONE:
            if process_icmp.is_alive() == True:
                process_icmp.terminate()
        if process_udp != NONE:
            if process_udp.is_alive() == True:
                process_udp.terminate()
        if process_igmp != NONE:
            if process_igmp.is_alive() == True:
                process_igmp.terminate()
        process_tcp = Process(target = tcp)
        process_tcp.start()
    if event.char == '2':
        if process_tcp != NONE:
            if process_tcp.is_alive() == True:
                process_tcp.terminate()
        if process_udp != NONE:
            if process_udp.is_alive() == True:
                process_udp.terminate()
        if process_igmp != NONE:
            if process_igmp.is_alive() == True:
                process_igmp.terminate()
        process_icmp = Process(target = icmp)
        process_icmp.start()
    if event.char == '3':
        if process_tcp != NONE:
            if process_tcp.is_alive() == True:
                process_tcp.terminate()
        if process_icmp != NONE:
            if process_icmp.is_alive() == True:
                process_icmp.terminate()
        if process_igmp != NONE:
            if process_igmp.is_alive() == True:
                process_igmp.terminate()
        process_udp = Process(target = udp)
        process_udp.start()
    if event.char == '4':
        if process_tcp != NONE:
            if process_tcp.is_alive() == True:
                process_tcp.terminate()
        if process_icmp != NONE:
            if process_icmp.is_alive() == True:
                process_icmp.terminate()
        if process_udp != NONE:
            if process_udp.is_alive() == True:
                process_udp.terminate()
        process_igmp = Process(target = igmp)
        process_igmp.start()

hook = Tk()
entry = Entry(hook)
entry.bind('<Key>', printkey)
entry.pack()
hook.mainloop()
