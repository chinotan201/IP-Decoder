import ipaddress
import os
import socket
import struct
import sys
import logging

class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        self.protocol_map = {
            1: "ICMP", 
            6: "TCP", 
            17: "UDP",
            89: "OSPF",  # Add more protocols as needed
            132: "SCTP"  # Example protocol
        }

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except KeyError:
            logging.warning(f"Unknown protocol: {self.protocol_num}")
            self.protocol = str(self.protocol_num)

class PacketSniffer:
    def __init__(self, host, promiscuous=False, log_file='sniffer.log'):
        self.host = host
        self.promiscuous = promiscuous
        self.log_file = log_file
        logging.basicConfig(filename=self.log_file, level=logging.DEBUG)

    def setup_socket(self):
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((self.host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt' and self.promiscuous:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        return sniffer

    def sniff_packets(self):
        sniffer = self.setup_socket()
        try:
            while True:
                raw_buffer = sniffer.recvfrom(65535)[0]
                ip_header = IP(raw_buffer[0:20])

                # Log the detected protocol and IP addresses
                logging.info(f'Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}')
                print(f'Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}')

        except KeyboardInterrupt:
            logging.info("Sniffing stopped by user.")
            if os.name == 'nt' and self.promiscuous:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sys.exit()

if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.203'  # Default IP

    sniffer = PacketSniffer(host, promiscuous=True)
    sniffer.sniff_packets()
