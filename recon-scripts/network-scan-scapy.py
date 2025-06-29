#!/usr/bin/python3

from scapy.all import *

class NetworkScanner:
    def __init__(self,host):
        self.host = host

    def create_packet(self):
        layer1 = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.host)
        layer2 = Arp()