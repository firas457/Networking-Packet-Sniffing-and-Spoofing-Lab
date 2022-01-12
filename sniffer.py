#!/usr/bin/python

from scapy.all import *

def print_pkt(pkt):
    pkt.show()


interfaces=['br-af27d383f404','enp0s3','lo']

pkt = sniff(iface=interfaces, filter='icmp',prn=print_pkt)


