#!/usr/bin/env python3

from scapy.all import *

def print_pkt(pkt):
  pkt.show()

pkt = sniff(iface='br-af27d383f404', filter='icmp' , prn=print_pkt)


