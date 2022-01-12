from scapy.all import *

def print_pkt(pkt):
     
     if pkt[ICMP] is not None:
           if pkt[ICMP].type == 0 or pkt[ICMP].type ==8:

                 print(f"\tsource: {pkt[IP].src}")

                 print(f"\tdest: {pkt[IP].dst}")

                

                 if pkt[ICMP].type == 0:
                       print("ICMP type: echo-reply") 

                 
                 if pkt[ICMP].type == 8:
                       print("ICMP type: echo-request")


interfaces=['br-af27d383f404','enp0s3','lo']

pkt = sniff(iface=interfaces, filter='icmp',prn=print_pkt)

