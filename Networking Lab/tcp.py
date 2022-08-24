from scapy.all import *

def print_pkt(pkt):
      if pkt[TCP] is not None:

            print(f"\tsource: {pkt[IP].src}")

            print(f"\tdest: {pkt[IP].dst}")


            print(f"\tsource_port: {pkt[TCP].sport}")


            print(f"\tdest_port: {pkt[TCP].dport}")


interfaces=['br-af27d383f404','enp0s3','lo']
pkt = sniff(iface=interfaces, filter='tcp port 23 and src host 10.0.2.15',prn=print_pkt)






