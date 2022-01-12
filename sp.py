from scapy.all import *

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type==8:
        print('The packet')
        print('\t|-src ip:' ,pkt[IP].src)

        print('\t|-dest ip:' ,pkt[IP].dst)
        


        ip=Ip(src=pkt[IP].dst,dst=pkt[IP].src,ihl=pkt[IP].ihl)
        
        icmp=ICMP(type=0,id=pkt[ICMP].id,seq=pkt[ICMP].seq)
        
        info=pkt[RAW].load

        packet=ip/icmp/info



        print('packet copy(spoffed)')

        print('\t|-src ip:', packet[IP].src)

        print('\n')

        send(packet,verbose=0)


pkt=sniff(iface=['enp0s3','br-af27d383f404'],filter='icmp and src host 10.9.0.5',prn=spoof_pkt)


