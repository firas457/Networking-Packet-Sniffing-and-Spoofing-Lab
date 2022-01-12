from scapy.all import *

in_r = True

i=1

while  in_r:

    add=IP(dst='216.58.210.36', ttl=i)

    res = sr1(add/ICMP(),timeout=7,verbose=8)

    if res is None:
        print(f"{i}  time out")


    elif  res.type == 0:
        print(f"{i} {res.src}")
        in_r=False

    else:

        print(f"{i} {res.src}")


    i= i + 1    


