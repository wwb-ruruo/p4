#!/usr/bin/env python3


import socket
import sys
from time import sleep
from mri import Mri
from mri import Swtrace
from srlayer import SrLayer

from scapy.all import(
    IP,
    UDP,
    Ether,
    IntField,
    Packet,
    PacketListField,
    ShortField,
    get_if_list,
    get_if_hwaddr,
    sendp,
    bind_layers
)





def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface



def main():
    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff",type=0x1234)/SrLayer(next=0x1212)/Mri(next=0x0800) / IP(
        dst=addr)/ UDP(
            dport=4321, sport=1234) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface)


if __name__ =='__main__':
    main()
