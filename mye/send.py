#!/usr/bin/env python3

import socket
import sys
from time import sleep

from Mri import Mri
from scapy.all import (
    IP,
    UDP,
    Ether,
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    PacketListField,
    ShortField,
    get_if_hwaddr,
    get_if_list,
    sendp
)
from scapy.layers.inet import _IPOption_HDR


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

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / Mri(next_layer=0x0800)/IP(
        dst=addr) / UDP(
            dport=4321, sport=1234) / sys.argv[2]

 #   pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
 #       dst=addr, options = IPOption_MRI(count=2,
 #           swtraces=[SwitchTrace(swid=0,qdepth=0), SwitchTrace(swid=1,qdepth=0)])) / UDP(
 #           dport=4321, sport=1234) / sys.argv[2]
    pkt.show2()
    #hexdump(pkt)
    try:
      for i in range(int(sys.argv[3])):
        sendp(pkt, iface=iface)
        sleep(1)
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()
