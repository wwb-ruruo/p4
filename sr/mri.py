#!/usr/bin/env python3

import socket
import sys
from time import sleep
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


class Swtrace(Packet):
    name = "swtraces"
    fields_desc = [IntField("swid",0)]
    def extract_padding(self, p):
                return "", p


class Mri(Packet):
    name = "Mri"
    fields_desc = [
                    ShortField("next",0x0800),
                    ShortField("count",0),
                    PacketListField("sw",[],
                    Swtrace,
                    count_from=lambda pkt:(pkt.count*1))
                    ]


bind_layers(SrLayer,Mri,next=0x1212)
bind_layers(Mri,IP,next=0x0800)
