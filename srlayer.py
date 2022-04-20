#!/usr/bin/env python3


import socket
import sys
from time import sleep

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


class SrLayer(Packet):
    name = "sr"
    fields_desc = [IntField("PathId",0),
                    IntField("RoadTh",0),
                    ShortField("next",0x1212)
                    ]


bind_layers(Ether,SrLayer,type = 0x1234)
