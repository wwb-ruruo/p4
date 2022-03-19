
from scapy.all import (
    IP,
    UDP,
    Ether,
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    BitField,
    PacketListField,
    ShortField,
    get_if_hwaddr,
    get_if_list,
    sendp,
    bind_layers,
    IP
)


TYPE_MRI = 0x1212
TYPE_IP = 0x0800

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                    IntField("qdepth", 0),
                    IntField("id",0)]
    def extract_padding(self, p):
                return "", p


class Mri(Packet):
    name = "MRI"
    fields_desc = [

        ShortField("next_layer",0),
        ShortField("count",0),
        ShortField("ban",0),
        PacketListField(
                "swtraces",
                [],
                SwitchTrace,
                count_from = lambda pkt:(pkt.count*1))
    ]


bind_layers(Ether,Mri,type=TYPE_MRI)
bind_layers(Mri,IP,next_layer = TYPE_IP)
