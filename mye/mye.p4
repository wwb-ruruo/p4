/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<5>  IPV4_OPTION_MRI = 31;
const bit<16> TYPE_MRI = 0x1212;
const bit<16> threhold = 60;
const bit<16> item_size = 12;

#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


header mri_t {
    bit<16>   next_layer;
    bit<16>   count;
    bit<16>    ban;
}

header switch_t {
    switchID_t  swid;
    qdepth_t    qdepth;
    bit<32>     id;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}


struct headers {
    ethernet_t         ethernet;
    mri_t              mri;
    switch_t[MAX_HOPS] swtraces;
    ipv4_t             ipv4;
}
struct clonedata_t
{
    bit<9>  egress_port;
    bit<32> next_id;
    bit<1>  isclone;
    macAddr_t srcAddr;
}


struct metadata {
    ingress_metadata_t    ingress_metadata;
    parser_metadata_t     parser_metadata;
    bit<32>               next_id;
    bit<16>               packet_length;
    headers               hdr;
    @field_list(1)
    clonedata_t                clonedata;

}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.packet_length = (bit<16>)standard_metadata.packet_length;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.hdr.ethernet = hdr.ethernet;
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_MRI: parse_mri;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.hdr.ipv4 = hdr.ipv4;
        transition accept;
    }

    state parse_mri {
        packet.extract(hdr.mri);
        meta.parser_metadata.remaining = hdr.mri.count;
        meta.hdr.mri = hdr.mri;
        meta.hdr.mri.count = 0;
        transition select(hdr.mri.count)
        {
            0: parse_ipv4;
            default: checkclone;
        }
    }
    state checkclone{
      transition select(standard_metadata.instance_type)
      {
          0 : parse_swtrace;
          default :prase_clone_swtrace;
      }
    }
    state prase_clone_swtrace
    {
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : parse_ipv4;
            default: prase_clone_swtrace;
        }
    }
    state parse_swtrace {
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : parse_ipv4;
            default: parse_swtrace;
        }
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.clonedata.egress_port = port;
        meta.clonedata.srcAddr = hdr.ethernet.dstAddr;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if(hdr.mri.count > 0)
        {
          meta.clonedata.next_id = hdr.swtraces[0].id;
        }
        else
        {
          meta.clonedata.next_id = 0;
        }
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            if(meta.packet_length + item_size > threhold)
            {
                meta.clonedata.isclone = 1;
                clone_preserving_field_list(CloneType.I2E,100,1);
                hdr.mri.ban = 1;
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
     action drop() {
         mark_to_drop(standard_metadata);
     }
    action add_swtrace(switchID_t swid) {
          hdr.mri.count = hdr.mri.count + 1;
          hdr.swtraces.push_front(1);
          // According to the P4_16 spec, pushed elements are invalid, so we need
          // to call setValid(). Older bmv2 versions would mark the new header(s)
          // valid automatically (P4_14 behavior), but starting with version 1.11,
          // bmv2 conforms with the P4_16 spec.
          hdr.swtraces[0].setValid();
          hdr.swtraces[0].swid = swid;
          hdr.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth;
          hdr.swtraces[0].id = meta.clonedata.next_id + 1;
    }

    table swtrace {
        actions = {
            add_swtrace;
            NoAction;
        }
        default_action = NoAction();
    }
    apply {
        if(standard_metadata.egress_port!=meta.clonedata.egress_port)
        {
            drop();
        }
        if(standard_metadata.instance_type!=0)
        {
            hdr = meta.hdr;
            hdr.ethernet.srcAddr = meta.clonedata.srcAddr;
        }
        if (hdr.mri.isValid() && hdr.mri.ban==0) {
            swtrace.apply();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mri);
        packet.emit(hdr.swtraces);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
