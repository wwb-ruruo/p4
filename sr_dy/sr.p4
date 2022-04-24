/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_SR = 0x1234;
const bit<16> TYPE_MRI = 0x1212;


#define MAX_HOPS 30

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header sr_t
{
   bit<32> PathId;
   bit<32> RoadTh;
   bit<16> next;
}
header mri_t
{
    bit<16> next;
    bit<16> count;
}

header sw_t
{
   bit<32> swid;
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

struct metadata {
  bit<16> remaining;
  bit<1> srok;
}

struct headers {
    ethernet_t   ethernet;
    sr_t          sr;
    mri_t        mri;
    sw_t[MAX_HOPS] sw;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.srok = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_MRI: parse_mri;
            TYPE_SR:  parse_sr;
            default: accept;
        }
    }
    state parse_sr
    {
      packet.extract(hdr.sr);
      transition select(hdr.sr.next){
        TYPE_IPV4: parse_ipv4;
        TYPE_MRI: parse_mri;
      }
    }
    state parse_mri{
      packet.extract(hdr.mri);
      meta.remaining = hdr.mri.count;
      transition select(meta.remaining){
        0: parse_ipv4;
        default: parse_sw;
      }
    }
    state parse_sw{
      meta.remaining = meta.remaining - 1;
      packet.extract(hdr.sw.next);
      transition select(meta.remaining){
        0: parse_ipv4;
        default: parse_sw;
      }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
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
        default_action = drop();
    }
    action update_sr(macAddr_t dstAddr, egressSpec_t port)
    {
      standard_metadata.egress_spec = port;
      hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
      hdr.ethernet.dstAddr = dstAddr;
      hdr.sr.RoadTh = hdr.sr.RoadTh + 1;
      meta.srok = 1;
    }
    table sr_m {
      key = {
        hdr.sr.PathId: exact;
        hdr.sr.RoadTh: exact;
      }
      actions = {
        update_sr;
        NoAction;
      }
    }
    apply {
        if(hdr.sr.isValid())
        {
            sr_m.apply();
        }
        meta.srok = 1;
        if (hdr.ipv4.isValid() && meta.srok==0) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
        action addsw(bit<32> swid)
        {
          hdr.sw.push_front(1);
          hdr.sw[0].setValid();
          hdr.sw[0].swid = swid;
          hdr.mri.count = hdr.mri.count + 1;
        }
        table mri_m{
          actions = {
            addsw;
            NoAction;
          }
          default_action = NoAction;
        }
        apply{
          mri_m.apply();
        }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
        packet.emit(hdr.sr);
        packet.emit(hdr.mri);
        packet.emit(hdr.sw);
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
