#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

s = []
port = [[0 for i in range(9)] for i in range(9)]
dst = [["xx" for i in range(9)] for i in range(9)]


def writeRule(p4info_helper, sw, PathId,RoadTh,
                     dstAddr, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.sr_m",
        match_fields={
            "hdr.sr.PathId": PathId,
            "hdr.sr.RoadTh": RoadTh,
        },
        action_name="MyIngress.update_sr",
        action_params={
            "dstAddr":dstAddr,
            "port": port,
        })
    sw.WriteTableEntry(table_entry)

def writeMri(p4info_helper, sw, id):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.mri_m",
        match_fields={
        },
        action_name="MyEgress.addsw",
        action_params={
            "swid": id
        })
    sw.WriteTableEntry(table_entry)


def init_topo():
    port[1][2] = 2
    port[1][4] = 3
    port[2][1] = 1
    port[2][3] = 2
    port[3][2] = 1
    port[3][8] = 2
    port[3][6] = 3
    port[6][5] = 1
    port[6][3] = 2
    port[5][6] = 2
    port[5][4] = 1
    port[4][5] = 2
    port[4][1] = 1

    for i in range(1,9):
        for j in range(1,9):
            if port[i][j]==0:
                continue
            if j < 7:
                dst[i][j] = "08:00:00:00:0%d:00"%(j)
            if j >= 7:
                dst[i][j] = "08:00:00:00:0%d:%d%d"%(j-6,j-6,j-6)

def printGrpcError(e):
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))



def writeMRI(p4info_helper,s):
    for i in range(6):
        writeMri(p4info_helper,s[i],i+1)


def writeSR(p4info_helper,Road=[],id=0):
    n = len(Road)
    i = 1
    while(i<n-1):
        writeRule(p4info_helper = p4info_helper,sw = s[Road[i]-1],
                    PathId = id,RoadTh = i-1,
                    port = port[Road[i]][Road[i+1]],
                    dstAddr = dst[Road[i]][Road[i+1]])
        i = i+1

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        # s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        #     name='s1',
        #     address='127.0.0.1:50051',
        #     device_id=0,
        #     proto_dump_file='logs/s1-p4runtime-requests.txt')
        for i in range(1,7):
            sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s%d'%(i),
                address='127.0.0.1:%d'%(50050+i),
                device_id=i-1,
                proto_dump_file='logs/s%d-p4runtime-requests.txt'%(i))
            s.append(sw)
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        for i in range(6):
            s[i].MasterArbitrationUpdate()
        # s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
        #                                bmv2_json_file_path=bmv2_file_path)
        for i in range(6):
            s[i].SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                        bmv2_json_file_path=bmv2_file_path)


        writeMRI(p4info_helper,s)
        while(True):
            try:
                print('input the SR')
                a = input().strip().split()
                a = [int(e) for e in a]
                id = a[0]
                road = a[1:]
            except:
                print('illegal input')
                continue
            writeSR(p4info_helper,road,id)

        # Write the rules that tunnel traffic from h1 to h2
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/sr.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/sr.json')
    args = parser.parse_args()

    init_topo()
    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
