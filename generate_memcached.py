from __future__ import print_function
from scapy.all import *
import json
import argparse
import struct
import random
import time

class PacketGenerator:

    SET_SYNTAX = '{cmd} {key} 0 0 {bytes} \r\n{payload}\r\n'
    GET_SYNTAX = '{cmd} {key}\r\n'

    def __init__(self, src_mac, dst_mac, src_ip, dst_ip, sport = 12345, dport = 11211):

        self.Pkt = Ether(src=src_mac, dst=dst_mac)/IP(src=src_ip, dst=dst_ip)/UDP(sport=sport, dport=dport)
        random.seed(time.time())
        self.cur_id = random.randint(0, 100)

    def hdr(self):
        h = ''.join([struct.pack(">h", x) for x in [self.cur_id, 0, 1, 0]])
        self.cur_id+= 1
        self.cur_id %= 32000
        return h

    def set(self, key, bytes=8):
        key = "{:}".format(key)

        load = (key + '-') * (bytes)
        load = load[:bytes]

        pkt = self.Pkt/(self.hdr() + self.SET_SYNTAX.format(cmd='set', key=key, bytes=bytes, payload=load))

        return pkt

    def get(self, key):

        return self.Pkt/(self.hdr() + self.GET_SYNTAX.format(cmd='get', key=key))

def send_and_show(pkt, iface):
    print("Sending: {}".format(pkt.load[8:]))
    a = srp1(pkt, iface=iface)
    print("Received: {}".format(a.load[8:]))

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--smac', type=str, default='00:00:00:00:00:00', help="Source MAC")
    parser.add_argument('--dmac', type=str, default='00:00:00:00:00:00', help="Dst MAC")
    parser.add_argument('--sip', type=str, default='127.0.0.1', help="Source IP")
    parser.add_argument('--dip', type=str, default='127.0.0.1', help="Dst IP")
    parser.add_argument('--iface', type=str, default=None, help="Interface on which to play traffic")
    parser.add_argument('--wait-resp', action='store_true', help="Wait for responses")
    parser.add_argument('--out', type=str, default=None, help="pcap file to write output to")
    parser.add_argument('--n-pkt', type=int, default=1000, help="Total number of packets")
    parser.add_argument('--get-pct', type=float, default=.95, help="Percentage of packets that are GETs")
    parser.add_argument('--pre-set', action='store_true', help='Perform all SETs before any gets')
    parser.add_argument('--set-out', type=str, default=None, help='if --pre-set, saves SETs to separate file')

    args = parser.parse_args()
 
    if args.out is None and args.iface is None:
        raise Exception("Must provide either output file or interface")

    return args

def generate_packets(args):
    gen = PacketGenerator(args.smac, args.dmac, args.sip, args.dip)
    log = []

    n_get = int(args.n_pkt * args.get_pct)
    n_set = int(args.n_pkt * ( 1 - args.get_pct))
    if n_set == 0:
        n_set = 1
        print("Ratio too low! Setting N_SET to 1")

    if args.pre_set:

        sets = []

        for _ in range(n_set):
            sets.append(random.randint(1, n_set))

        gets = []

        for _ in range(n_get):
            gets.append(random.choice(sets))

        pkts = []
        for s in sets:
            pkts.append(gen.set(s))
        for g in gets:
            pkts.append(gen.get(g))

    else:
        total_n = n_get + n_set
        inter_set = n_get / n_set

        pkts = []
        gets_placed = 0

        sets = [ random.randint(1, n_set) for _ in range(n_set) ]
        placed_sets = []

        for i, s in enumerate(sets):
            pkts.append(gen.set(s))

            for _ in range(inter_set):
                pkts.append(gen.get(random.choice(sets[:i+1])))
                gets_placed += 1
                if gets_placed >= n_get:
                    break
            if gets_placed >= n_get:
                break

    if args.iface:
        for pkt in pkts:
            if 'set' in pkt.load:
                sendp(pkt, iface=args.iface)
            else:
                send_and_show(pkt, args.iface)

    if args.out:
        print("Writing output")
        if not args.set_out:
            wrpcap(args.out, pkts)
        else:
            sets = [pkt for pkt in pkts if 'set' in pkt.load]
            gets = [pkt for pkt in pkts if 'get' in pkt.load]
            wrpcap(args.out, gets)
            print("Writing sets")
            wrpcap(args.set_out, sets)

if __name__ == "__main__":
    args = parse_args()
    generate_packets(args)
