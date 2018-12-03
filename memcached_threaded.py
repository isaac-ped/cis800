#!/usr/bin/env python
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
import ctypes as ct
import multiprocessing as mp
import time

class Msg(ct.Structure):
    _fields_ = [("size", ct.c_size_t),
                ("msg", ct.c_char * 100)];

class Sz(ct.Structure):
    _fields_ = [("size", ct.c_size_t)]

def print_notification(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Msg)).contents
    print("Notification:")
    print(event.msg)

def print_pkt_size(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Sz)).contents
    print("Size: %d" % event.size)

def start_bpf(fn):
    ipr = IPRoute()
    ipdb = IPDB(nl=ipr)
    ifc  = ipr.get_links(ifname='ens3d1')[0]
    idx= ifc['index']
    #ifc = ipdb.interfaces.ens3d1

    try:
        # add ingress clsact
        ipr.tc("add-filter", "bpf", idx,
                fd=fn.fd, name=fn.name, parent="ffff:fff2",
                class_id=1,
                direct_action=True)

        print "ready"
        while True:
            time.sleep(1)
    except:
        print 'exiting'
        raise

def main():
    b = BPF(src_file="memcached.c", debug=0)
    fn = b.load_func("handle_ingress", BPF.SCHED_CLS)

    ipr = IPRoute()
    ifc  = ipr.get_links(ifname='ens3d1')[0]
    idx= ifc['index']
    try:
        ipr.tc("add", "clsact", idx)
    except:
        print 'already...'
    ps = []
    try:
        for _ in range(16):
            p = mp.Process(target=start_bpf, args=(fn,))
            ps.append(p)
            p.start()
        b['NOTIFY_EVT'].open_perf_buffer(print_notification)
        b['PKT_EVT'].open_perf_buffer(print_pkt_size);
        while True:
            b.perf_buffer_poll()
    except:
        ipr.tc("del", "clsact", idx)
        for p in ps:
            p.terminate()
            p.join()
        print "Stored {} items".format(len(b['MCD_MAP']))
        raise

if __name__ == '__main__':
    main()
