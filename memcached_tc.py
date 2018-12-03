#!/usr/bin/env python
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
import ctypes as ct

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

def main():
    b = BPF(src_file="memcached_tc.c", debug=0)
    fn = b.load_func("handle_ingress", BPF.SCHED_CLS)
    print "ready"

    ipr = IPRoute()
    ipdb = IPDB(nl=ipr)
    ifc  = ipr.get_links(ifname='ens3d1')[0]
    idx= ifc['index']
    #ifc = ipdb.interfaces.ens3d1

    try:
        try:
            ipr.tc("add", "clsact", idx)
        except:
            pass
        # add ingress clsact
        ipr.tc("add-filter", "bpf", idx,
                fd=fn.fd, name=fn.name, parent="ffff:fff2",
                class_id=1,
                direct_action=True)

        b['NOTIFY_EVT'].open_perf_buffer(print_notification)
        b['PKT_EVT'].open_perf_buffer(print_pkt_size);
        while True:
            b.perf_buffer_poll()
    except:
        ipr.tc("del", "clsact", idx)
        #for key, val in b['MCD_MAP'].items():
        #    print "Stored:"
        #    print key.key, ":", val.val
        print "stored", len(b['MCD_MAP']), "items"
        raise

if __name__ == '__main__':
    main()
