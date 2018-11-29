#!/usr/bin/env python
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
import ctypes as ct

class Msg(ct.Structure):
    _fields_ = [("size", ct.c_size_t),
                ("msg", ct.c_char * 100)];

def print_notification(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Msg)).contents
    print("Notification:")
    print(event.msg)

def main():
    b = BPF(src_file="memcached.c", debug=0)
    fn = b.load_func("handle_ingress", BPF.SCHED_CLS)
    print "ready"

    ipr = IPRoute()
    ipdb = IPDB(nl=ipr)
    ifc = ipdb.interfaces.enp0s10

    try:
        ipr.tc("add", "clsact", ifc.index)
        # add ingress clsact
        ipr.tc("add-filter", "bpf", ifc.index, ":1", 
                fd=fn.fd, name=fn.name, parent="ffff:fff2", 
                classid=1, direct_action=True)

        b['NOTIFY_EVT'].open_perf_buffer(print_notification)
        while True:
            b.perf_buffer_poll()
    except:
        ipr.tc("del", "clsact", ifc.index)
        for key, val in b['MCD_MAP'].items():
            print "Stored:"
            print key.key, ":", val.val
        raise

if __name__ == '__main__':
    main()
