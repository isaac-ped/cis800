#!/usr/bin/env python
from bcc import BPF
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
import time
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
    b = BPF(src_file="memcached_xdp.c", debug=0, cflags=['-w'])
    get_fn = b.load_func("handle_get", BPF.XDP)
    print "loaded get"

    fn = b.load_func("handle_ingress", BPF.XDP)

    print "loaded ingress"
    set_fn = b.load_func("handle_set", BPF.XDP)
    print "loaded set"
    prog_array = b.get_table("prog_array")
    prog_array[ct.c_int(1)] = ct.c_int(set_fn.fd)
    prog_array[ct.c_int(2)] = ct.c_int(get_fn.fd)

    flags = 0

    in_if = 'ens3d1'
    b.remove_xdp(in_if, flags)

    ip = IPRoute()

    b.attach_xdp(in_if, fn, flags)

    b['NOTIFY_EVT'].open_perf_buffer(print_notification)
    b['PKT_EVT'].open_perf_buffer(print_pkt_size)

    try:
        print "ready"
        while True:
            b.perf_buffer_poll()
            #for k, v in b['MCD_MAP'].items():
            #    print k.key, v.val
    except:
        pass

    b.remove_xdp(in_if, flags)

    print set([v.size for v in b['MCD_MAP'].values()])
    print set([len(k.key) for k in b['MCD_MAP'].keys()])

    def showit(labs):
        for i in range(16):
            print '\t'.join([str(b[lab][0][i]) for lab in labs])
        for lab in labs:
            print lab
            print sum(b[lab][0])


    showit(['getcnt', 'valcnt', 'setcnt', 'storedcnt'])

    print len(b['MCD_MAP'])


if __name__ == '__main__':
    main()
