import sys
from scapy.all import *

class Mem(Packet):
    name = "Memcached"
    fields_desc=[ ShortField("id",0),
                  ShortField("seq",0),
                  ShortField("tot",0),
                  ShortField("zer",0)]

if __name__ == '__main__':
    if len(sys.argv) == 2:
        cmd = sys.argv[1]
        pkts = []
        for i in range(100):
            key = 'KEY' + str(i)
            val = 'VAL' + str(i)

            pkts.append((Ether(dst="08:00:27:fb:97:53")/
                   IP(dst="192.168.56.101")/
                   UDP(dport=11211)/
                   Mem()/
                   ("%s %s \r\n%s\r\n" % (cmd, key, val))))
        sendp(pkts, iface='vboxnet0')
    else:
        cmd = sys.argv[1]
        key = sys.argv[2]

        if cmd == 'set':
            val = sys.argv[3]
            load = "%s %s \r\n%s\r\n" % (cmd, key, val)
        else:
            load = "%s %s\r\n" % (cmd, key)

        pkt = (Ether(dst="08:00:27:fb:97:53")/
               IP(dst="192.168.56.101")/
               UDP(dport=11211)/
               Mem()/ load)

        sendp(pkt, iface='vboxnet0')

