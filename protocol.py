import ctypes as ct

class Udp(ct.Structure):
    _fields_ = [("usrc", ct.c_ushort),
                ("udst", ct.c_ushort),
                ("ulen", ct.c_ushort),
                ("uchk", ct.c_ushort)]

class Eth(ct.Structure):
    _fields_ = [("edst", ct.c_char * 6),
                ("esrc", ct.c_char * 6),
                ("eproto", ct.c_ushort)]

class Ip4(ct.Structure):
    _fields_ = [("iverihn", ct.c_char),
                ("idscpecn", ct.c_char),
                ("ilen", ct.c_ushort),
                ("iid", ct.c_ushort),
                ("iflgfrag", ct.c_ushort),
                ("ittl", ct.c_char),
                ("iproto", ct.c_char),
                ("ichk", ct.c_ushort),
                ("isrc", ct.c_char * 4),
                ("idst", ct.c_char * 4)]

class Mcd(ct.Structure):
    _fields_ = [("id", ct.c_ushort),
                ("seq", ct.c_ushort),
                ("tot", ct.c_ushort),
                ("zero", ct.c_ushort)]

class Hdr(ct.Structure):
    _fields_ = Udp._fields_ + Eth._fields_ + Ip4._fields_ + Mcd._fields_

def as_hex(ptr, typ):
    st = ct.string_at(ptr, ct.sizeof(typ))
    return ":".join(c.encode('hex') for c in st)


