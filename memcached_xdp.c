#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

BPF_PROG_ARRAY(prog_array, 10);
BPF_DEVMAP(tx_port, 1);
BPF_PERF_OUTPUT(NOTIFY_EVT);
BPF_PERF_OUTPUT(PKT_EVT);
BPF_PERCPU_ARRAY(getcnt, long, 1);
BPF_PERCPU_ARRAY(setcnt, long, 1);
BPF_PERCPU_ARRAY(valcnt, long, 1);
BPF_PERCPU_ARRAY(storedcnt, long, 1);

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest),(src),(n))
#endif


#ifndef memset
#define memset(dest, src, n) __builtin_memset((dest),(src),(n))
#endif

#define MEMCPY(dest, src, n)\
for (int i=0; i < n; i++) dest[i] = src[i];

#define MAX_NOT 30

#define MAX_KEYLEN 16
#define MAX_VALLEN 8

struct key_t {
    char key[MAX_KEYLEN];
};

struct val_t {
    size_t size;
    char val[MAX_VALLEN];
};

#define MAX_DATALEN 64

struct data_t {
    char data[MAX_DATALEN];
};

BPF_PERCPU_ARRAY(datamap, struct data_t, 1);

BPF_HASH(MCD_MAP, struct key_t, struct val_t, 3e5);

struct not_t {
    size_t len;
    char msg[MAX_NOT];
};

static inline void notify(struct xdp_md *skb, const char *str, size_t len) {
    struct not_t n = {};
    n.len = len;
    memcpy(n.msg, str, len > MAX_NOT ? MAX_NOT : len);
    NOTIFY_EVT.perf_submit(skb, &n, sizeof(n));
}

#define NOTIFY(skb, str) \
    notify(skb, str, strlen(str))

#define PASS(x) \
    NOTIFY(x, "Passing"); return XDP_PASS;

#define MCD_PORT 11211

struct mcdhdr {
    uint16_t id;
    uint16_t seq;
    uint16_t tot;
    uint16_t zero;
};

struct __attribute__((__packed__)) hdrs {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    struct mcdhdr mcd;
};
#include "cp_help.h"

#define SWAP(skb, base, basename, basestruct, f1, f2) \
    bpf_skb_store_bytes(skb, offsetof(struct hdrs, basename) + offsetof(basestruct, f1), \
                        &(base).basename.f2, sizeof((base).basename.f2), 0); \
    bpf_skb_store_bytes(skb, offsetof(struct hdrs, basename) + offsetof(basestruct, f2), \
                        &(base).basename.f1, sizeof((base).basename.f1), 0); \

static inline void swap_direction(struct hdrs *h) {
    struct ethhdr e = h->eth;
    struct iphdr i = h->ip;
    struct udphdr u = h->udp;

    memcpy(h->eth.h_source, e.h_dest, sizeof(e.h_dest));
    memcpy(h->eth.h_dest, e.h_source, sizeof(e.h_source));;
    h->ip.saddr = i.daddr;
    h->ip.daddr = i.saddr;
    h->udp.source = u.dest;
    h->udp.dest = u.source;

    //bpf_skb_store_bytes(skb, offsetof(struct hdrs, ip) + offsetof(struct iphdr, saddr),
                        //&hdrs.ip.daddr, sizeof(hdrs.ip.saddr), 0);
    /*bpf_skb_store_bytes(skb, offsetof(struct hdrs, eth) + offsetof(struct ethhdr, h_dest),
                        hdrs.eth.h_source, sizeof(hdrs.eth.h_source), 0);
*/

}

static inline bool mem_cmp(char *a, char *b, size_t l) {
#pragma unroll
    for (int i=0; i < l; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

#define FITS(ptr, end, str) \
    (void*)((long)((ptr) + sizeof(str) < (end)))

#define STRMATCH(ptr, end, str) \
    (FITS(ptr, end, str) & mem_adv(ptr, str, sizeof(str)))

#define SET_CMD "set "
#define GET_CMD "get "

static inline bool datacmp(struct data_t *data, char *cmp, size_t len) {
#pragma unroll
    for (int i=0; i < len; i++) {
        if (data->data[ i] != cmp[i]) {
            return false;
        }
    }
    return true;
}

static inline int datafind1(struct data_t *data, unsigned int off, unsigned int maxoff, char find) {
#pragma unroll
    for (int i=off; i < maxoff; i++) {
        if (data->data[i] == find) {
            return i - off;
        }
    }
    return -1;
}

static inline size_t datafind2(struct data_t *data, unsigned int off, char find, char find2) {
#pragma unroll
    for (int i=off + 1; i < MAX_DATALEN - 10; i++) {
        if (data->data[i] == find){// && data->data[i+1] == find2) {
            return i - off;
        }
    }
    return 0;
}

static inline size_t datafind3(struct data_t *data, unsigned int off, char find, char find2) {
#pragma unroll
    for (int i=strlen(GET_CMD) + 1; i < MAX_DATALEN - 16; i++) {
        if (i > off && data->data[i] == find  && data->data[i+1] == find2) {
            return i;
        }
    }
    return 0;
}

#define NOT_FOUND_STR "NOT_FOUND\r\n"
#define VAL_STR "VALUE "
#define FLAG_STR " 0 "
struct flag_struct {
    char flag[strlen(FLAG_STR)];
};
#define END_STR "END\r\n"

static inline size_t itoc(size_t s, char *b) {
    int maxmult = 1;
    size_t maxi = 0;
#pragma unroll
    for (unsigned int i=1; i < 6; i++) {
        if (maxmult * 10 > s) {
            maxi = i;
            break;
        }
        maxmult *= 10;
    }
    int mult = 1;
#pragma unroll
    for (int i=0; i < 6; i++) {
        if (i < maxi) {
            b[maxi - i - 1] = '0' + ((s / mult) % 10);
            mult *= 10;
        }
    }
    return maxi;
}
/* Incrementaly update a checksum, given old and new 16bit words */
static inline __u16 incr_check_s(__u16 old_check, __u16 old, __u16 new)
{ /* see RFC's 1624, 1141 and 1071 for incremental checksum updates */
__u32 l;
old_check = ~ntohs(old_check);
old = ~old;
l = (__u32)old_check + old + new;
return htons(~( (__u16)(l>>16) + (l&0xffff) ));
}
#define strlen(X) sizeof(X) - 1

int handle_get(struct xdp_md *xdp) {
    uint32_t k = 0;
    long *value = getcnt.lookup(&k);
    if (value) 
        *value += 1;
    void *data_raw = (void*)(long)xdp->data;
    void *data_end = (void*)(long)xdp->data_end;

    uint32_t didx = 0;
    struct data_t *data  = datamap.lookup(&didx);
    if (data == NULL) {
        PASS(xdp);
    }

    if (!datacmp(data, GET_CMD, strlen(GET_CMD))) {
        //notify(xdp, data->data, 10);
        NOTIFY(xdp, "NOT GET");
        PASS(xdp);
    }
    size_t offset = strlen(GET_CMD);

    size_t keylen = datafind2(data, offset, '\r', '\n');
    if (keylen== 0) {
        NOTIFY(xdp, "GET but no space");
        PASS(xdp);
    }
    struct key_t key;
    if (keylen > sizeof(key.key)) {
        NOTIFY(xdp, "GET but too big");
        PASS(xdp);
    }

#pragma unroll
    for (int i=0; i < sizeof(key.key); i++) {
        if (i < keylen) {
            key.key[i] = data->data[offset + i];
        } else {
            key.key[i] = '\0';
        }
    }

    struct val_t *val = MCD_MAP.lookup(&key);
    if (val == NULL) {
        NOTIFY(xdp, "NOT FOUND");
        struct hdrs *h = data_raw;
        if (data_raw + sizeof(*h) > data_end) {
            PASS(xdp);
        }
        swap_direction(h);
        char msg[] = NOT_FOUND_STR;
        if (data_raw + sizeof(*h) + strlen(NOT_FOUND_STR) > data_end) {
            PASS(xdp);
        }
        memcpy(data_raw + sizeof(*h), msg, strlen(NOT_FOUND_STR));
        return XDP_TX;
    }

    struct hdrs *h = data_raw;
    if (data_raw + sizeof(*h) > data_end) {
        NOTIFY(xdp, "BUT HOW!");
        PASS(xdp);
    }
    struct hdrs h_orig = *h;

    bpf_xdp_adjust_head(xdp, -40);
    void *data_n = (void*)(long)xdp->data;
    void *data_nend = (void*)(long)xdp->data_end;

    struct hdrs *h_new = data_n;
    if (data_n + sizeof(*h_new) > data_nend) {
        PASS(xdp);
    }
    *h_new = h_orig;
    swap_direction(h_new);

    size_t off = sizeof(*h_new);

    char valstr[] = VAL_STR;
    if (data_n + off + sizeof(valstr) > data_nend) {
        return XDP_PASS;
    }
    memcpy(data_n + off, valstr, strlen(valstr));
    off += strlen(valstr);
///
    if (data_n + off + sizeof(key.key) > data_nend) {
        return XDP_PASS;
    }
    memcpy(data_n + off, key.key, sizeof(key.key));
    size_t realoff = off + keylen;
    size_t minoff = off;
///
    char *data_nc = (char*)data_n;

    size_t maxoff = off + sizeof(key.key);
    if (data_n + maxoff + 3 > data_nend) {
        return XDP_PASS;
    }

#pragma unroll
    for (int i = minoff; i <= maxoff; i++) {
        if (i == realoff) {
            memcpy(data_nc+ i, " 0 ", 3);
        }
    }
    realoff += 3;
    maxoff += 3;
    minoff += 3;

    char sizestr[6] = {};
    size_t sizesize = itoc(val->size, sizestr);

    if (data_n + maxoff + 9 > data_nend) {
        return XDP_PASS;
    }

    for (int i=minoff; i <= maxoff; i++) {
        if (i == realoff) {
            memcpy(data_nc + i, sizestr, 6);
        }
    }

    realoff += sizesize;
    maxoff += 6;
    minoff += 1;

    for (int i=minoff; i <= maxoff; i++) {
        if (i == realoff) {
            memcpy(data_nc + i, " \r\n", 3);
        }
    }

    realoff += 3;
    maxoff += 3;
    minoff += 3;

    if (data_n + maxoff + sizeof(val->val) + 10 > data_nend) {
        return XDP_PASS;
    }

#pragma unroll
    for (int i=minoff; i <= maxoff; i++) {
        if (i == realoff) {
            memcpy(data_nc + i, val->val, sizeof(val->val));
        }
    }

    realoff += val->size;
    maxoff += sizeof(val->val);
    minoff += 2;

#pragma unroll
    for (int i=minoff; i <= maxoff; i++) {
        if (i == realoff) {
            memcpy(data_nc + i, "\r\nEND\r\n", 8);
        }
    }
    minoff += 7;
    realoff += 7;
    maxoff += 7;


    //memcpy(data_n + off, flagsstr, strlen(FLAG_STR));

    __u16 prevlen = h_new->ip.tot_len;
    h_new->ip.tot_len = htons(realoff - 14);
    h_new->udp.len = htons(realoff - sizeof(*h_new) + sizeof(h_new->udp) + 8);
    h_new->ip.check = incr_check_s(h_new->ip.check, ntohs(prevlen), ntohs(h_new->ip.tot_len));
    h_new->mcd.seq = 0;
    h_new->mcd.zero = 0;
    h_new->udp.check = 0;

    value = valcnt.lookup(&k);
    if (value)
        *value += 1;


    if (data_n + maxoff + 9 < data_nend) {
#pragma unroll
        for (int i=minoff; i < maxoff; i++) {
            if (i == realoff) {
                data_nc[i] =  '\0';
                data_nc[i+1] = '\0';
                data_nc[i+2] = '\0';
                data_nc[i+3] = '\0';
                data_nc[i+4] = '\0';
                data_nc[i+5] = '\0';
                data_nc[i+6] = '\0';
                data_nc[i+7] = '\0';
                data_nc[i+8] = '\0';
            }
        }
    }

    return XDP_TX;
}


#define IP_CSUM_OFFSET (ETH_HLEN + offsetof(struct iphdr, check))
#define STORED_STR "STORED\r\n"

int handle_set(struct xdp_md *xdp){
    uint32_t k = 0;
    long *value;
    value = setcnt.lookup(&k);
    if (value)
        *value += 1;
    uint32_t didx = 0;
    struct data_t *data  = datamap.lookup(&didx);
    if (data == NULL) {
        PASS(xdp);
    }

    if (!datacmp(data, SET_CMD, strlen(SET_CMD))) {
        //notify(xdp, data->data, 10);
        NOTIFY(xdp, "NOT SET");
        PASS(xdp);
    }
    ssize_t offset = strlen(SET_CMD);

    ssize_t keylen_s = datafind1(data, offset, offset + 20, ' ');
    if (keylen_s < 0) {
        NOTIFY(xdp, "SET but no space");
        PASS(xdp);
    }
    size_t keylen = keylen_s;

    struct key_t key = {};
    if (keylen > sizeof(key.key)) {
        NOTIFY(xdp, "SET but too big");
        size_t ks = keylen;
        PKT_EVT.perf_submit(xdp, &ks, sizeof(ks));
        PASS(xdp);
    }

#pragma unroll
    for (int i=0; i < sizeof(key.key); i++) {
        if (i < keylen) {
            key.key[i] = data->data[i + offset];
        }
    }
    //notify(xdp, key.key, sizeof(key.key));

    offset += keylen;
    size_t rn_off = datafind3(data, offset, '\r', '\n');
    if (rn_off == 0) {
        NOTIFY(xdp, "Set but no rn");
        PKT_EVT.perf_submit(xdp, &keylen, sizeof(keylen));
        PASS(xdp);
    }

    offset = rn_off;

    size_t val_start = offset + 2;
    size_t val_end = datafind3(data, offset, '\r', '\n');
    if (val_end == 0) {
        NOTIFY(xdp, "Set but no value rn");
        PASS(xdp);
    }
    struct val_t val = {val_end - val_start};

    for (int i=0; i < sizeof(val.val); i++) {
        if (i < (val_end - val_start)) {
            val.val[i] = data->data[val_start + i];
        }
    }

    //notify(xdp, val.val, sizeof(val.val));

    MCD_MAP.update(&key, &val);

    void *data_h = (void*)(long)xdp->data;
    void *data_hend = (void*)(long)xdp->data_end;
    size_t orig_len = data_hend - data_h;

    struct hdrs *h = data_h;
    if (data_h + sizeof(*h) > data_hend) {
        NOTIFY(xdp, "HOW, THOUGH!");
        PASS(xdp);
    }
    struct hdrs h_orig = *h;

    //int rtn = bpf_xdp_adjust_head(xdp, -strlen(STORED_STR));

    void *data_n = (void*)(long)xdp->data;
    void *data_nend = (void*)(long)xdp->data_end;
    struct hdrs *h_new = data_n;
    if (data_n + sizeof(*h_new) > data_nend) {
        NOTIFY(xdp, "HOW, THOUGH!");
        PASS(xdp);
    }
    *h_new = h_orig;
    swap_direction(h_new);

    __u16 prevlen = (h_new->ip.tot_len);
    h_new->mcd.seq = 0;
    h_new->mcd.zero = 0;
    h_new->ip.tot_len = htons(sizeof(struct hdrs) + sizeof(STORED_STR) - 14);
    h_new->udp.len = htons(16 + sizeof(STORED_STR) - 1);
    h_new->udp.check = 0;
    //h_new->ip.check += htons(0x11);
    h_new->ip.check = incr_check_s(h_new->ip.check, ntohs(prevlen), ntohs(h_new->ip.tot_len));
    //
    char stored[] = STORED_STR;
    if (data_n + sizeof(*h_new) + strlen(STORED_STR) > data_nend) {
        NOTIFY(xdp, "HOW, THOUGH!");
        PASS(xdp);
    }
    memcpy(data_n + sizeof(*h_new), stored,  strlen(STORED_STR));

    value = storedcnt.lookup(&k);
    if (value)
        *value += 1;
    //return XDP_PASS;;
    return XDP_TX;
    //return tx_port.redirect_map(0,0);


    /*ssize_t keylen_s = tok(next, end, ' ');
    if (keylen_s < 0) {
        NOTIFY(skb, "SET but no space");
        return false;
    }
    size_t keylen = keylen_s;
    struct key_t key = {};
    if (keylen >= sizeof(key.key)) {
        NOTIFY(skb, "SET but too big!");
        )eturn false;
    }
    for (int i=0; i < sizeof(key.key); i++) {
        if (i < keylen) {
            key.key[i] = next[i];
        }
    }
    NOTIFY(skb, "Setting");
    notify(skb, key.key, MAX_KEYLEN);

    ssize_t ret_off = tok2(next, end, "\r\n", 2, MAX_KEYLEN);
    if (ret_off < 0) {
        NOTIFY(skb, "SET BUT No \\r\\n");
        return false;
    }
    next += ret_off;

    char *val_start = next;
    char *val_end = next;
    if (next + origlen < end) {
        //val_end = next + origlen;
    }

    ssize_t sval_ret = back_tok2(val_end,  end, '\r', '\n', 16);
    if (sval_ret < 0) {
        NOTIFY(skb, "SET BUT No val \\r\\n");
        return false;
    }
    size_t val_ret = sval_ret + 2;

    struct val_t val = {val_ret};
#pragma unroll
    for (int i=0; i < sizeof(val.val); i++) {
        if (i < val_ret) {
            val.val[i] = val_start[i];
        }
    }
    MCD_MAP.update(&key, &val);
    swap_direction(skb);
    char stored[] = STORED_STR;
    bpf_skb_store_bytes(skb, sizeof(struct hdrs),
                        &stored, sizeof(stored), 0);
    struct hdrs hdr;
    bpf_skb_load_bytes(skb, 0,  &hdr, sizeof(hdr));
    size_t prevlen = hdr.ip.tot_len;
    hdr.ip.tot_len = htons(sizeof(struct hdrs) + sizeof(STORED_STR) - 14);
    size_t prevudplen = hdr.udp.len;
    hdr.udp.len = htons(16 + sizeof(STORED_STR) - 1);
    hdr.mcd.seq = 0;
    hdr.mcd.zero = 0;
    hdr.udp.check = 0;
    bpf_skb_store_bytes(skb, 0, &hdr, sizeof(hdr), 0);
    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), prevlen, hdr.ip.tot_len, 2);
    //bpf_l4_csum_replace(skb, offsetof(struct hdrs, udp) + offsetof(struct udphdr, check), , u64 to, u64 flags)
    int rtn = bpf_skb_change_tail(skb, sizeof(struct hdrs) + sizeof(STORED_STR), 0);
    bpf_clone_redirect(skb, 7, 0);
    return true;
    */
}

int handle_ingress(struct xdp_md *xdp) {
    long *value;
    uint32_t key = 0;
    void *data = (void*)(long)xdp->data;
    void *data_end = (void*)(long)xdp->data_end;
    size_t data_len = (long)data_end - (long)data;

    struct hdrs *hdr_p = data;

    size_t hdrsize = sizeof(*hdr_p);
    if (data +sizeof(*hdr_p) > data_end) {
        NOTIFY(xdp, "TOO SMALL");
        PASS(xdp);
    }
    //PKT_EVT.perf_submit(xdp, &data_len, sizeof(data_len));
    //PKT_EVT.perf_submit(xdp, &hdrsize, sizeof(data_len));
    struct hdrs hdr = *hdr_p;
    if (hdr.udp.dest != htons(11211)) {
        NOTIFY(xdp, "WRONG PORT");
        PASS(xdp);
    }

    struct data_t *data_cp = datamap.lookup(&key);
    if (!data_cp) {
        NOTIFY(xdp, "NO DATA SLOT");
        PASS(xdp);
    }
    //void *data_nohdr = data + sizeof(hdr);

    CP_46(data_cp->data, data, data_end);


    //CP_10(data_cp->data, data, data_end);

    //notify(xdp, data_cp->data, sizeof(data_cp->data));

    /*if (handle_set(xdp, data_cp, data_len)) {
        return XDP_PASS;
    }*/
/*
    if (handle_get(xdp, data_cp, sizeof(data_cp))) {
        return XDP_PASS;
    }*/


    if (datacmp(data_cp, SET_CMD, strlen(SET_CMD))) {
        //return handle_set(xdp);
        prog_array.call(xdp, 1);
    }

    if (datacmp(data_cp, GET_CMD, strlen(GET_CMD))) {
        //return handle_get(xdp);
        prog_array.call(xdp, 2);
    }
    NOTIFY(xdp, "NOT 4 me");

    return XDP_PASS;


    /*

    struct hdrs *hdrs_p = data;
    size_t hdr_size = sizeof(*hdrs_p);
    if (data + sizeof(*hdrs_p) > data_end) {
        PKT_EVT.perf_submit(skb, &data_len, sizeof(data_len));
        PKT_EVT.perf_submit(skb, &hdr_size, sizeof(data_len));
        NOTIFY(skb, "too short");
        return TC_ACT_OK;
    }
    */
    //struct hdrs hdr = *hdrs_p;
/*
    if (hdr.udp.dest != htons(11211)) {
        NOTIFY(skb, "WRONG PORT");
        return TC_ACT_OK;
    }
    int rtn = bpf_skb_change_tail(skb, 1024, 0);
    char payload[100];
    bpf_skb_load_bytes(skb, sizeof(hdr), payload, 200);
    if (handle_set(skb, payload, data_len)) {
        return TC_ACT_REDIRECT;
    }

    if (handle_get(skb, payload, payload + 200)) {
        return TC_ACT_REDIRECT;
    }

    NOTIFY(skb, "NOTHING!");
    return TC_ACT_OK;
    */
}


