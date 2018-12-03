#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

BPF_PERF_OUTPUT(NOTIFY_EVT);
BPF_PERF_OUTPUT(PKT_EVT);

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest),(src),(n))
#endif


#ifndef memset
#define memset(dest, src, n) __builtin_memset((dest),(src),(n))
#endif

#define MEMCPY(dest, src, n)\
for (int i=0; i < n; i++) dest[i] = src[i];

#define MAX_NOT 32

#define MAX_KEYLEN 32
#define MAX_VALLEN 18

struct key_t {
    char key[MAX_KEYLEN];
};

struct val_t {
    size_t size;
    char val[MAX_VALLEN];
};

BPF_HASH(MCD_MAP, struct key_t, struct val_t, 3e7);

struct not_t {
    size_t len;
    char msg[MAX_NOT];
};

static inline void notify(struct __sk_buff *skb, const char *str, size_t len) {
    return;
    struct not_t n = {};
    n.len = len;
    memcpy(n.msg, str, len > MAX_NOT ? MAX_NOT : len);
    NOTIFY_EVT.perf_submit(skb, &n, sizeof(n));
}

#define NOTIFY(skb, str) \
    notify(skb, str, sizeof(str) + 1)

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

#define SWAP(skb, base, basename, basestruct, f1, f2) \
    bpf_skb_store_bytes(skb, offsetof(struct hdrs, basename) + offsetof(basestruct, f1), \
                        &(base).basename.f2, sizeof((base).basename.f2), 0); \
    bpf_skb_store_bytes(skb, offsetof(struct hdrs, basename) + offsetof(basestruct, f2), \
                        &(base).basename.f1, sizeof((base).basename.f1), 0); \

static inline void swap_direction(struct __sk_buff *skb) {
    void *end = (void*)(long)skb->data_end;
    struct hdrs *hdrs_p = (void*)(long)skb->data;
    if ((void*)hdrs_p + sizeof(*hdrs_p) > end) {
        return;
    }
    struct hdrs hdrs = *hdrs_p;

    SWAP(skb, hdrs, eth, struct ethhdr, h_source, h_dest);
    SWAP(skb, hdrs, ip, struct iphdr, saddr, daddr);
    SWAP(skb, hdrs, udp, struct udphdr, source, dest);
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

static inline void *mem_adv(char *a, char *b, char *end, size_t l) {
    if (a + l > end) {
        return NULL;
    }
#pragma unroll
    for (int i=0; i < l; i++) {
        if (a[i] != b[i]) {
            return NULL;
        }
    }
    return a + l;
}

#define MEM_ADV(a, b, end) \
    mem_adv(a, b, end, sizeof(b) - 1)


static inline ssize_t tok(char *payload, char *end, char tok) {
    for (int i=0; i < MAX_KEYLEN; i++) {
        if (payload + i > end) {
            return -1;
        }
        if (payload[i] == tok) {
            return i;
        }
    }
    return -1;
}

static inline ssize_t tok2(char *payload, char *end, char* tok, size_t toklen, size_t paylen) {
#pragma unroll
    for (int i=0; i < paylen; i++) {
        if (payload + i + toklen > end) {
            return -1;
        }
        bool found = true;
        for (int j=0; j < toklen; j++) {
            if (payload[i+j] != tok[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return i + toklen;
        }
    }
    return -1;
}

static inline ssize_t back_tok2(char *payload, char *end, char tok1, char tok2, size_t backlen) {
    //size_t paylen = end - payload;
#pragma unroll
    for (size_t i=1; i < backlen; i++) {
        if (payload[i] == tok1 && payload[i+1] == tok2) {
            return i;
        }
        //if (payload[idx+1] != tok2) {
        //    continue;
        //}
        //return (size_t)(idx + 2);
    }
    return -1;
}


#define NOT_FOUND_STR "NOT_FOUND\r\n"
#define VAL_STR "VALUE "
#define FLAG_STR " 0 "
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

static inline bool handle_get(struct __sk_buff *skb, char *payload, char *end) {
    char *next;
    if (!(next = MEM_ADV(payload, GET_CMD, end))) {
        return false;
    }

    ssize_t keylen_s = tok2(next, end, "\r\n", 2, MAX_KEYLEN);
    if (keylen_s < 2) {
        NOTIFY(skb, "GET with no key");
        return false;
    }

    size_t keylen = keylen_s;
    struct key_t key = {};
    if (keylen >= sizeof(key.key)) {
        NOTIFY(skb, "GET but too big!");
        return false;
    }

#pragma unroll
    for (int i=0; i < sizeof(key.key); i++) {
        if (i < keylen - 2) {
            key.key[i] = next[i];
        }
    }
    //notify(skb, key.key, MAX_KEYLEN);

    struct val_t *val = MCD_MAP.lookup(&key);
    if (val == NULL) {
        char msg[] = NOT_FOUND_STR;
        bpf_skb_store_bytes(skb, sizeof(struct hdrs),
                            &msg, sizeof(msg), 0);
        int rtn = bpf_skb_change_tail(skb, sizeof(struct hdrs) + sizeof(msg), 0);
        bpf_clone_redirect(skb, 5, 0);
        return true;
    }
    size_t off = sizeof(struct hdrs);
    char valstr[] = VAL_STR;
    bpf_skb_store_bytes(skb, off,
                        &valstr, sizeof(valstr), 0);
    off += sizeof(valstr) - 1;
    bpf_skb_store_bytes(skb, off,
                        &key.key, keylen , 0);

    off += keylen - 2;
    char flagsstr[] = FLAG_STR;
    bpf_skb_store_bytes(skb, off,
                        &flagsstr, sizeof(flagsstr), 0);

    off += sizeof(flagsstr) - 1;
    char sizestr[6] = {};
    size_t sizesize = itoc(val->size - 2, sizestr);
    bpf_skb_store_bytes(skb, off,
                        &sizestr, 6, 0);

    off += sizesize ;
    char delim[] = "\r\n";
    bpf_skb_store_bytes(skb, off,
                        &delim, sizeof(delim), 0);

    off += sizeof(delim) - 1;
    bpf_skb_store_bytes(skb, off,
                        &val->val, MAX_VALLEN, 0);
    off += val->size;

    char endstr[] = END_STR;
    bpf_skb_store_bytes(skb, off,
                        &endstr, sizeof(endstr), 0);
    off += sizeof(endstr) - 1;

    swap_direction(skb);
    struct hdrs hdr;
    bpf_skb_load_bytes(skb, 0,  &hdr, sizeof(hdr));
    size_t prevlen = hdr.ip.tot_len;
    hdr.ip.tot_len = htons(off - 14);
    size_t prevudplen = hdr.udp.len;
    hdr.udp.len = htons(off - sizeof(struct hdrs) + sizeof(struct udphdr) + sizeof(struct mcdhdr));
    hdr.mcd.seq = 0;
    hdr.mcd.zero = 0;
    hdr.udp.check = 0;
    bpf_skb_store_bytes(skb, 0, &hdr, sizeof(hdr), 0);
    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), prevlen, hdr.ip.tot_len, 2);

    int rtn = bpf_skb_change_tail(skb, off, 0);
    bpf_clone_redirect(skb, 7, 0);


    return true;

}

#define IP_CSUM_OFFSET (ETH_HLEN + offsetof(struct iphdr, check))
#define STORED_STR "STORED\r\n"

static inline bool handle_set(struct __sk_buff *skb, char *payload, size_t origlen) {
    char *end = payload + origlen;
    char *next;
    if (!(next = MEM_ADV(payload, SET_CMD, end))) {
        return false;
    }
    ssize_t keylen_s = tok(next, end, ' ');
    if (keylen_s < 0) {
        NOTIFY(skb, "SET but no space");
        return false;
    }
    size_t keylen = keylen_s;
    struct key_t key = {};
    if (keylen >= sizeof(key.key)) {
        NOTIFY(skb, "SET but too big!");
        return false;
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
}

int handle_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    size_t data_len = (long)data_end - (long)data;

    struct hdrs hdr;
    bpf_skb_load_bytes(skb, 0,  &hdr, sizeof(hdr));

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
}


