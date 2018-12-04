#include<stdio.h>	//printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include <unistd.h>
#include<arpa/inet.h>
#include<sys/socket.h>

#include <iostream>
#include <sparsehash/dense_hash_map>
using google::dense_hash_map;      // namespace where class lives by default
using std::cout;
using std::endl;



#define MAX_KEYLEN 32
#define MAX_VALLEN 18

//using mkey_t = const char[MAX_KEYLEN];

struct mkey_t {
    size_t size;
    char key[MAX_KEYLEN];
    };

const struct mkey_t EMPTY_KEY = {};

struct val_t {
    size_t size;
    char val[MAX_VALLEN];
};

struct mcdhdr {
    uint16_t id;
    uint16_t seq;
    uint16_t tot;
    uint16_t zero;
};
struct eqstr
{
  bool operator()(const char* s1, const char* s2) const
  {
    return (s1 == s2) || (s1 && s2 && strcmp(s1, s2) == 0);
  }
};

static dense_hash_map<const std::string, struct val_t, std::hash<std::string>> MAP(3e7);

static inline ssize_t tok(const char *payload, const char *end, char tok) {
    for (int i=0; i < MAX_KEYLEN; i++) {
        if (payload + i > end) {
            return -1;
        }
        //printf("I IS %d; %c\n", i, payload[i]);
        if (payload[i] == tok) {
            return i;
        }
    }
    return -1;
}

static inline ssize_t tok2(const char *payload, const char *end, const char* tok, size_t toklen, size_t paylen) {
#pragma unroll
    for (int i=0; i < paylen; i++) {
        if (payload + i + toklen > end) {
            return -1;
        }
        bool found = true;
        //printf("II is %d; %c\n", i, payload[i]);
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
#pragma unroll
    for (size_t i=1; i < backlen; i++) {
        if (payload[i] == tok1 && payload[i+1] == tok2) {
            return i;
        }
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

static inline const char *mem_adv(const char *a, const char *b, const char *end, size_t l) {
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

#define SET_CMD "set "
#define GET_CMD "get "
#define MEM_ADV(a, b, end) \
    mem_adv(a, b, end, sizeof(b) - 1)

static inline bool handle_get(int sock, char *payload, size_t size, struct sockaddr_in *dst) {
    char *end = payload + size;
    if (!(MEM_ADV(payload + sizeof(struct mcdhdr), GET_CMD, end))) {
        return false;
    }
    char *next = payload + sizeof(struct mcdhdr) + strlen(GET_CMD);

    ssize_t keylen_s = tok2(next, end, "\r\n", 2, MAX_KEYLEN);
    if (keylen_s < 2) {
        printf("Keylen too small\n");
        return false;
    }

    size_t keylen = keylen_s - 2;

    struct mkey_t key = {};
    bzero(&key, sizeof(key));
    if (keylen >= sizeof(key.key)) {
        printf("keylen too large\n");
        return false;
    }

    memcpy(key.key, next, keylen);

    std::string k(key.key);
    auto val_it = MAP.find(k);
    if (val_it == MAP.end()) {
        printf("Not found\n");
        char output[sizeof(struct mcdhdr) + strlen(NOT_FOUND_STR)];
        memcpy(output, payload, sizeof(struct mcdhdr));
        memcpy(output + sizeof(struct mcdhdr), NOT_FOUND_STR, strlen(NOT_FOUND_STR));
        sendto(sock, output, sizeof(output), 0, (struct sockaddr*)dst, sizeof(*dst) );
        return true;
    }

    struct val_t val = val_it->second;

    char sizestr[6] = {};
    size_t sizesize = itoc(val.size - 2, sizestr);
    char resp[sizeof(struct mcdhdr) + strlen(VAL_STR) + keylen + strlen(FLAG_STR) + sizesize + 2 + val.size + strlen(END_STR)];

    char *off = resp;
    memcpy(off, payload, sizeof(struct mcdhdr));
    off += sizeof(struct mcdhdr);

    memcpy(off, VAL_STR, strlen(VAL_STR));
    off += strlen(VAL_STR);

    memcpy(off, key.key, keylen);
    off += keylen;

    memcpy(off, FLAG_STR, strlen(FLAG_STR));
    off += strlen(FLAG_STR);

    memcpy(off, sizestr, sizesize);
    off += sizesize;

    memcpy(off, "\r\n", 2);
    off += 2;

    memcpy(off, val.val, val.size);
    off += val.size;

    memcpy(off, END_STR, strlen(END_STR));
    off += strlen(END_STR);

    sendto(sock, resp, sizeof(resp), 0, (struct sockaddr*)dst, sizeof(*dst) );

    return true;

}

#define IP_CSUM_OFFSET (ETH_HLEN + offsetof(struct iphdr, check))
#define STORED_STR "STORED\r\n"

static inline bool handle_set(int sock, char *payload, size_t size, struct sockaddr_in *dst) {
    char *end = payload + size;
    char *next;
    if (!(next = (char*)MEM_ADV(payload + sizeof(struct mcdhdr), SET_CMD, end))) {
        return false;
    }
    ssize_t keylen_s = tok(next, end, ' ');
    if (keylen_s < 0) {
        printf("Neg keylen\n");
        return false;
    }
    size_t keylen = keylen_s;
    struct mkey_t key = {};
    bzero(&key, sizeof(key));
    if (keylen >= sizeof(key.key)) {
        printf("Keylen too long\n");
        return false;
    }
    memcpy(key.key, next, keylen);

    ssize_t ret_off = tok2(next, end, "\r\n", 2, MAX_KEYLEN);
    if (ret_off < 0) {
        printf("ret_off < 0\n");
        return false;
    }
    next += ret_off;

    char *val_start = next;
    char *val_end = next;

    ssize_t sval_ret = tok2(val_end,  end, "\r\n", 2, MAX_VALLEN * 2);
    if (sval_ret < 0) {
        printf("sval_ret < 0\n");
        return false;
    }
    size_t val_ret = sval_ret + 2;

    struct val_t val = {val_ret};
    memcpy(val.val, val_start, val_ret);

    std::string k(key.key);
    MAP[k] = val;

    char output[sizeof(struct mcdhdr) + strlen(STORED_STR)];
    memcpy(output, payload, sizeof(struct mcdhdr));
    memcpy(output + sizeof(struct mcdhdr), STORED_STR, strlen(STORED_STR));
    sendto(sock, output, sizeof(output), 0, (struct sockaddr*)dst, sizeof(*dst) );
    return true;
}

int main(int argc, char **argv) {
    std::string k("");
    MAP.set_empty_key(k);
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1) {
        perror("socket");
        return -1;
	}

    struct sockaddr_in si = {};
    si.sin_family = AF_INET;
    si.sin_port = htons(11211);
	si.sin_addr.s_addr = htonl(INADDR_ANY);

    if ( bind(s, (struct sockaddr*)&si, sizeof(si)) != 0) {
        perror("bind");
        return -1;
    }

    struct sockaddr_in recved;
    socklen_t rcvlen = sizeof(recved);
    char buff[2048];
    while (1) {
        ssize_t len =  recvfrom(s, buff, 2048, 0, (struct sockaddr *) &recved, &rcvlen);
        if (len == -1) {
            perror("read");
            return -1;
        }

        if (handle_set(s, buff, len, &recved)) {
            continue;
        }
        handle_get(s, buff, len, &recved);
    }
    return 0;
}
