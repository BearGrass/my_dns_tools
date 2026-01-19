/*
 * Copyright (C)
 * Filename: dns.c
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#ifndef __DNS_H__
#define __DNS_H__

#define AS_DNSRES	0x1
#define AS_DNSQUERY	0x0
#define AS_DNSANSWER 0x1
#define RR_END		0x2b2b
#define RR_TYPE_ANAME	0x0001
#define RR_TYPE_CNAME	0x0005
#define RR_TYPE_NS	0x0002
#define RR_TYPE_PTR	0x000c
#define RR_TYPE_MX	0x000f
#define RR_TYPE_SOA	0x0006
#define RR_TYPE_TXT	0x0010
#define RR_TYPE_AAAA	0x001c
#define RR_CLASS_IN	0x0001

#define MAX_DNAME_LEN	255
#define MAX_DOMAIN_LABEL_LEN 63

/* dns package header */
struct as_dnshdr {
    __u16 id;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16 rd:1, tc:1, aa:1, opcode:4, qr:1, rcode:4, z:1, ad:1, cd:1, ra:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16 qr:1, opcode:4, aa:1, tc:1, rd:1, ra:1, z:1, ad:1, cd:1, rcode:4;
#endif
    __u16 questions;
    __u16 answer_rrs;
    __u16 authority_rrs;
    __u16 additional_rrs;
    uint8_t data[0];
};

/*
 * reserve for parse dns package
 */
struct as_dnsques {
    uint16_t qtype;
    uint16_t qclass;
    uint16_t qsize;
    uint8_t dot_num;
    char qname[255];
};

struct as_dnsans {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t nlen;
    uint32_t offset;
    char query[255];
    union {
        char ip[4];
        char name[255];
    }data;
};

#endif                          /* __DNS_H__ */
