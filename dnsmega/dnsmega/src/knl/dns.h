/*
 * Copyright (C)
 * Filename: dns.c
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#ifndef __DNS_H__
#define __DNS_H__

#define DM_DNSRES	0x1
#define DM_DNSQUERY	0x0
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

#define DM_RR_HEAD	(3 * sizeof(__u16) + sizeof(__u32))
//#define RR_NUM        16
#define RR_NUM		32
#define MAX_RR_SIZE	(256 + DM_RR_HEAD)
#define MAX_DOMAIN_SIZE	256

/* dns package header */
struct dm_dnshdr {
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
    char data[0];
};

/*
 * reserve for parse dns package
 */
struct dm_dnsques {
    uint16_t qtype;
    uint16_t qclass;
    uint16_t qsize;
    uint8_t dot_num;
    char qname[255];
};

struct dm_dnsans {
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

/*
struct dm_rr_t {
    char *value;
    __u16 len;
};
struct dm_aname_t {
    struct dm_rr_t rrs[RR_NUM];
    __u8 weight[RR_NUM];
    __u8 refcnt[RR_NUM];
    __u8 pos;
    __u8 num;
    spinlock_t lock;
};
struct dm_otherRR {
    struct dm_rr_t rrs;
    __u8 num;
    __u16 rr_len[RR_NUM];
};
#define dm_ns_t	dm_otherRR
#define dm_txt_t	dm_otherRR
#define dm_mx_t	dm_otherRR
#define dm_cname_t	dm_otherRR
#define dm_ptr_t	dm_otherRR
#define dm_soa_t	dm_otherRR
*/

extern int
parse_dns_message(struct dm_dnshdr *dnshdr, uint16_t dns_len,
        struct dm_dnsques *dnsques, struct dm_dnsans dnsans[], int *ansnum);

#endif                          /* __DNS_H__ */
