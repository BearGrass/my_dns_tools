
#ifndef _DNS_PACKET_H_
#define _DNS_PACKET_H_

#include <stdint.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include "edns.h"
#include "common.h"
#include "consts.h"
#include "rte_core.h"
#include "wire.h"
#include "iplib.h"
#include "ip_filter.h"
#include "ldns.h"
#include "view.h"
#include "stats.h"
#include "tolower.h"


#define DNS_PORT 53
#define HTTP_PORT 80

// Maximum udp payload with edns disabled, 512-8B dns header
#define MAX_UDP_PAYLOAD 512
#define  DNS_EDNS0_MAX_LENGTH 1408
#define ADNS_DNAME_MAXLEN 255     /*!< 1-byte maximum. */
#define LABEL_MAX_SIZE      63
#define ADNS_DNAME_MAXLABELS 127  /*!< 1-char labels. */
#define ADNS_RESPONSE_RECORD_MAX_LEN 128
#define MAX_COMPRESSION_DEPTH 10

#define IPV4_HDR_OFFSET_MF_MASK ((1 << IPV4_HDR_DF_SHIFT) - 1)

#ifndef IP_MAX_LEN 
#define IP_MAX_LEN 15
#endif

#ifndef PORT_MAX_LEN
#define PORT_MAX_LEN 5
#endif

#define NIP6_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define NIP6(addr) \
        (unsigned)((addr)[0]), \
(unsigned)((addr)[1]), \
(unsigned)((addr)[2]), \
(unsigned)((addr)[3]), \
(unsigned)((addr)[4]), \
(unsigned)((addr)[5]), \
(unsigned)((addr)[6]), \
(unsigned)((addr)[7]), \
(unsigned)((addr)[8]), \
(unsigned)((addr)[9]), \
(unsigned)((addr)[10]), \
(unsigned)((addr)[11]), \
(unsigned)((addr)[12]), \
(unsigned)((addr)[13]), \
(unsigned)((addr)[14]), \
(unsigned)((addr)[15])


#define adns_ntohs(x) rte_be_to_cpu_16(x)
#define adns_ntohl(x) rte_be_to_cpu_32(x)
#define adns_htons(x) rte_cpu_to_be_16(x)
#define adns_htonl(x) rte_cpu_to_be_32(x)

#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)

#define ICMPV6_ECHO_REQUEST     128
#define ICMPV6_ECHO_REPLY       129

#define SRV_TYPE_REC 0
#define SRV_TYPE_AUTH 1
#define SRV_TYPE_SEC 2
#define SRV_TYPE_NUM (SRV_TYPE_SEC + 1)
extern const char *g_srv_type_string[SRV_TYPE_NUM];

union common_ip_head {
    struct ipv4_hdr ipv4_hdr;
    struct ipv6_hdr ipv6_hdr;
};

union common_l4_head {
    struct udp_hdr udp_hdr;
    struct tcp_hdr tcp_hdr;
};

union common_ip {
    uint32_t client_ip;
    struct in6_addr client_ipv6;
};

struct ipv6_opt_hdr {
    uint8_t nexthdr;
    uint8_t hdrlen;
} __attribute__((packed));

struct dns_header {
	uint16_t id;
	uint8_t flags1;
	uint8_t flags2;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

struct adns_response {
    uint8_t *wire;
    int16_t size;
    int16_t parsed;

    char answer_content[ADNS_RESPONSE_RECORD_MAX_LEN];
    char authority_content[ADNS_RESPONSE_RECORD_MAX_LEN];
    char additional_content[ADNS_RESPONSE_RECORD_MAX_LEN];
} __attribute__((packed));

struct dns_chaos_answer {
    uint16_t cdomain;
    uint16_t ctype;
    uint16_t cclass;
    uint32_t cttl;
    uint16_t clen;
    uint8_t buf[0];
} __attribute__((packed));

struct dns_packet {
    uint16_t ip_ver;
    union {
        uint32_t client_ip;
        struct in6_addr client_ipv6;
    };
    adns_viewid_t cli_view;
	struct dns_header header;
	uint16_t qtype;
	uint16_t qclass;

	uint8_t qname[NAME_MAX_LEN+10];
	char dname[NAME_MAX_LEN];
	uint8_t dname_len;
	uint8_t zname_offset;
    uint8_t label_offset[NAME_MAX_LEN];
	uint16_t qname_size;
    uint8_t labels;
	uint8_t *wire;
	size_t size;

    adns_opt_rr_t opt_rr;
    uint8_t has_edns; /* flag indicates if query has edns0 */
    uint8_t has_ecs; /* flag indicates if query has ecs */
            //has_cookie :1, /* flag indicates if query has cookie */
            //do_dnssec :1; /* flag indicates if query require dnssec */
    uint8_t srv_type; /* flag indicates what service type this packet is handling */
    size_t parsed;
    uint16_t answer_max_size;    /* initialized at adns_parse_additional function */
    int16_t answered;    /* initialized at adns_parse function */
    //int16_t answer_section_offset;    /* initialized at adns_parse function */
    view_db_t *views;
};

#define ETH_HLEN (sizeof(struct ether_hdr))
#define IP_HLEN (sizeof(struct ipv4_hdr))
#define UDP_HLEN (sizeof(struct udp_hdr))
#define DNS_HLEN (sizeof(struct dns_header))

static inline uint8_t
set_srv_type(struct dns_packet *pkt, union common_ip_head *ip_head) {
    // default server type
    pkt->srv_type = SRV_TYPE_REC;

    if (pkt->ip_ver == 4) {
        if (get_ip_filter(ip_head->ipv4_hdr.dst_addr, IP_FILTER_MASK_CACHE)) {
            pkt->srv_type = SRV_TYPE_AUTH;
        } else if (get_ip_filter(ip_head->ipv4_hdr.dst_addr,
                IP_FILTER_MASK_SEC)) {
            pkt->srv_type = SRV_TYPE_SEC;
        }/* else if (get_ip_filter(ip_head->ipv4_hdr.dst_addr,
                IP_FILTER_MASK_RECUS)) {
            pkt->srv_type = SRV_TYPE_REC;
        }*/
    } else if (pkt->ip_ver == 6) {
        ipv6_filter *ip6_info = get_ipv6_filter_info(
                ip_head->ipv6_hdr.dst_addr);
        if (get_ipv6_filter_by_info(ip6_info, IP_FILTER_MASK_CACHE)) {
            pkt->srv_type = SRV_TYPE_AUTH;
        } else if (get_ipv6_filter_by_info(ip6_info, IP_FILTER_MASK_SEC)) {
            pkt->srv_type = SRV_TYPE_SEC;
        }/* else if (get_ipv6_filter_by_info(ip6_info, IP_FILTER_MASK_RECUS)) {
            pkt->srv_type = SRV_TYPE_REC;
        }*/
    }

    return pkt->srv_type;
}

static inline uint16_t
get_psd_sum(void *l3_hdr, uint16_t ethertype, uint64_t ol_flags)
{
    if (ethertype == ETHER_TYPE_IPv4)
        return rte_ipv4_phdr_cksum(l3_hdr, ol_flags);
    else /* assume ethertype == ETHER_TYPE_IPV4*/
        return rte_ipv6_phdr_cksum(l3_hdr, ol_flags);
}

static inline int ipv6_ext_hdr(uint8_t nexthdr)
{
    /*
     * find out if nexthdr is an extension header or a protocol
     */
    return (nexthdr == IPPROTO_HOPOPTS)   ||
        (nexthdr == IPPROTO_ROUTING)  ||
        (nexthdr == IPPROTO_FRAGMENT) ||
        (nexthdr == IPPROTO_AH)     ||
        (nexthdr == IPPROTO_NONE)     ||
        (nexthdr == IPPROTO_DSTOPTS);
}

/* simplify from Exthdrs_core.c in 7u kernel */
static inline int
ipv6_skip_exthdr(struct ipv6_hdr *pkt, uint8_t *offset, uint16_t *ip_pld_len)
{
    struct ipv6_opt_hdr *hp;
    unsigned int start = sizeof(struct ipv6_hdr);
    uint8_t nexthdr = pkt->proto;
    int hdrlen;
    while (ipv6_ext_hdr(nexthdr)) {
        if (nexthdr == IPPROTO_NONE) {
            return -1;
        }
        if (unlikely(*ip_pld_len < sizeof(struct ipv6_opt_hdr))) {
            return -1;
        }
        hp = (struct ipv6_opt_hdr *)((uint8_t*)pkt + start);
        /* we need check whether hp is illegal or not */
        if (nexthdr == IPPROTO_FRAGMENT) {
            hdrlen = 8;
        } else if (nexthdr == IPPROTO_AH) {
            hdrlen = (hp->hdrlen + 2) << 2;
        } else {
            hdrlen = ipv6_optlen(hp);
        }
        nexthdr = hp->nexthdr;
        start += hdrlen;

        if(unlikely(*ip_pld_len < hdrlen)) {
            return -1;
        }
        (*ip_pld_len) -= hdrlen;
    }
    *offset = start;
    return nexthdr;
}

static inline void
l3_output_ipv6(struct ipv6_hdr *iph6)
{
    uint8_t tmp_addr[16];
    rte_memcpy(tmp_addr, iph6->src_addr, sizeof(iph6->src_addr));
    rte_memcpy(iph6->src_addr, iph6->dst_addr, sizeof(iph6->src_addr));
    rte_memcpy(iph6->dst_addr, tmp_addr, sizeof(iph6->dst_addr));
}

static inline int is_valid_ipv6_pkt(struct ipv6_hdr *pkt, uint32_t link_len,
        uint16_t *ip_pld_len, uint8_t *offset)
{
    if (unlikely(link_len < sizeof(struct ipv6_hdr)))
        return -1;
    *ip_pld_len = adns_htons(pkt->payload_len);

    if (unlikely((link_len - sizeof(struct ipv6_hdr)) < *ip_pld_len)) {
        return -1;
    }

    return ipv6_skip_exthdr(pkt, offset, ip_pld_len);
}

static inline int is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len,
        uint16_t *ip_pld_len, uint8_t *offset)
{
	if (unlikely(link_len < sizeof(struct ipv4_hdr)))
		return -1;
	*ip_pld_len = adns_htons(pkt->total_length);

    if (unlikely(link_len < *ip_pld_len))
        return -2;

	if (unlikely(((pkt->version_ihl) >> 4) != 4))
		return -3;

	*offset = (pkt->version_ihl & 0xf) << 2;
	if (unlikely(*offset < sizeof(struct ipv4_hdr)))
		return -4;

	if (unlikely(*ip_pld_len < *offset))
		return -5;
	(*ip_pld_len) -= *offset;

	return 0;
}

static inline struct ipv4_hdr * dns_ipv4_hdr(struct rte_mbuf *m)
{
    return (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + ETH_HLEN);
}

static inline struct udp_hdr *dns_udp_hdr(struct rte_mbuf *m, struct ipv4_hdr *iph)
{
    return (struct udp_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + ETH_HLEN 
        + ((iph->version_ihl & 0xf) << 2));
}


static inline int dns_packet_qdcount(const struct dns_packet *packet)
{
	return packet->header.qdcount;
}

static inline int dns_packet_ancount(const struct dns_packet *packet)
{
	return packet->header.ancount;
}

static inline int dns_packet_nscount(const struct dns_packet *packet)
{
	return packet->header.nscount;
}

static inline int dns_packet_arcount(const struct dns_packet *packet)
{
	return packet->header.arcount;
}

static inline int pkt_parse_available(const struct dns_packet *pkt, int16_t count)
{
    return count <= (pkt->size - pkt->parsed);
}

static inline void pkt_parse_read(struct dns_packet *pkt, void *data, int16_t count)
{
    if (pkt->parsed + count > pkt->size) {
        return;
    }

    memcpy(data, pkt->wire + pkt->parsed, count);
    pkt->parsed += count;
}

static inline uint8_t pkt_parse_read_u8(struct dns_packet *pkt)
{
    uint8_t res;

    //assert(pkt_parse_available(pkt, sizeof(uint8_t)));
    if(pkt_parse_available(pkt, sizeof(uint8_t)) == 0){
        return 0;
    }

    res = *(pkt->wire + pkt->parsed);
    pkt->parsed += 1;
    return res;
}

static inline uint16_t pkt_parse_read_u16(struct dns_packet *pkt)
{
    uint16_t res;

    //assert(pkt_parse_available(pkt, sizeof(uint16_t)));
    if(pkt_parse_available(pkt, sizeof(uint16_t)) == 0){
        return 0;
    }

    res = adns_wire_read_u16(pkt->wire + pkt->parsed);
    pkt->parsed += 2;
    return res;
}
static inline uint32_t pkt_parse_read_u32(struct dns_packet *pkt)
{
    uint32_t res;

    //assert(pkt_parse_available(pkt, sizeof(uint32_t)));
    if(pkt_parse_available(pkt, sizeof(uint32_t)) == 0){
        return 0;
    }

    res = adns_wire_read_u32(pkt->wire + pkt->parsed);
    pkt->parsed += 4;
    return res;
}

/*
 *  * If domain node found, but cannot find target rrset, should response with noerror
 *   * rcode set.
 *    */
static inline void resp_set_noerror(struct dns_header *dnh)
{
    //qr, aa, ip_checksum, udp_checksum is set in resp_set_header
    ldns_wire_set_rcode((uint8_t *)dnh, DNS_RCODE_NOERROR);
}

static inline void resp_set_refuse(struct dns_header *dnh)
{
    ldns_wire_set_rcode((uint8_t *)dnh, DNS_RCODE_REFUSED);
}

static inline void resp_set_srvfail(struct dns_header *dnh)
{
    ldns_wire_set_rcode((uint8_t *)dnh, DNS_RCODE_SERVFAIL);
}

static inline void
resp_init_header(struct dns_header *dnh)
{
    ldns_wire_set_ra((uint8_t *)dnh); /* support recursion */
    ldns_wire_set_aa((uint8_t *)dnh); /* authority server */
    ldns_wire_clear_ad((uint8_t *)dnh); /* clear AD bit */
    ldns_wire_set_qdcount((uint8_t *)dnh, 1); /* only one question */
    ldns_wire_set_qr((uint8_t *)dnh); /* set QR bit */
    ldns_wire_clear_tc((uint8_t *)dnh); /* don't support truncation */
    ldns_wire_clear_z((uint8_t *)dnh);  /* clear Z flag (See RFC1035, 4.1.1. Header section format)*/
}

/*
 * edns-client-subnet format
 * option-code                     uint16_t
 * option-length                   uint16_t
 * family                          uint16_t
 * souce netmask | scope netmask   uint8_t | uint8_t
 * address...                      variable
 */
static inline int
adns_parse_ecs(struct dns_packet *packet, uint16_t opt_len, uint8_t is_query)
{
    struct adns_opt_ecs *ecs = &packet->opt_rr.opt_ecs;

    uint16_t i, addr_len;

    /* if we have already seen a well formed ECS option, skip this ECS option */
    if (unlikely(packet->has_ecs)) {
        packet->parsed += opt_len;
        return 0;
    }
    ecs->length = opt_len;

    if (unlikely(opt_len < 4)) {
        return -1;
    }

    /* get ecs family */
    uint16_t family = pkt_parse_read_u16(packet);
    /* get ecs source mask */
    uint8_t src_mask = pkt_parse_read_u8(packet);
    /* get ecs scope mask */
    ecs->scope_mask = pkt_parse_read_u8(packet);
    opt_len -= 4;

    /* scope mask must be zero for queries */
    if (is_query && unlikely(ecs->scope_mask)) {
        return -1;
    }

    switch (family) {
        case 0:
            if (unlikely(src_mask != 0)) {
                return -1;
            }
            break;
        case ECS_FAMILY_IPV4:
            if (unlikely(src_mask > 32)) {
                return -1;
            }
            ecs->addr.v4 = 0;
            break;
        case ECS_FAMILY_IPV6:
            if (unlikely(src_mask > 128)) {
                return -1;
            }
            ecs->addr.v64[0] = 0;
            ecs->addr.v64[1] = 0;
            break;
        default:
            return -1;
    }
    ecs->src_mask = src_mask;
    ecs->family = family;
    addr_len = (src_mask + 7) / 8;
    for (i = 0; i < addr_len; i++) {
        ecs->addr.v61[i] = pkt_parse_read_u8(packet);
    }
    ecs->addr_len = addr_len;

    if (unlikely(opt_len < addr_len)) {
        return -1;
    }
    opt_len -= addr_len;

    if (unlikely(opt_len > 0)) {
        packet->parsed += opt_len;
    }

    packet->has_ecs = 1;

    return 0;
}

static inline int
adns_parse_edns(struct dns_packet *packet, uint8_t is_query) {
    /*
     * edns0 format
     * Filed name    Filed type      Description
     * ------------------------------------------
     * NAME          domain name     empty(root domain)
     * TYPE          uint16_t        OPT
     * CLASS         uint16_t        sender's UDP payload size
     * TTL           uint32_t        extended RCODE and flags
     * RDLEN         uint16_t        describes RDATA
     * RDATA         octet stream    {attr, value} pairs
     */
    /* has checked outside
    uint8_t opt_owner = pkt_parse_read_u8(packet);
    uint16_t opt_type = pkt_parse_read_u16(packet);

    if (opt_owner != 0 || opt_type != EDNS_OPT) {
        return 0;
    }
    */
    /* class - sender's UDP payload size */
    uint16_t opt_class = pkt_parse_read_u16(packet);
    if (opt_class < MAX_UDP_PAYLOAD) {
        packet->answer_max_size = MAX_UDP_PAYLOAD;
    } else if (opt_class > DNS_EDNS0_MAX_LENGTH) {
        packet->answer_max_size = DNS_EDNS0_MAX_LENGTH;
    } else {
        packet->answer_max_size = opt_class;
    }
   /*
    * ttl - extended RCODE and flags
    * extended rcode(uint8_t) | version(uint8_t) | zero flags(uint16_t)
    */
   pkt_parse_read_u8(packet);
   uint8_t opt_version = pkt_parse_read_u8(packet);
   packet->opt_rr.version = opt_version;

   /* if EDNS version is not zero, no need to parse following part of EDNS */
   if (unlikely(opt_version != 0)) {
       packet->has_edns = 1;
       return 0;
   }

   pkt_parse_read_u16(packet);

   /* rdlen -- describes rdata */
   uint16_t opt_rdlen = pkt_parse_read_u16(packet);
   if (likely(opt_rdlen == 0)) {
       packet->has_edns = 1;
       return 0;
   }

   if (unlikely(packet->size - packet->parsed < opt_rdlen)) {
       return -1;
   }

   int ret = 0;
   while ((packet->size - packet->parsed) >= 4) {
       uint16_t opt_code = pkt_parse_read_u16(packet);
       uint16_t opt_len = pkt_parse_read_u16(packet);
       if (unlikely((packet->size - packet->parsed) < opt_len)) {
           return -1;
       }

       switch (opt_code) {
           /* edns client subnet */
           case EDNS_OPTION_ECS:
               ret = adns_parse_ecs(packet, opt_len, is_query);
               break;
           /* cookie */
           /*
           case EDNS_OPTION_COOKIE:
               ret = adns_parse_cookie(packet, opt_len);
               break;
           */
           /* other option not support */
           default:
                /* skip the unsupport option */
                packet->parsed += opt_len;
                break;
        }
        if (unlikely(ret < 0)) {
            return -1;
        }
    }

    packet->has_edns = 1;

    return 0;
}

static inline int get_an_name(const uint8_t *name, uint16_t name_len, uint8_t depth,
        const uint8_t * endp, uint8_t * dnh_pos, char *dname, uint8_t *an_name,
        const char *sec_name, uint16_t *len) {
    uint8_t lblen = 0;
    const uint8_t *next_label;

    //if (unlikely(name == NULL))
    //  return -EINVAL;

    /* Count name size without terminal label. */
    while (*name != '\0') {
        /* Check bounds (must have at least 2 octets remaining). */
        if (unlikely(name + 2 > endp)) {
            STATS(DNS_PKT_LEN_ERR);
/*            ALOG(SERVER, WARN,
                    "Current offset (%d) exceed the total packet length (%d) at node [%s], depth = %d In %s",
                    (name + 2 - dnh_pos), (endp - dnh_pos), dname, depth,
                    sec_name);*/
            return -ENOSPC;
        }

        /* Compression pointer is 2 octets. */
        if (adns_wire_is_pointer(name)) {
            if(unlikely(depth >= MAX_COMPRESSION_DEPTH)){
                STATS(DNAME_COMP_ERR);
/*                ALOG(SERVER,WARN,"Too many compression depth at node [%s], depth = %d In %s",dname, depth, sec_name);*/
                return -1;
            }

            //assert((wire[0] & 0xc0) == 0xc0);
            uint16_t p_offset = ((name[0] & ~0xc0) << 8) | name[1];
            //ALOG(ANSWER,INFO,"Offset %d\n",p_offset);
            if (unlikely(p_offset < LDNS_WIRE_HEADER_SIZE)) {
                STATS(DNAME_COMP_ERR);
/*                ALOG(SERVER, WARN,
                        "The compress offset (%d) is before the dns query section in answer name at node [%s], depth = %d in %s",
                        p_offset, dname, depth, sec_name);*/
                return -1;
            }

            if (unlikely(dnh_pos + p_offset >= name)) {
                STATS(DNAME_COMP_ERR);
/*                ALOG(SERVER, WARN,
                        "The compress offset (%d) is after current offset (%d) in answer name at node [%s], depth = %d in %s",
                        p_offset, (name - dnh_pos), dname, depth, sec_name);*/
                return -1;
            }

            if(len != NULL) {
                *len = name_len + 2;
            }
            return get_an_name(dnh_pos + p_offset, name_len, ++depth, endp, dnh_pos, dname, an_name, sec_name, NULL);
        }

        /* Check label length (maximum 63 bytes allowed). */
        if (unlikely(*name > LABEL_MAX_SIZE)) {
            STATS(DNAME_PARSE_ERR);
/*            ALOG(SERVER, WARN,
                    "The label length (%d) exceeds max value (%d) in answer name at node [%s], depth = %d in %s",
                    *name, LABEL_MAX_SIZE, dname, depth, sec_name);*/
            return -1;
        }

        lblen = *name + 1;
        if (unlikely(name_len + lblen >= ADNS_DNAME_MAXLEN)) {
            STATS(DNAME_PARSE_ERR);
/*            ALOG(SERVER, WARN,
                    "Get answer name will too long [cur[%d] + %d + 1 > %d ] at node [%s], depth = %d in %s",
                    name_len, lblen, ADNS_DNAME_MAXLEN, dname, depth, sec_name);*/
            return -1;
        }
        next_label = name + lblen;
        // Check if there's enough space in the name buffer.
        if (unlikely(next_label >= endp)) {
            STATS(DNS_PKT_LEN_ERR);
/*            ALOG(SERVER, WARN,
                    "Next label offset (%d) exceed the total packet length (%d) at node [%s], depth = %d In %s",
                    (next_label - dnh_pos), (endp - dnh_pos), dname, depth,
                    sec_name);*/
            return -ENOSPC;
        }
        if (an_name != NULL) {
            *an_name++ = *name++;

            do {
                *an_name++ = adns_tolower(*name++);
            } while (name < next_label);
        } else {
            name = next_label;
        }

        /* Update wire size only for noncompressed part. */
        name_len += lblen;
    }
    if (an_name != NULL) {
        *an_name = '\0';
    }
    name_len += 1;

    if (len != NULL) {
        *len = name_len;
    }

    return name_len;
}

/*-
 * parse additional, only support edns now-
 */
static inline int
adns_parse_additional(struct dns_packet *packet, uint8_t is_query)
{
    int i, ret;
    uint16_t len = 0, opt_type, rdlength;
    //uint16_t class;
    //uint32_t ttl;
    const uint8_t * end_pos = packet->wire + packet->size;
    uint8_t * dnh_pos = packet->wire;
    uint8_t *an_pos = packet->wire + packet->parsed;

    for (i = 0; i < Lntohs(packet->header.arcount); i++) {
        ret = get_an_name(an_pos, 0, 0, end_pos, dnh_pos, packet->dname,
                NULL, "additional", &len);
        if (unlikely(ret < 0)) {
            return -1;
        }
        an_pos += len;
        if (unlikely(an_pos + 10 > end_pos)) {
            STATS (UDP_PKT_LEN_ERR);
            return -1;
        }
        opt_type = adns_ntohs(*(uint16_t *) an_pos);
        an_pos += 2;

        if (len == 1 && opt_type == EDNS_OPT) {
            packet->parsed = an_pos - packet->wire;
            if (!is_query) {
                ldns_wire_set_arcount(packet->wire, i);
                packet->answered = packet->parsed - 3;
            }
            return adns_parse_edns(packet, is_query);
        }
        //class = adns_ntohs(*(uint16_t*)pos);
        an_pos += 2;
        //ttl = adns_ntohl(*(uint32_t*)an_pos);
        an_pos += 4;
        rdlength = adns_ntohs(*(uint16_t *)an_pos);
        an_pos += 2;
        if (unlikely(an_pos + rdlength > end_pos)) {
            STATS(UDP_PKT_LEN_ERR);
            return -1;
        }
        an_pos += rdlength;
    }
    packet->parsed = an_pos - packet->wire;
    if (!is_query) {
        packet->answered = packet->parsed;
    }

    return 0;
}

static inline void
adns_dname_parse_fast(const uint8_t *name, uint16_t len, struct dns_packet *pkt) {
    const uint8_t *base;

    pkt->qname_size = len;
    pkt->labels = 0;
    base = name;

    while (*name != '\0') {
        uint8_t lblen = *name + 1;
        pkt->label_offset[pkt->labels++] = (name - base);
        name += lblen;
    }
}
#endif

