
#ifndef _DNS_PACKET_H_
#define _DNS_PACKET_H_

#include <stdint.h>
#include <netinet/ip6.h>

#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "rte_eth_ctrl.h"
#include "rte_core.h"
#include "log.h"
#include "rrset.h"
#include "edns.h"
#include "consts.h"
#include "wire.h"

#define IPV4_TTL 128
#define IPV6_TTL 128
#define DNS_PORT 53
#define MAX_UDP_PAYLOAD 512
#define ADNS_RESPONSE_RECORD_MAX_LEN 128

#define ADNS_PKT_DROP 0
#define ADNS_PKT_ACCEPT 1
#define ADNS_PKT_SEND_TO_KNI 2
#define ADNS_PKT_CONTINUE   3

#define adns_ntohs(x) rte_be_to_cpu_16(x)
#define adns_ntohl(x) rte_be_to_cpu_32(x)
#define adns_htons(x) rte_cpu_to_be_16(x)
#define adns_htonl(x) rte_cpu_to_be_32(x)

#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)

#define NIPQUAD_FMT "%u.%u.%u.%u"
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

#define NIP6_ADDR(addr) \
    (unsigned)((addr).s6_addr[0]), \
    (unsigned)((addr).s6_addr[1]), \
    (unsigned)((addr).s6_addr[2]), \
    (unsigned)((addr).s6_addr[3]), \
    (unsigned)((addr).s6_addr[4]), \
    (unsigned)((addr).s6_addr[5]), \
    (unsigned)((addr).s6_addr[6]), \
    (unsigned)((addr).s6_addr[7]), \
    (unsigned)((addr).s6_addr[8]), \
    (unsigned)((addr).s6_addr[9]), \
    (unsigned)((addr).s6_addr[10]), \
    (unsigned)((addr).s6_addr[11]), \
    (unsigned)((addr).s6_addr[12]), \
    (unsigned)((addr).s6_addr[13]), \
    (unsigned)((addr).s6_addr[14]), \
    (unsigned)((addr).s6_addr[15])

union common_ip_head {
    struct ipv4_hdr ipv4_hdr;
    struct ipv6_hdr ipv6_hdr;
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

struct adns_packet {
    /* header section */
    struct dns_header header;    /* initialized at adns_parse function */
    /* wire question dname */

    uint16_t qtype;
    uint16_t qclass;
    uint16_t ip_ver; /* 4 or 6 */

    union {
        uint32_t client_ip;
        struct in6_addr client_ipv6;
    };

    union common_ip_head *ip_head;

    char    *cli_view_name;     /* the view where the client resource IP address is located */
    char    *final_view_name;   /* the real view where the query result is located */
    adns_viewid_t cli_view_id;
    adns_private_route_id_t custom_view_id;
    uint8_t *qname;
    uint8_t qname_size;
    uint8_t lower_qname[ADNS_DNAME_MAXLEN + 1];  /* canonical qname */
    uint8_t *wire;
    int16_t size;

    adns_opt_rr_t opt_rr;
    uint8_t dnssec;
    uint8_t has_edns:1,     /* flag indicates if query has edns0 */
            has_ecs:1,      /* flag indicates if query has ecs */
            has_cookie:1,   /* flag indicates if query has cookie */
            is_tcp:1,       /* flag indicates if query via TCP */
            is_aa:1,        /* flag indicates if answer is authoritative, set by default and clear in delegation */
            is_ipv6_view:1; /* flag indicates if use IPv6 for view lookup */

    int16_t parsed;    /* initialized at adns_parse function */

    uint16_t answer_max_size;    /* initialized at adns_parse_additional function */
    int16_t answered;    /* initialized at adns_parse function */
    int16_t answer_section_offset;    /* initialized at adns_parse function */

    #if PVT_ZONE_PREFIX
    uint8_t qname_size_prefix;
    uint8_t qname_size_postfix;
    char qname_postfix[PVT_ZONE_POSTFIX_MAX];
    #endif
}__attribute__((packed));



#define ETH_HLEN (sizeof(struct ether_hdr))
#define UDP_HLEN (sizeof(struct udp_hdr))
#define DNS_HLEN (sizeof(struct dns_header))

    static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, int32_t link_len)
{
    if (link_len < sizeof(struct ipv4_hdr))
        return -1;

    if (((pkt->version_ihl) >> 4) != 4)
        return -3;
    if ((pkt->version_ihl & 0xf) < 5)
        return -4;

    if (rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr))
        return -5;

    return 0;
}

    static inline struct ipv4_hdr *
adns_ipv4_hdr(struct rte_mbuf *m)
{
    return (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + ETH_HLEN);
}

    static inline struct tcp_hdr *
adns_tcp_hdr(struct ipv4_hdr *iph)
{
    return (struct tcp_hdr *)((uint8_t *)iph + ((iph->version_ihl & 0xf) << 2));
}

    static inline struct udp_hdr *
adns_udp_hdr(struct ipv4_hdr *iph)
{
    return (struct udp_hdr *)((uint8_t *)iph + ((iph->version_ihl & 0xf) << 2));
}
    
/* --  DNS packet --- */
struct adns_rrset *query_parse_rr(const uint8_t *wire, size_t *pos, size_t size);

int query_parse_additional(struct adns_packet *query, const uint8_t *wire,
        size_t *pos, size_t size);


static inline int adns_query_edns_supported(const struct adns_packet *query)
{
    return (adns_edns_get_version(&query->opt_rr) != EDNS_NOT_SUPPORTED);
}

static inline int adns_packet_qdcount(const struct adns_packet *packet)
{
    return adns_wire_get_qdcount(packet->wire);
}

static inline int adns_packet_ancount(const struct adns_packet *packet)
{
    return adns_wire_get_ancount(packet->wire);
}

static inline int adns_packet_nscount(const struct adns_packet *packet)
{
    return adns_wire_get_nscount(packet->wire);
}

static inline int adns_packet_arcount(const struct adns_packet *packet)
{
    return adns_wire_get_arcount(packet->wire);
}

/*
 * Used for zonedb search, if cannot find target zone in zonedb, that means
 * this name server does not responsibly for query dname, should refuse thsi
 * query.
 */
static inline void resp_set_notimpl(struct dns_header *dnh)
{
    /* set response */
    adns_wire_set_qr((uint8_t *)dnh);
    adns_wire_set_aa((uint8_t *)dnh);
    adns_wire_set_rcode((uint8_t *)dnh, ADNS_RCODE_NOTIMPL);
}

/*
 * If zone already found, but cannot find target domain node, should response with
 * nxdomain rcode set.
 */
static inline void resp_set_nxdomain(struct dns_header *dnh)
{
    /* set response */
    adns_wire_set_qr((uint8_t *)dnh);
    adns_wire_set_aa((uint8_t *)dnh);
    adns_wire_set_rcode((uint8_t *)dnh, ADNS_RCODE_NXDOMAIN);
}

/*
 * If domain node found, but cannot find target rrset, should response with noerror
 * rcode set.
 */
static inline void resp_set_noerror(struct dns_header *dnh)
{
    //qr, aa, ip_checksum, udp_checksum is set in resp_set_header
    adns_wire_set_rcode((uint8_t *)dnh, ADNS_RCODE_NOERROR);
}

static inline void resp_set_formerr(struct ipv4_hdr *iph, struct udp_hdr *udh,
        struct dns_header *dnh)
{
    /* set response */
    adns_wire_set_qr((uint8_t *)dnh);
    adns_wire_set_aa((uint8_t *)dnh);
    adns_wire_set_rcode((uint8_t *)dnh, ADNS_RCODE_FORMERR);
}
/* -----------------  packet buffer API ---------------- */
/*
 * the rest bytes for parse in dns question packet
 */
static inline int16_t pkt_parse_rest(struct adns_packet *pkt)
{
    //assert(pkt->parsed <= pkt->size);
	if(pkt->parsed > pkt->size){
		log_server_warn(rte_lcore_id(), "pkt_parse_rest failed\n");
		return 0;
	}
    return pkt->size - pkt->parsed;
}

/* check if buffer has at least *count* bytes available for parse */
static inline int pkt_parse_available(const struct adns_packet *pkt, int16_t count)
{
    return count <= (pkt->size - pkt->parsed);
}

static inline void pkt_parse_read(struct adns_packet *pkt, void *data, int16_t count)
{
    if (pkt->parsed + count > pkt->size) {
        return;
    }

    memcpy(data, pkt->wire + pkt->parsed, count);
    pkt->parsed += count;
}

static inline uint8_t pkt_parse_read_u8(struct adns_packet *pkt)
{
    uint8_t res;

    //assert(pkt_parse_available(pkt, sizeof(uint8_t)));
    if(pkt_parse_available(pkt, sizeof(uint8_t)) == 0){
		log_server_warn(rte_lcore_id(), "pkt_parse_read_u8 failed\n");
		return 0;
	}

    res = *(pkt->wire + pkt->parsed);
    pkt->parsed += 1;
    return res;
}

static inline uint16_t pkt_parse_read_u16(struct adns_packet *pkt)
{
    uint16_t res;

    //assert(pkt_parse_available(pkt, sizeof(uint16_t)));
	if(pkt_parse_available(pkt, sizeof(uint16_t)) == 0){
		log_server_warn(rte_lcore_id(), "pkt_parse_read_u16 failed\n");
		return 0;
	}

    res = adns_wire_read_u16(pkt->wire + pkt->parsed);
    pkt->parsed += 2;
    return res;
}

static inline uint32_t pkt_parse_read_u32(struct adns_packet *pkt)
{
    uint32_t res;

    //assert(pkt_parse_available(pkt, sizeof(uint32_t)));
	if(pkt_parse_available(pkt, sizeof(uint32_t)) == 0){
		log_server_warn(rte_lcore_id(), "pkt_parse_read_u32 failed\n");
		return 0;
	}
	
    res = adns_wire_read_u32(pkt->wire + pkt->parsed);
    pkt->parsed += 4;
    return res;
}

/* packet answer */
static inline int16_t pkt_answer_rest(struct adns_packet *pkt)
{
    //assert(pkt->answered <= pkt->answer_max_size);
	if(pkt->answered > pkt->answer_max_size){
		log_server_warn(rte_lcore_id(), "pkt_answer_rest failed\n");
		return 0;
	}
    return pkt->answer_max_size - pkt->answered;
}

static inline int pkt_answer_available(struct adns_packet *pkt, int16_t count)
{
    return count <= (pkt->answer_max_size - pkt->answered);
}

static inline int pkt_answer_length_enough(struct adns_packet *pkt, int16_t count)
{
    if(count < (pkt->answer_max_size - pkt->answered)){
        return 0;
    }else{
        return -1;
    }
}

static inline void pkt_answer_write(struct adns_packet *pkt, const void *data, 
        int16_t count)
{
    //assert(pkt_answer_available(pkt, count));
	if(pkt_answer_available(pkt, count) == 0){
		log_server_warn(rte_lcore_id(), "%s:pkt_answer_write failed. data:%s, count:%u\n", __FUNCTION__, data, count);
		return;
	}
    memcpy(pkt->wire + pkt->answered, data, count);
    pkt->answered += count;
}

static inline void pkt_answer_write_u8(struct adns_packet *pkt, uint8_t data)
{
    //assert(pkt_answer_available(pkt, 1));
	if(pkt_answer_available(pkt, 1) == 0){
		log_server_warn(rte_lcore_id(), "%s:pkt_answer_write_u8 failed. data:%u\n", __FUNCTION__, data);
		return;
	}

    *(pkt->wire + pkt->answered) = data;
    pkt->answered += 1;
}

static inline void pkt_answer_write_u16(struct adns_packet *pkt, uint16_t data)
{
    //assert(pkt_answer_available(pkt, 2));
	if(pkt_answer_available(pkt, 2) == 0){
		log_server_warn(rte_lcore_id(), "%s:pkt_answer_write_u16 failed. data:%u\n", __FUNCTION__, data);
		return;
	}
    adns_wire_write_u16(pkt->wire + pkt->answered, data);
    pkt->answered += 2;
}

static inline void pkt_answer_write_u32(struct adns_packet *pkt, uint32_t data)
{
    //assert(pkt_answer_available(pkt, 4));
	if(pkt_answer_available(pkt, 4) == 0){
		log_server_warn(rte_lcore_id(), "%s:pkt_answer_write_u32 failed. data:%u\n", __FUNCTION__, data);
		return;
	}

    adns_wire_write_u32(pkt->wire + pkt->answered, data);
    pkt->answered += 4;
}



static inline int
is_valid_ipv6_pkt(struct ipv6_hdr *pkt, int32_t link_len)
{
    if (link_len < sizeof(struct ipv6_hdr))
        return -1;
    return 0;
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

static inline uint16_t
get_psd_sum(void *l3_hdr, uint16_t ethertype, uint64_t ol_flags)
{
    if (ethertype == ETHER_TYPE_IPv4)
        return rte_ipv4_phdr_cksum((const struct ipv4_hdr *)l3_hdr, ol_flags);
    else /* assume ethertype == ETHER_TYPE_IPv6 */
        return rte_ipv6_phdr_cksum((const struct ipv6_hdr *)l3_hdr, ol_flags);
}

static inline void l2_output(struct ether_hdr *eth_hdr)
{
    struct ether_addr tmp;

    ether_addr_copy(&eth_hdr->s_addr, &tmp);
    ether_addr_copy(&eth_hdr->d_addr, &eth_hdr->s_addr);
    ether_addr_copy(&tmp, &eth_hdr->d_addr);
}

static inline void l3_output(struct ipv4_hdr *iph)
{
    iph->src_addr ^= iph->dst_addr;
    iph->dst_addr ^= iph->src_addr;
    iph->src_addr ^= iph->dst_addr;
}

static inline void l4_rst_output(struct tcp_hdr *tcph)
{
    tcph->tcp_flags = TCP_RST_FLAG | TCP_ACK_FLAG;
    tcph->src_port ^= tcph->dst_port;
    tcph->dst_port ^= tcph->src_port;
    tcph->src_port ^= tcph->dst_port;
    tcph->recv_ack  = htonl(htonl(tcph->sent_seq)+1);
    tcph->sent_seq  = 0;
}

static inline void l3_output_ipv6(struct ipv6_hdr *iph6)
{
    uint8_t tmp_addr[16];
    rte_memcpy(tmp_addr, iph6->src_addr, sizeof(iph6->src_addr));
    rte_memcpy(iph6->src_addr, iph6->dst_addr, sizeof(iph6->src_addr));
    rte_memcpy(iph6->dst_addr, tmp_addr, sizeof(iph6->dst_addr));
}

static inline void l4_udp_output(struct udp_hdr *udh)
{
    udh->src_port ^= udh->dst_port;
    udh->dst_port ^= udh->src_port;
    udh->src_port ^= udh->dst_port;
}

    static inline int
is_valid_tcp_pkt_v4(struct rte_mbuf *m, struct tcp_hdr **tcph)
{
    const int min_tcp_hdr_len = 20;
    int ipv4_hdr_len = 0;
    int ipv4_total_len = 0;
    struct ipv4_hdr *pkt;

    pkt = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr)); 
    ipv4_hdr_len = (pkt->version_ihl & 0xf) << 2;
    ipv4_total_len = rte_be_to_cpu_16(pkt->total_length);

    if (unlikely(ipv4_total_len - ipv4_hdr_len < min_tcp_hdr_len))
        return -1;

    if (unlikely(m->pkt_len - ETH_HLEN < ipv4_total_len))
        return -1;

    if (tcph)
        *tcph = (struct tcp_hdr *)(ipv4_hdr_len + (char *)pkt);

    return 0;
}

/* simplify from Exthdrs_core.c in 7u kernel */
static inline int ipv6_skip_exthdr(struct ipv6_hdr *pkt, uint8_t *offset)
{
    struct ipv6_opt_hdr *hp;
    unsigned int start = sizeof(struct ipv6_hdr);
    uint8_t nexthdr = pkt->proto;
    int hdrlen;
    while (ipv6_ext_hdr(nexthdr)) {
        if (unlikely(nexthdr == IPPROTO_NONE)) {
            return -1;
        }
        if (unlikely(start + sizeof(struct ipv6_opt_hdr) > rte_cpu_to_be_16(pkt->payload_len))) {
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
    }
    *offset = start;
    return nexthdr;
}
    static inline int
is_valid_tcp_pkt_v6(struct rte_mbuf * m, struct tcp_hdr **tcph)
{
    uint8_t offset = 0;
    union common_ip_head *ip_head;
    const int min_tcp_hdr_len = 20;
    int ret;

    ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
            sizeof(struct ether_hdr));
    ret = ipv6_skip_exthdr(&(ip_head->ipv6_hdr), &offset);
    if (unlikely(ret < 0)) {
        return -1;
    }

    if (unlikely(rte_cpu_to_be_16(ip_head->ipv6_hdr.payload_len) < min_tcp_hdr_len)) {
        return -1;
    }
    
    if (unlikely(m->pkt_len - ETH_HLEN < rte_cpu_to_be_16(ip_head->ipv6_hdr.payload_len))) {
        return -1;
    }

    if (tcph)
        *tcph = (struct tcp_hdr*)((uint8_t*)ip_head + offset);

    return 0;
}

    static inline int
is_valid_tcp_pkt(struct rte_mbuf * m, struct tcp_hdr **tcph, int isipv6)
{
    if (unlikely(isipv6)) {
        return is_valid_tcp_pkt_v6(m, tcph);
    } else {
        return is_valid_tcp_pkt_v4(m, tcph);
    }
}

    static inline int
is_valid_ipv4v6_pkt(struct rte_mbuf * m, union common_ip_head *ip_head, int isipv6) {
    if (unlikely(isipv6))
        return is_valid_ipv6_pkt(&(ip_head->ipv6_hdr), (int)m->pkt_len - (int)ETH_HLEN);
    else 
        return is_valid_ipv4_pkt(&(ip_head->ipv4_hdr), (int)m->pkt_len - (int)ETH_HLEN);
}


#endif

