#include <stdint.h>
#include "rte_core.h"
#include "dns_pkt.h"
#define FWD_COMMON_IP_PKT_ID 0x313f
#define FWD_PREFETCH_IP_PKT_ID 0x323f
#define FWD_TIMEOUTFETCH_IP_PKT_ID 0x333f
#define REDIS_GETOP_IP_PKT_ID (0x9876) 
#define REDIS_SETOP_IP_PKT_ID (0x1234) 
#define REDIS_DELOP_IP_PKT_ID (0x1313) 

#define TCP_OFF_FLAG 0xF0

#define TCP_URG_FLAG 0x20
#define TCP_ACK_FLAG 0x10
#define TCP_PSH_FLAG 0x08
#define TCP_RST_FLAG 0x04
#define TCP_SYN_FLAG 0x02
#define TCP_FIN_FLAG 0x01
#define TCP_FLAG_ALL 0x3F

#define TCP_OPT_MSS_LEN         4
#define TCP_OPT_WSCALE_LEN      3
#define TCP_OPT_SACK_PERMIT_LEN 2
#define TCP_OPT_SACK_LEN        10
#define TCP_OPT_TIMESTAMP_LEN   10

#define TCP_DEFAULT_MSS         DNS_EDNS0_MAX_LENGTH

enum tcp_option
{
    TCP_OPT_END         = 0,
    TCP_OPT_NOP         = 1,
    TCP_OPT_MSS         = 2,
    TCP_OPT_WSCALE      = 3,
    TCP_OPT_SACK_PERMIT = 4,
    TCP_OPT_SACK        = 5,
    TCP_OPT_TIMESTAMP   = 8
};

#define IPV4_TTL 128
#define IPV6_TTL 128


static inline void gen_ether_hdr(struct ether_hdr * eth_hdr,
        struct ether_addr *s_addr, struct ether_addr *d_addr, uint16_t type);
static inline void gen_ipv4_hdr(struct ipv4_hdr *ipv4_hdr, uint16_t packet_id,
        uint8_t proto_id, uint32_t s_addr, uint32_t d_addr, uint16_t total_length);
static inline void gen_udp_hdr(struct udp_hdr *udh, uint16_t s_port,
        uint16_t d_port, uint16_t dgram_len);
static inline void gen_query_dns_hdr(struct dns_header *dnh, uint16_t dns_id,
        uint8_t flag1, uint8_t flag2);
static inline void l2_output(struct ether_hdr *eth_hdr);
static inline void l3_output(struct ipv4_hdr *iph);


static inline void l2_output(struct ether_hdr *eth_hdr) {
    struct ether_addr tmp;

    ether_addr_copy(&eth_hdr->s_addr, &tmp);
    ether_addr_copy(&eth_hdr->d_addr, &eth_hdr->s_addr);
    ether_addr_copy(&tmp, &eth_hdr->d_addr);
}

static inline void l3_output(struct ipv4_hdr *iph) {
    iph->src_addr ^= iph->dst_addr;
    iph->dst_addr ^= iph->src_addr;
    iph->src_addr ^= iph->dst_addr;
}

static inline void l4_udp_output(struct udp_hdr *udh) {
    udh->src_port ^= udh->dst_port;
    udh->dst_port ^= udh->src_port;
    udh->src_port ^= udh->dst_port;
}

static inline void l4_tcp_output(struct tcp_hdr *tcph) {
    tcph->src_port ^= tcph->dst_port;
    tcph->dst_port ^= tcph->src_port;
    tcph->src_port ^= tcph->dst_port;
}

static inline void gen_ether_hdr(struct ether_hdr * eth_hdr,
        struct ether_addr *s_addr, struct ether_addr *d_addr, uint16_t type) {
    ether_addr_copy(s_addr,&eth_hdr->s_addr);
    ether_addr_copy(d_addr,&eth_hdr->d_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(type);
}  

static inline void gen_ipv4_hdr(struct ipv4_hdr *ipv4_hdr, uint16_t packet_id,
        uint8_t proto_id, uint32_t s_addr, uint32_t d_addr, uint16_t total_length) {
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->packet_id = packet_id;
    ipv4_hdr->fragment_offset = Lhtons(0|(2 << 13));
    ipv4_hdr->time_to_live = IPV4_TTL;
    ipv4_hdr->next_proto_id = proto_id;
    ipv4_hdr->src_addr = Lhtonl(s_addr);
    ipv4_hdr->dst_addr = Lhtonl(d_addr);
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->total_length = Lhtons(total_length);
}

static inline void gen_udp_hdr(struct udp_hdr *udh, uint16_t s_port,
        uint16_t d_port, uint16_t dgram_len) {
    udh->dst_port = Lhtons(d_port);
    udh->src_port = Lhtons(s_port);
    udh->dgram_cksum = 0;
    udh->dgram_len = Lhtons(dgram_len);
}

static inline void gen_query_dns_hdr(struct dns_header *dnh, uint16_t dns_id,
        uint8_t flag1, uint8_t flag2) {
    dnh->id = dns_id;
    dnh->flags1 = flag1;
    dnh->flags2 = flag2;
    dnh->qdcount = Lhtons(1);
    dnh->ancount = 0;
    dnh->nscount = 0;
    dnh->arcount = Lhtons(1);
}

