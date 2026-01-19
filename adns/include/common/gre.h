
/*
* Copyright (C)
* Filename: gre.h
* Author:
* yisong <songyi.sy@alibaba-inc.com>
* Description: GRE tunnel
*
* these file is consisted of stuff move out from scattered
* files for support GRE, which are not used any more.
*/

#ifndef _GRE_H_
#define _GRE_H_

#define GRE_HDR_CHECK 0x800004 /* accroding to rfc 1701, Key Present bit is 1, Protocol Type is IPv4 0x0800 */

struct gre_hdr{
    uint16_t checksum_present:1;
    uint16_t routing_present:1;
    uint16_t key_present:1;
    uint16_t seq_num_present:1;
    uint16_t strict_source_route:1;
    uint16_t recur_ctl:3;
    uint16_t flags:5;
    uint16_t ver:3;
    uint16_t proto;
    uint16_t checksum;
    uint16_t offset;
};

extern uint16_t get_ipv4_cksum(const struct ipv4_hdr *ipv4_hdr);
//extern void l3_output(struct ipv4_hdr *iph);
//extern int udp_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr, struct ipv4_hdr *iph, uint8_t port);

static inline struct gre_hdr *adns_gre_hdr(struct ipv4_hdr *iph)
{
    return (struct gre_hdr *)((uint8_t *)iph + ((iph->version_ihl & 0xf) << 2));
}


static inline int get_gre_key(const struct gre_hdr *grh, uint32_t client_ip,
                uint32_t vip, uint32_t real_ip, uint16_t client_port,
                uint16_t real_port, int frag)
{
    uint32_t key;
    key = client_ip ^ vip ^ real_ip;
    if (!frag) {
        key = key ^ ((client_port << 16) | real_port);
    }

    key = (key >> 16) ^ (key & 0xffff);
    key = ((key ^ grh->checksum) & 0x7fff) | 0x8000;
    return key;
}

static inline int is_valid_gre_pkt(const struct gre_hdr *grh)
{
    /* key bit = 1, protocol type is IP(0x0800) */
    if (*(const uint32_t *)grh != 0x080020) {
        return 0;
    }

    return 1;
}

/* compute gre_key according to grh->checksum and other fields, and
   determine whether the gre_key and gre->offset are equal
   step:
   1. compute a according to input parameter
   2. compute b according to a
   3. compute c according to b
   4. compute gre_key according to c */
static inline int is_valid_gre_key(const struct gre_hdr *grh, uint32_t client_ip,
                     uint32_t vip, uint32_t real_ip, uint16_t client_port,
                     uint16_t real_port)
{
    uint32_t key = get_gre_key(grh, client_ip, vip, real_ip, client_port, real_port, 0);
    if (grh->offset == key) {
        return 1;
    }

    return 0;
}

static inline int gre_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr, struct ipv4_hdr *outer_iph, uint8_t port)
{
    struct gre_hdr *grh;
    uint8_t l4_proto;
    struct ipv4_hdr *inner_iph;
    struct udp_hdr *udp_hdr;
    int ret;

    //STATS_INC(gre);

    grh = adns_gre_hdr(outer_iph);

    if (is_valid_gre_pkt(grh) != 1) {
        //adns_counter_increase(g_adns_pkt_drop_counter[GRE_PACKET_INVALID]);
        goto drop_pkt;
    }

    inner_iph = (struct ipv4_hdr *)(grh + 1);

    if (is_valid_ipv4_pkt(inner_iph, (int)m->pkt.pkt_len - (int)ETH_HLEN - (int)((outer_iph->version_ihl & 0xf) << 2) - (int)sizeof(struct gre_hdr)) < 0) {
        //adns_counter_increase(g_adns_pkt_drop_counter[GRE_PACKET_INNER_IP_INVALID]);
        goto drop_pkt;
    }

    l4_proto = inner_iph->next_proto_id;

    if (l4_proto != IPPROTO_UDP) {
        //adns_counter_increase(g_adns_pkt_drop_counter[GRE_PACKET_INNER_L4_INVALID]);
        goto drop_pkt;
    }

    udp_hdr = adns_udp_hdr(inner_iph);

    /* the gre key need inner udp src_port, so put it after parse udp header */
    if (is_valid_gre_key(grh, inner_iph->src_addr, inner_iph->dst_addr, outer_iph->dst_addr, udp_hdr->src_port, udp_hdr->dst_port) == 0) {
        //adns_counter_increase(g_adns_pkt_drop_counter[GRE_PACKET_HEADER_KEY_INVALID]);
        goto drop_pkt;
    }

    /* eth_hdr only used in adns_traffic_handle() inside udp_input() to send
       syslog packet, so outer eth_hdr can be passed to udp_input() */
    //ret = udp_input(m, eth_hdr, inner_iph, port);
    if (ret != ADNS_PKT_ACCEPT) {
        return ret;
    }

    //l3_output(outer_iph);

    /* dpdk can't calculate inner IP header checksum, so do it manually */
    inner_iph->hdr_checksum = get_ipv4_cksum(inner_iph);

    /* set ipv4 header checksum to 0 to enable hardware checksum offload */
    outer_iph->hdr_checksum = 0;
    outer_iph->total_length = adns_htons(adns_ntohs(inner_iph->total_length) + sizeof(struct gre_hdr) + ((outer_iph->version_ihl & 0xf) << 2));

    return ADNS_PKT_ACCEPT;

drop_pkt:
    return ADNS_PKT_DROP;
}

#endif
