
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include <rte_ether.h>
#include "rte_core.h"

#include "net_debug.h"
#include "ldns.h"
#include "msg.h"
#include "dns_pkt.h"
#include "common.h"
#include "wire.h"
#include "request.h"
#include "tolower.h"
#include "storage.h"
#include "consts.h"
#include "view.h"
#include "stats.h"
#include "qtype.h"
#include "user_config.h"
#include "health_check.h"
#include "whitelist.h"
#include "blacklist.h"
#include "oversealist.h"
#include "gen_pkt.h"
#include "adns_log.h"
#include "iplib.h"
#include "view_maps.h"
#include "ipv6_fwd.h"
#include "edns.h"
#include "ip_filter.h"
#include "man_whitelist.h"
#include "man_blacklist.h"
#include "hijack.h"
#include "dnscache_tbl.h"

#define BE_53 13568
#define MTU_SIZE  1500

nic_info nic[8];

/*
 * Parse dns header from the wire format.
 */
static inline int
dns_parse_header(const uint8_t * wire, size_t * pos, size_t size,
                 struct dns_header *header)
{
    if (unlikely(wire == NULL || pos == NULL || header == NULL)) {
        return -1;
    }

    if (unlikely(size - *pos < LDNS_WIRE_HEADER_SIZE)) {
        return -1;
    }

    header->id = ldns_wire_get_u16(wire, LDNS_WIRE_OFFSET_ID);
    header->flags1 = ldns_wire_get_u8(wire, LDNS_WIRE_OFFSET_FLAGS1);
    header->flags2 = ldns_wire_get_u8(wire, LDNS_WIRE_OFFSET_FLAGS2);
    header->qdcount = ldns_wire_get_u16(wire, LDNS_WIRE_OFFSET_QDCOUNT);
    header->ancount = ldns_wire_get_u16(wire, LDNS_WIRE_OFFSET_ANCOUNT);
    header->nscount = ldns_wire_get_u16(wire, LDNS_WIRE_OFFSET_NSCOUNT);
    header->arcount = ldns_wire_get_u16(wire, LDNS_WIRE_OFFSET_ARCOUNT);

    *pos += LDNS_WIRE_HEADER_SIZE;

    return 0;
}

/* The endp points to the next position of query's last valid octet */
static inline int
adns_dname_wire_check(const uint8_t *name, const uint8_t *endp, struct dns_packet *packet)
{
    int name_len = 1; /* Keep \x00 terminal label in advance. */
    const uint8_t *next_label, *base;
    uint8_t *lower_name = packet->qname;
    char * buff = packet->dname;
    packet->labels = 0;
    base = name;
    packet->dname_len = 0;

    if (unlikely(name == NULL || name == endp)){
        return -EINVAL;
    }

    while (*name != '\0') {
        /* Check label length (maximum 63 bytes allowed). */
        if (unlikely(*name > LABEL_MAX_SIZE)){
            return -1;
        }
        uint8_t lblen = *name + 1;
        packet->label_offset[packet->labels++] = (name - base);
        if (unlikely(name_len + lblen > ADNS_DNAME_MAXLEN)){
            return -1;
        }
        next_label = name + lblen;

        /* Check if there's enough space in the name buffer.
         */
        if (unlikely(next_label >= endp)) {
            return -ENOSPC;
        }
        *lower_name++ = *name++;

        do {
            buff[packet->dname_len++] = *name;
            *lower_name++ = adns_tolower(*name++);
        } while (name < next_label);
        buff[packet->dname_len++] = '.';

        /* Update wire size only for noncompressed part. */
        name_len += lblen;
    }
    if (unlikely(packet->dname_len == 0)) {
            buff[packet->dname_len++] = '.';
    }
    buff[packet->dname_len++] = '\0';
    *lower_name = '\0';

    return name_len;
}
/*
 * Parse DNS Question entry from the wire format
 */
static inline int
adns_parse_question(const uint8_t *wire, size_t *pos, size_t size,
        struct dns_packet *packet)
{
    int len;

    if (unlikely(wire == NULL || pos == NULL || packet == NULL)) {
        return -1;
    }

    if (unlikely(size - *pos < LDNS_WIRE_QUESTION_MIN_SIZE)) {
        STATS(DNS_PKT_LEN_ERR);
        //ALOG(QUERY, ERROR, "Not enough data to parse question");
        return -1;
    }
    len = adns_dname_wire_check(wire + packet->parsed, wire + size, packet);
    if (len <= 0) {
        STATS(DNAME_PARSE_ERR);
        //ALOG(QUERY, ERROR, "Malformed dns request packet");
        return -1;
    }

    if (unlikely(size - len - *pos  < 4)) {
        STATS(DNS_PKT_LEN_ERR);
        //ALOG(QUERY, ERROR, "Not enough data to parse question");
        return -1;
    }

    packet->qname_size = len;
    packet->parsed += len;
    *pos += len;

    packet->qtype = adns_wire_read_u16(wire + packet->parsed);
    packet->qclass = adns_wire_read_u16(wire + packet->parsed + 2);
    packet->parsed += 4;

    *pos += 4;

    return 0;
}

/*
 * cookie format
 * option-code                     uint16_t
 * option-length                   uint16_t, value 8 or [16, 40]
 * client cookie                   8 bytes
 * server cookie                   0 | [8, 32] bytes
 */
/*
static inline int
adns_parse_cookie(struct dns_packet *packet, uint16_t opt_len)
{
    if (unlikely(opt_len != 8 &&-
        (opt_len < 16 || opt_len > 40))) {
        return -1;
    }

    // skip cookie option
    packet->parsed += opt_len;

    if (packet->has_cookie == 0) {
        packet->has_cookie = 1;
    }

    return 0;
}
*/

/*
 * Parse dns requset from wire format, fill in the dns_packet struct.
 * return 0 on success, otherwise on failure
 */
static inline int dns_parse_query(struct dns_packet *packet, uint8_t * wire, size_t size)
{
    int ret = 0;

    if (unlikely(packet == NULL || wire == NULL)) {
        return -EINVAL;
    }

    packet->wire = wire;   /*total udp data packet, dns header */
    packet->size = size;        /*total dns data size */

    /* malformed packet, should drop it */
    if (unlikely(size < DNS_HLEN)) {
        return -EINVAL;
    }

    size_t pos = 0;
    /* Parse header to packet from wire format */
    ret = dns_parse_header(wire, &pos, size, &packet->header);
    if (unlikely(ret != 0)) {
        return ret;
    }

    /* Process opcode, only support standard query */
    if ((packet->header.flags1 & 0x78) != 0) {
        return -1;
    }

    /* Only parse one question dns request */
    if (unlikely(packet->header.qdcount != 1))
        return -1;
    packet->parsed = pos;       /*pos now = dns header len */
    /* Parse question */
    ret = adns_parse_question(wire, &pos, size, packet);
    if (unlikely(ret != 0)) {
        return ret;
    }
    packet->answered = packet->parsed;
    //packet->answer_section_offset = packet->parsed;

    return 0;
}

static inline int udp_filter(struct udp_hdr *udh, uint8_t port, int ip_pld_len)
{
    if(unlikely(ip_pld_len < sizeof(struct udp_hdr) || ip_pld_len < adns_ntohs(udh->dgram_len))) {
        STATS(UDP_PKT_LEN_ERR);
/*        ALOG(SERVER, INFO, "Core %d Drop: ip_pld_len%d sizeof(struct udp_hdr) %d adns_ntohs(udh->dgram_len) %d < 0\n",
                rte_lcore_id(), ip_pld_len, sizeof(struct udp_hdr), adns_ntohs(udh->dgram_len));*/
        return -1;
    }
    if (unlikely(adns_ntohs(udh->dgram_len) <= UDP_HLEN + DNS_HLEN)) {
        STATS(UDP_PKT_LEN_ERR);
/*        ALOG(SERVER, INFO, "Core %d Drop: udh_dgram_len %d\n", rte_lcore_id(),
                adns_ntohs(udh->dgram_len));*/
        return -1;
    }

    uint16_t fwd_port_begin = fwd_port_mgr[rte_lcore_id()][port].ports[0];
    uint16_t fwd_prot_end =
        fwd_port_mgr[rte_lcore_id()][port].ports[LCORE_FWD_PORTS_MAX - 1];
    uint16_t dst_port = Lntohs(udh->dst_port);

//    if (dst_port != DNS_PORT && dst_port != RDS_SET_SRC_PORT
//        && dst_port != RDS_GET_SRC_PORT && dst_port != RDS_DEL_SRC_PORT){
//        if (dst_port < fwd_port_begin || dst_port > fwd_prot_end) {
//            ALOG(SERVER, INFO, "Core %d Drop: dst port %d\n", rte_lcore_id(),
//                    Lntohs(udh->dst_port));
//            return -1;
//        }
//    }
    if (dst_port != DNS_PORT && (dst_port < fwd_port_begin || dst_port > fwd_prot_end)) {
        STATS(UNKNOWN_UDP_PKT);
/*        ALOG(SERVER, INFO, "Core %d Drop: dst port %d(%d %d)\n", rte_lcore_id(),
                Lntohs(udh->dst_port), fwd_port_begin, fwd_prot_end);*/
        return -1;
    }

    return 0;
}

static inline int
resize_mbuf(struct rte_mbuf *m, union common_ip_head *ip_head, int is_ipv6, int append) {
    if (!is_ipv6) {
        ip_head->ipv4_hdr.total_length = adns_htons(
                adns_ntohs(ip_head->ipv4_hdr.total_length) + append);
    } else {
        ip_head->ipv6_hdr.payload_len = adns_htons(
                adns_ntohs(ip_head->ipv6_hdr.payload_len) + append);
    }

    if (append > 0) {
        if (unlikely(rte_pktmbuf_append(m, append) < 0)) {
            //ALOG(ANSWER, ERROR, "APPEND_FAIL");
            STATS(MBUF_APPEND_DROP);
            return -1;
        }
    } else if (append < 0) {
        if (unlikely(rte_pktmbuf_trim(m, -1 * append) < 0)) {
            //ALOG(ANSWER, ERROR, "Tirm_FAIL\n");
            STATS(MBUF_APPEND_DROP);
            return -1;
        }
    }

    return 0;
}

static inline int answer_from_node(struct rte_mbuf *m,
        struct ether_hdr *eth_hdr, union common_ip_head *ip_head,
        union common_l4_head *l4_head, uint16_t l4_len, struct dns_header *dnh,
        node * n, struct dns_packet *pkt, int is_ipv6, int is_tcp,
        int is_from_kni)
{
    STATS(HIT_REQ);
    VSTATS(n->forward_vid, VHIT_REQ);

    dval *dv = n->val;
    int now_dns_len = dv->len;
    int append = now_dns_len - l4_len;

    if (unlikely(resize_mbuf(m, ip_head, is_ipv6, append) < 0)) {
        rte_pktmbuf_free(m);
        return -1;
    }

    if (is_tcp) {
        *(((uint16_t *)dnh) - 1) = adns_htons(l4_len + append);
    } else {
        l4_head->udp_hdr.dgram_len = adns_htons(adns_ntohs(l4_head->udp_hdr.dgram_len) + append);
    }
    uint16_t tmp_id = dnh->id;
    uint8_t flag1 = dnh->flags1;
    uint8_t flag2 = dnh->flags2;
    union common_ip *ip;
    uint8_t *pos = (uint8_t *)dnh;

    rte_memcpy(pos, dv->data, sizeof(struct dns_header));
    rte_memcpy(pos + pkt->answered, dv->data + pkt->answered, dv->len - pkt->answered);
    dnh->id = tmp_id;

    fix_ttl(dnh, n);
    fix_flag(dnh, flag1, flag2);

    if (pkt->has_ecs) {
        if (is_ipv6) {
            ip = (union common_ip *)&pkt->client_ipv6;
        } else {
            ip = (union common_ip *)&pkt->client_ip;
        }
        if (add_edns_client_subnet(m, ip_head, l4_head, now_dns_len, dnh, ip,
                is_ipv6, is_tcp, &pkt->opt_rr.opt_ecs, pkt->answer_max_size)
                < 0) {
            //ALOG(ANSWER, ERROR, "Add edns client subnet Fail in %s", __func__);
            STATS(ADD_EDNS_DROP);
            rte_pktmbuf_free(m);
            return -1;
        }
    }

/*        char dname[NAME_MAX_LEN + 30];
        get_query_dname(n->key->buf.base,n->key->buf.len,dname);
        ALOG(ANSWER, INFO,
                "LCORE %d : AnswerQuery [%s:%s] from forwarder cache, is_tcp:%d, is_tc:%d",
                rte_lcore_id(), get_view_name(n->forward_vid), dname, is_tcp,
                ldns_wire_get_tc((uint8_t * )dnh));*/
    log_answer_info(ip_head, l4_head, is_tcp, is_from_kni, is_ipv6,
            n->forward_vid, dnh, pkt->has_ecs, pkt->srv_type, pkt->zname_offset);

    return 0;
}

static inline int is_query(struct dns_packet *pkt)
{
    int QR = pkt->header.flags1 & LDNS_WIRE_QR_MASK;
    if (QR == 0)
        return 1;
    return 0;
}

static inline int domain_fliter(struct dns_packet *pkt)
{
    int i;
    const uint8_t *pos, *zone, *domain_name = pkt->qname;
    size_t zone_len = 0; 
    int temp_max_label;

    if (domain_name == NULL) {
        return -1; 
    }

    if (g_blacklist_label_max > g_whitelist_label_max)
        temp_max_label = g_blacklist_label_max;
    else
        temp_max_label = g_whitelist_label_max;

    pos = domain_name;
    for (i = pkt->labels; i >= 2; --i, pos += *pos + 1) { 
        if ( i > temp_max_label) {
            continue;
        }
        zone_len = pkt->qname_size - pkt->label_offset[pkt->labels - i] - 1;
        if (zone_len == 0)
            break;

        zone = pos;
        if (i <= g_whitelist_label_max) {
            if (g_man_white_state && man_whitelist_judge(zone, zone_len)){
                return 0;
            }
        }

        if (i <= g_blacklist_label_max) {
            if (g_man_black_state && man_blacklist_judge(zone, zone_len)){
                return 1;
            }
        }

    }

    return 0;
}

static inline void parse_srv_type(struct dns_packet *packet,
        union common_ip_head *ip_head) {
    switch (set_srv_type(packet, ip_head)) {
    case SRV_TYPE_REC:
        if (packet->ip_ver == 4) {
            STATS(IPV4_DNS_IN);
        } else {
            STATS(IPV6_DNS_IN);
        }
        packet->views = g_recs_views;
        break;
    case SRV_TYPE_AUTH:
        if (packet->ip_ver == 4) {
            STATS(IPV4_AUTH_IN);
        } else {
            STATS(IPV6_AUTH_IN);
        }
        packet->views = g_auth_views;
        break;
    case SRV_TYPE_SEC:
        if (packet->ip_ver == 4) {
            STATS(IPV4_SEC_IN);
        } else {
            STATS(IPV6_SEC_IN);
        }
        packet->views = g_recs_views;
        break;
    default:
        if (packet->ip_ver == 4) {
            ALOG(QUERY, ERROR,
                    "LCORE %d : failed to get service type for query dest ip %d.%d.%d.%d",
                    rte_lcore_id(), NIPQUAD(ip_head->ipv4_hdr.dst_addr));
        } else {
            ALOG(QUERY, ERROR,
                    "LCORE %d : failed to get service type for query dest ip " NIP6_FMT,
                    rte_lcore_id(), NIP6(ip_head->ipv6_hdr.dst_addr));
        }
    }
}

static inline int answer_refused(struct dns_packet *pkt,
        union common_ip_head *ip_head, union common_l4_head *l4_hdr,
        struct dns_header *dns_hdr, int is_ipv6, int is_tcp, int is_from_kni) {
    log_query_info(ip_head, l4_hdr, is_tcp, is_from_kni, pkt,
            LOG_ACTION_ANSWER);
    resp_set_refuse(dns_hdr);

    ldns_wire_clear_ra((uint8_t *) dns_hdr);
    ldns_wire_clear_aa((uint8_t *) dns_hdr);
    ldns_wire_clear_ad((uint8_t *) dns_hdr);
    ldns_wire_set_qr((uint8_t *) dns_hdr);
    ldns_wire_clear_tc((uint8_t *) dns_hdr);
    ldns_wire_clear_z((uint8_t *) dns_hdr);

    log_answer_info(ip_head, l4_hdr, is_tcp, is_from_kni, is_ipv6,
            pkt->cli_view, dns_hdr, pkt->has_ecs, pkt->srv_type, pkt->zname_offset);
    return IO_RET_ANSWER;
}

static inline int answer_srvfail(struct dns_packet *pkt,
        union common_ip_head *ip_head, union common_l4_head *l4_hdr,
        struct dns_header *dns_hdr, int is_ipv6, int is_tcp, int is_from_kni) {
    log_query_info(ip_head, l4_hdr, is_tcp, is_from_kni, pkt,
            LOG_ACTION_ANSWER);
    resp_set_srvfail(dns_hdr);

    ldns_wire_set_ra((uint8_t *) dns_hdr);
    ldns_wire_clear_aa((uint8_t *) dns_hdr);
    ldns_wire_clear_ad((uint8_t *) dns_hdr);
    ldns_wire_set_qr((uint8_t *) dns_hdr);
    ldns_wire_clear_tc((uint8_t *) dns_hdr);
    ldns_wire_clear_z((uint8_t *) dns_hdr);

    log_answer_info(ip_head, l4_hdr, is_tcp, is_from_kni, is_ipv6,
            pkt->cli_view, dns_hdr, pkt->has_ecs, pkt->srv_type, pkt->zname_offset);
    return IO_RET_ANSWER;
}

//static inline int auth_dns_input(struct rte_mbuf *m, struct dns_packet *pkt,
//        struct ether_hdr *eth_hdr, union common_ip_head *ip_head,
//        union common_l4_head *l4_hdr, uint16_t l4_len,
//        struct dns_header *dns_hdr, uint8_t port, int is_ipv6, int is_tcp,
//        int is_from_kni) {
//    struct dnscache_node *fnode = dnscache_zone_lookup(g_dnscache_node_tbl,
//            pkt);
//    if (fnode == NULL) {
//        return answer_refused(pkt, ip_head, l4_hdr, dns_hdr, is_ipv6, is_tcp,
//                is_from_kni);
//    }
//
//    uint8_t qkey[QKEY_LEN];
//    //memset(qkey, 0, sizeof(qkey));
//    int klen = get_query_key(pkt, qkey);
//    uint32_t idx = node_hash_val(qkey, klen);
//    /* push request to correct core */
//    int new_core_id = get_core_by_idx(idx);
//    struct lcore_params *lp = &app.lcore_params[rte_lcore_id()];
//    node *find;
//    int answer;
//
//    if (new_core_id != rte_lcore_id()) {
//        VSTATS(pkt->cli_view, VSLV_REQ);
//        answer = query_find_diff_core(qkey, klen, idx, &find, pkt->cli_view,
//                new_core_id, fnode->src_edns);
//    } else {
//        VSTATS(pkt->cli_view, VMST_REQ);
//        answer = query_find(qkey, klen, idx, eth_hdr, ip_head, l4_hdr, l4_len,
//                pkt, port, &find, is_ipv6, is_tcp, is_from_kni,
//                fnode->src_edns);
//    }
//
//    return answer;
//}

inline int dns_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        union common_ip_head *ip_head, union common_l4_head *l4_hdr, uint16_t l4_len,
        struct dns_header *dns_hdr, uint8_t port, int is_ipv6, int is_tcp, int is_from_kni) {
    int ret, flag;
    uint8_t *wire;
    struct dns_packet packet;
    uint8_t support_ecs = 1;

    packet.zname_offset = ADNS_DNAME_MAXLEN;
    packet.has_edns = 0;
    packet.has_ecs = 0;
    //packet.has_cookie = 0;
    //packet.do_dnssec = 0;

    wire = (uint8_t *)dns_hdr;
    ret = dns_parse_query(&packet, wire, l4_len);
    if (unlikely(ret)) {
        STATS(DNS_PARSE_DROP);
        //ALOG(SERVER, INFO, "Failed to parse dns request");
        return IO_RET_DROP;
    }

    if (is_query(&packet)) {
        if (is_ipv6) {
            packet.ip_ver = 6;
        } else {
            packet.ip_ver = 4;
        }
        parse_srv_type(&packet, ip_head);

        /* parse additional */
        ret = adns_parse_additional(&packet, 1);
        if (unlikely(ret < 0)) {
            STATS(DNS_PARSE_DROP);
            //ALOG(SERVER, INFO, "Failed to parse dns additional");
            return IO_RET_DROP;
        }

        if (unlikely(packet.has_ecs)) {
            if(packet.opt_rr.opt_ecs.family == ECS_FAMILY_IPV4) {
                packet.client_ip = packet.opt_rr.opt_ecs.addr.v4;
                flag = 4;
            } else {
                memcpy(&packet.client_ipv6, packet.opt_rr.opt_ecs.addr.v61, sizeof(struct in6_addr));
                flag = 6;
            }
        } else {
            if (packet.ip_ver == 4) {
                packet.client_ip = ip_head->ipv4_hdr.src_addr;
                flag = 4;
            } else {
                memcpy(&packet.client_ipv6, &ip_head->ipv6_hdr.src_addr, sizeof(struct in6_addr));
                flag = 6;
            }
        }
    }else{
        if (is_ipv6 || is_tcp) {
            return IO_RET_DROP;
        }
        packet.ip_ver = 4;
        STATS(DNS_RESP);
        cache_packet(&packet, Lntohl(ip_head->ipv4_hdr.src_addr), Lntohs(l4_hdr->udp_hdr.src_port));
        return IO_RET_FREE;
    }

    if (flag == 4) {
        packet.cli_view = ip_bitmap_get(Lntohl(packet.client_ip), 0);
    } else if (flag == 6) {
        packet.cli_view = ipv6_bitmap_get(packet.client_ipv6, 0);
    }

    VSTATS(packet.cli_view, VIN_REQ);

    if (unlikely(is_hijacked(&packet))) {
        log_query_info(ip_head, l4_hdr, is_tcp, is_from_kni, &packet,
        LOG_ACTION_HIJACK);
        int hijack_t = get_hijack_type(&packet);
        char temp[255];
        switch (hijack_t) {
        case CLIENTIP:
            if (packet.ip_ver == 6) {
                sprintf(temp, NIP6_FMT, NIP6((uint8_t*)&packet.client_ipv6));
            } else {
                sprintf(temp, "%d.%d.%d.%d", NIP_STR(packet.client_ip));
            }
            break;
        case VIEWNAME:
            strcpy(temp, view_id_to_name(packet.cli_view));
            break;
        case HOSTNAME:
            strcpy(temp, g_hostname);
            break;
        default:
            temp[0] = 0;
        }
        ret = answer_from_hijack(m, &packet, ip_head, l4_hdr, dns_hdr, temp,
                is_ipv6);
        if (ret < 0) {
            return IO_RET_DROP;
        }

        return IO_RET_ANSWER;
    }

    if (SRV_TYPE_AUTH == packet.srv_type) {
//        return auth_dns_input(m, &packet, eth_hdr, ip_head, l4_hdr, l4_len,
//                dns_hdr, port, is_ipv6, is_tcp, is_from_kni);
        struct dnscache_node *fnode = dnscache_zone_lookup(g_dnscache_node_tbl,
                &packet, packet.qname);
        if (fnode == NULL) {
            return answer_refused(&packet, ip_head, l4_hdr, dns_hdr, is_ipv6,
                    is_tcp, is_from_kni);
        }
        support_ecs = fnode->src_info->src_ecs;
    } else if (g_man_black_state) {
        if (domain_fliter(&packet)) {
            STATS(BLACK_DNAME_DROP);
            log_query_info(ip_head, l4_hdr, is_tcp, is_from_kni, &packet,
                    LOG_ACTION_DROP);
            return IO_RET_DROP;
        }
    }

    uint8_t qkey[QKEY_LEN];
    //memset(qkey, 0, sizeof(qkey));
    int klen = get_query_key(&packet, qkey);
    uint32_t idx = node_hash_val(qkey, klen);
    /* push request to correct core */
    int new_core_id = get_core_by_idx(idx);
    struct lcore_params *lp = &app.lcore_params[rte_lcore_id()];
    node *find;
    int answer;
    if (new_core_id != rte_lcore_id()) {
        VSTATS(packet.cli_view, VSLV_REQ);
        answer = query_find_diff_core(qkey, klen, idx, &find, packet.cli_view,
                new_core_id, support_ecs, packet.views);
    } else {
        VSTATS(packet.cli_view, VMST_REQ);
        answer = query_find(qkey, klen, idx, eth_hdr, ip_head, l4_hdr, l4_len,
                &packet, port, &find, is_ipv6, is_tcp, is_from_kni, support_ecs);
    }

    /* answer:
     * 0: need recursive in current lcore
     * 1: find a cache node
     * 2: need recursive and must send packet to correct lcore
     */
    switch (answer) {
    case 0:
        log_query_info(ip_head, l4_hdr, is_tcp, is_from_kni, &packet,
                LOG_ACTION_FORWARD);
        return IO_RET_FREE;
    case 1:
        log_query_info(ip_head, l4_hdr, is_tcp, is_from_kni, &packet,
                LOG_ACTION_ANSWER);
        if (answer_from_node(m, eth_hdr, ip_head, l4_hdr, l4_len, dns_hdr, find,
                &packet, is_ipv6, is_tcp, is_from_kni) == 0) {
            if (is_from_kni) {
                STATS(KNI_DNS_OUT);
                if (lp->type == e_LCORE_KNI) {
                    /* judge lcore id set */
                    return IO_RET_ANSWER;
                }
                struct lcore_msg_info* entry;
                int kni_id = kni_lcore_port_map[port];
                entry = get_kni_msg_info(m, eth_hdr, ip_head, l4_hdr, 1, port);
                if (entry == NULL) {
                    return IO_RET_DROP;
                }
                ret = lcore_msg_send(entry, kni_id);
                if (ret < 0) {
                    return IO_RET_DROP;
                }
                return IO_RET_STOLEN;
            }
            STATS(DNS_OUT);
            /*
             if (is_tcp) {
             STATS(TCP_DNS_OUT);
             }
             */
            return IO_RET_ANSWER;
        }
        /* answer_from_node has rte_pktmbuf_free(m); when error*/
        STATS(DNS_DROP);
        return IO_RET_ERROR;
    case 2:
        STATS(IPC_REQ_FWD);
        struct lcore_msg_info* entry;
        entry = get_fwd_msg_info(m, eth_hdr, ip_head, l4_hdr, l4_len, dns_hdr,
                port, is_ipv6, is_tcp, is_from_kni, &packet, idx, support_ecs);
        if (entry == NULL) {
            return IO_RET_DROP;
        }
        ret = lcore_msg_send(entry, new_core_id);
        if (ret < 0) {
            return IO_RET_DROP;
        }
        return IO_RET_STOLEN;
    default:
        if (SRV_TYPE_AUTH == packet.srv_type) {
            return answer_refused(&packet, ip_head, l4_hdr, dns_hdr, is_ipv6,
                    is_tcp, is_from_kni);
        } else {
            return answer_srvfail(&packet, ip_head, l4_hdr, dns_hdr, is_ipv6,
                    is_tcp, is_from_kni);
        }
    }

    return IO_RET_ERROR;
}


static inline int udp_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        union common_ip_head *ip_head, struct udp_hdr *udh, uint8_t port,
        int is_ipv6, int is_from_kni, uint16_t ip_pld_len) {
    uint16_t l4_len;
    struct dns_header *dnh;
    int ret;

    if (udp_filter(udh, port, ip_pld_len) < 0) {
        STATS(UDP_FILTER_DROP);
        //ALOG(SERVER, ERROR, "udp_filter Drop port %d", port);
        rte_pktmbuf_free(m);
        return -1;
    }

    dnh = (struct dns_header *) ((uint8_t *) udh + UDP_HLEN);
    l4_len = Lntohs(udh->dgram_len) - UDP_HLEN;

    ret = dns_input(m, eth_hdr, ip_head, (union common_l4_head *)udh, l4_len,
            dnh, port, is_ipv6, 0, is_from_kni);
    if (unlikely(IO_RET_DROP == ret)) {
        STATS(DNS_DROP);
        rte_pktmbuf_free(m);
    } else if (IO_RET_FREE == ret) {
        rte_pktmbuf_free(m);
    }

    return ret;
}

static inline int rst_tcp_conn(struct rte_mbuf *m,
        union common_ip_head *ip_head, int is_ipv6, struct tcp_hdr *tcph,
        uint32_t seq, int payloadlen) {
    if (unlikely(resize_mbuf(m, ip_head, is_ipv6, -payloadlen) < 0)) {
        rte_pktmbuf_free(m);
        return IO_RET_DROP;
    }
    STATS(TCP_DNS_RST);
    tcph->tcp_flags = TCP_RST_FLAG | TCP_ACK_FLAG;
    tcph->sent_seq = tcph->recv_ack;
    tcph->recv_ack = adns_htonl(seq + payloadlen);

    return IO_RET_ANSWER;
}

static inline int ack_tcp_conn(struct rte_mbuf *m,
        union common_ip_head *ip_head, int is_ipv6, struct tcp_hdr *tcph,
        uint32_t seq, int payloadlen) {
    if (unlikely(resize_mbuf(m, ip_head, is_ipv6, -payloadlen) < 0)) {
        rte_pktmbuf_free(m);
        return IO_RET_DROP;
    }
    tcph->tcp_flags = TCP_ACK_FLAG;
    tcph->sent_seq = tcph->recv_ack;
    tcph->recv_ack = adns_htonl(seq + payloadlen);

    return IO_RET_ANSWER;
}

static inline int tcp_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        union common_ip_head *ip_head, struct tcp_hdr *tcph, uint8_t port,
        int is_ipv6, uint16_t ip_pld_len) {

    int payloadlen = ip_pld_len - sizeof(struct tcp_hdr);
    if (payloadlen < 0) {
        STATS(TCP_FILTER_DROP);
        goto drop_pkt;
    }

    if ((BE_53 != tcph->dst_port)) {
        STATS(TCP_FILTER_DROP);
        goto drop_pkt;
    }

    payloadlen -= (((tcph->data_off & TCP_OFF_FLAG) >> 2) - sizeof(struct tcp_hdr));
    if (payloadlen < 0) {
        STATS(TCP_FILTER_DROP);
        goto drop_pkt;
    }


#if VERIFY_RX_CHECKSUM
    int rc = -1;
#ifndef DISABLE_HWCSUM
    if((g_dev_info[port].rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM) != 0) {
        rc = 1;
    }
#endif
    if (rc == -1) {
        /* should check the tcp checksum with software here */
    }
#endif

    uint8_t *payload = (uint8_t *)tcph + ((tcph->data_off & TCP_OFF_FLAG) >> 2);
    uint32_t seq = adns_ntohl(tcph->sent_seq);
    //uint32_t ack_seq = adns_ntohl(tcph->recv_ack);
    //uint16_t window = adns_ntohs(tcph->rx_win);
    int i, append;

    // If the real packet size is less than 60, the m->pkt_len will be set as 60,
    // this will lead to tx checksum error when enable hardware offloading
    if (m->pkt_len == 60) {
        m->pkt_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr)
                + ip_pld_len;
        m->data_len = m->pkt_len;
    }

    if(tcph->tcp_flags & TCP_RST_FLAG) {
        goto drop_pkt;
    } else if (tcph->tcp_flags & TCP_SYN_FLAG) {
        if(!(tcph->tcp_flags & TCP_ACK_FLAG)) {
            uint8_t *tcpopt = (uint8_t *)tcph + sizeof(struct tcp_hdr);

            tcph->recv_ack  = adns_htonl(seq + 1);
            tcph->sent_seq  = seq >> 1;
            // optlen: TCP_OPT_MSS_LEN + TCP_OPT_WSCALE_LEN + PADDING
            tcph->data_off = (sizeof(struct tcp_hdr) + 8) << 2;
            append = sizeof(struct tcp_hdr) + 8 - ip_pld_len;

            if (unlikely(resize_mbuf(m, ip_head, is_ipv6, append) < 0)) {
                goto drop_pkt;
            }
            tcph->tcp_flags = TCP_SYN_FLAG | TCP_ACK_FLAG;
            tcph->rx_win = adns_htons(TCP_DEFAULT_MSS);
            tcph->tcp_urp = 0;
            i = 0;
            // MSS
            tcpopt[i++] = TCP_OPT_MSS;
            tcpopt[i++] = TCP_OPT_MSS_LEN;
            tcpopt[i++] = TCP_DEFAULT_MSS >> 8;
            tcpopt[i++] = TCP_DEFAULT_MSS % 256;
            //WSCALE
            tcpopt[i++] = TCP_OPT_NOP;
            tcpopt[i++] = TCP_OPT_WSCALE;
            tcpopt[i++] = TCP_OPT_WSCALE_LEN;
            tcpopt[i++] = 0;
        } else {
            tcph->tcp_flags = TCP_ACK_FLAG;
            seq = tcph->sent_seq;
            tcph->sent_seq = tcph->recv_ack;
            tcph->recv_ack = seq;
        }
    } else if(tcph->tcp_flags & TCP_FIN_FLAG) {
        tcph->sent_seq = tcph->recv_ack;
        tcph->recv_ack  = adns_htonl(seq + 1);
        tcph->tcp_flags = TCP_FIN_FLAG | TCP_ACK_FLAG;
    } else if(payloadlen > 0) {
        // the data len field is 2 bytes at the begin of payload
        if (unlikely(payloadlen <= 2)) {
            STATS(TCP_PKT_LEN_ERR);
/*            ALOG(SERVER, INFO, "Core %d RST: tcp_pdu_len %d less than 2\n",
                    rte_lcore_id(), payloadlen);*/
            return rst_tcp_conn(m, ip_head, is_ipv6, tcph, seq, payloadlen);
        }

        uint16_t tcp_data_len = adns_ntohs(*(uint16_t *)payload);
        // clear here, will be set when response
        *(uint16_t *)payload = 0;
        payload += 2;
        if (unlikely(tcp_data_len > (payloadlen - 2))) {
            STATS(TCP_PKT_LEN_ERR);
/*            ALOG(SERVER, WARN,
                    "Core %d RST: tcp_data_len %d bigger than the rest of pdu_len %d\n",
                    rte_lcore_id(), tcp_data_len, payloadlen);*/
            return rst_tcp_conn(m, ip_head, is_ipv6, tcph, seq, payloadlen);
        }

        STATS(TCP_DNS_IN);
        int ret = dns_input(m, eth_hdr, ip_head, (union common_l4_head *) tcph,
                tcp_data_len, (struct dns_header *) payload, port, is_ipv6, 1, 0);
        if (unlikely(IO_RET_DROP == ret)) {
/*            ALOG(SERVER, WARN,
                    "Core %d RST: failed to process dns payload\n", rte_lcore_id());*/
            return rst_tcp_conn(m, ip_head, is_ipv6, tcph, seq, payloadlen);
        } else if (IO_RET_FREE == ret) {
            return ack_tcp_conn(m, ip_head, is_ipv6, tcph, seq, payloadlen);
        } else if (IO_RET_ANSWER == ret) {
            tcph->tcp_flags = TCP_PSH_FLAG | TCP_ACK_FLAG;
            tcph->sent_seq = tcph->recv_ack;
            tcph->recv_ack = adns_htonl(seq + payloadlen);
        }

        return ret;
    } else {
        goto drop_pkt;
    }

    return 0;
drop_pkt:
    rte_pktmbuf_free(m);
    return IO_RET_DROP;
}

static inline int fwd_req_input(struct lcore_msg_fwd *msg) {
    node *find;
    int answer, ret;
    uint8_t qkey[QKEY_LEN];
    //memset(qkey, 0, sizeof(qkey));
    int klen = get_query_key(&msg->packet, qkey);

    answer = query_find(qkey, klen, msg->idx, msg->eth_hdr, msg->ip_head,
            msg->l4_head, msg->l4_len, &msg->packet, msg->port_id, &find,
            msg->is_ipv6, msg->is_tcp, msg->is_from_kni, msg->support_ecs);
    /* answer:
     * 0: need recursive in current lcore
     * 1: find a cache node
     */
    if (answer == 0) {
        log_query_info(msg->ip_head, msg->l4_head, msg->is_tcp,
                msg->is_from_kni, &msg->packet, LOG_ACTION_FORWARD);
        return IO_RET_FREE;
    } else if (answer == 1) {
        log_query_info(msg->ip_head, msg->l4_head, msg->is_tcp,
                msg->is_from_kni, &msg->packet, LOG_ACTION_ANSWER);
        if (answer_from_node(msg->m, msg->eth_hdr, msg->ip_head, msg->l4_head,
                msg->l4_len, msg->dns_hdr, find, &msg->packet, msg->is_ipv6,
                msg->is_tcp, msg->is_from_kni) == 0) {
            if (msg->is_from_kni) {
                STATS(KNI_DNS_OUT);
                struct lcore_msg_info* entry;
                int kni_id = kni_lcore_port_map[msg->port_id];
                entry = get_kni_msg_info(msg->m, msg->eth_hdr, msg->ip_head,
                        msg->l4_head, 1, msg->port_id);
                if (entry == NULL) {
                    return IO_RET_DROP;
                }
                ret = lcore_msg_send(entry, kni_id);
                if (ret < 0) {
                    return IO_RET_DROP;
                }
                return IO_RET_STOLEN;
            }
            STATS(DNS_OUT);
            return IO_RET_ANSWER;
        }
        /* answer_from_node has rte_pktmbuf_free(m); when error*/
        STATS(DNS_DROP);
        return IO_RET_ERROR;
    } else {
        if (SRV_TYPE_AUTH == msg->packet.srv_type) {
            return answer_refused(&msg->packet, msg->ip_head, msg->l4_head, msg->dns_hdr, msg->is_ipv6,
                    msg->is_tcp, msg->is_from_kni);
        } else {
            return answer_srvfail(&msg->packet, msg->ip_head, msg->l4_head, msg->dns_hdr, msg->is_ipv6,
                    msg->is_tcp, msg->is_from_kni);
        }
    }

    return IO_RET_ERROR;
}

static inline int msg_tcp_update(struct lcore_msg_fwd *msg, int is_ack) {
    uint32_t seq = adns_ntohl(msg->l4_head->tcp_hdr.sent_seq);
    if (is_ack) {
        return ack_tcp_conn(msg->m, msg->ip_head, msg->is_ipv6,
                &msg->l4_head->tcp_hdr, seq, msg->l4_len + 2);
    } else {
        msg->l4_head->tcp_hdr.tcp_flags = TCP_PSH_FLAG | TCP_ACK_FLAG;
        msg->l4_head->tcp_hdr.sent_seq = msg->l4_head->tcp_hdr.recv_ack;
        msg->l4_head->tcp_hdr.recv_ack = adns_htonl(seq + msg->l4_len + 2);
    }

    return IO_RET_ANSWER;
}

void msg_input(struct lcore_msg_fwd *msg) {
    /* msg could come from IO cores and KNI cores
     * so here must use msg->is_from_kni */
    int ret = fwd_req_input(msg);

    if (unlikely(ret < 0)) {
        if (IO_RET_DROP == ret) {
            STATS(DNS_DROP);
            rte_pktmbuf_free(msg->m);
            return;
        } else if (IO_RET_FREE == ret) {
            if (!msg->is_tcp) {
                rte_pktmbuf_free(msg->m);
                return;
            }
        } else {
            return;
        }
    }

    if (msg->is_ipv6) {
        if (msg->is_tcp) {
            STATS(TCP_OUT);
            if (unlikely(msg_tcp_update(msg, (IO_RET_FREE == ret))
                    != IO_RET_ANSWER)) {
                rte_pktmbuf_free(msg->m);
                return;
            }
            l4_tcp_output(&(msg->l4_head->tcp_hdr));
            msg->m->l4_len = sizeof(struct tcp_hdr);
            msg->m->ol_flags = PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;
            l3_output_ipv6(&(msg->ip_head->ipv6_hdr));
            msg->l4_head->tcp_hdr.cksum =
                    rte_ipv6_phdr_cksum((void *) msg->ip_head, msg->m->ol_flags);
        } else {
            STATS(UDP_OUT);
            l4_udp_output(&(msg->l4_head->udp_hdr));
            msg->m->l4_len = sizeof(struct udp_hdr);
            msg->m->ol_flags = PKT_TX_IPV6 | PKT_TX_UDP_CKSUM;
            l3_output_ipv6(&(msg->ip_head->ipv6_hdr));
            msg->l4_head->udp_hdr.dgram_cksum =
                rte_ipv6_phdr_cksum((void *) msg->ip_head, msg->m->ol_flags);
        }
        msg->ip_head->ipv6_hdr.hop_limits = IPV6_TTL;
        msg->m->l3_len = sizeof(struct ipv6_hdr);
        l2_output(msg->eth_hdr);
        msg->m->l2_len = sizeof(struct ether_hdr);
    } else {
        if (msg->is_tcp) {
            STATS(TCP_OUT);
            if (unlikely(msg_tcp_update(msg, (IO_RET_FREE == ret))
                    != IO_RET_ANSWER)) {
                rte_pktmbuf_free(msg->m);
                return;
            }
            l4_tcp_output(&(msg->l4_head->tcp_hdr));
            msg->m->l4_len = sizeof(struct tcp_hdr);
            msg->m->ol_flags = PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
            l3_output(&(msg->ip_head->ipv4_hdr));
            msg->l4_head->tcp_hdr.cksum =
                    rte_ipv4_phdr_cksum((void *)msg->ip_head, msg->m->ol_flags);
        } else {
            STATS(UDP_OUT);
            l4_udp_output(&(msg->l4_head->udp_hdr));
            msg->m->ol_flags = PKT_TX_IPV4;
            l3_output(&(msg->ip_head->ipv4_hdr));
            msg->l4_head->udp_hdr.dgram_cksum = 0;
        }

        msg->ip_head->ipv4_hdr.time_to_live = IPV4_TTL;
        msg->ip_head->ipv4_hdr.hdr_checksum = 0;
        msg->m->l3_len = sizeof(struct ipv4_hdr);
        msg->m->ol_flags |= PKT_TX_IP_CKSUM;
        l2_output(msg->eth_hdr);
        msg->m->l2_len = sizeof(struct ether_hdr);
    }

    send_single_frame(msg->m, msg->port_id);
}

static inline void ipv6_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        uint8_t port)
{
    uint8_t l6_proto, offset;
    uint16_t ip_pld_len;
    union common_ip_head *ip_head;
    struct udp_hdr *udh;
    struct tcp_hdr *tcph;
    int ret;

    ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
            sizeof(struct ether_hdr));
    if (unlikely((ret = is_valid_ipv6_pkt(&(ip_head->ipv6_hdr), m->pkt_len - ETH_HLEN,
            &ip_pld_len, &offset)) < 0)) {
        //ALOG(QUERY, ERROR, "Not valid ipv6 packet ,drop");
        STATS(IPv6_FILTER_DROP),
        rte_pktmbuf_free(m);
        return;
    }
    l6_proto = (uint8_t)ret;
    switch (l6_proto) {
        case IPPROTO_UDP:
            udh = (struct udp_hdr*)((uint8_t*)ip_head + offset);
            /* packets which from ipv6_input always come from IO core
             * so is_from_kni wiil be 0*/
            ret = udp_input(m, eth_hdr, ip_head, udh, port, 1, 0, ip_pld_len);
            if (likely(ret < 0)) {
                return;
            }
            STATS(UDP_OUT);
            l4_udp_output(udh);
            m->l4_len = sizeof(struct udp_hdr);
            m->ol_flags = PKT_TX_IPV6 | PKT_TX_UDP_CKSUM;
            l3_output_ipv6(&(ip_head->ipv6_hdr));
            udh->dgram_cksum = rte_ipv6_phdr_cksum((void *)ip_head, m->ol_flags);
            break;
        case IPPROTO_TCP:
            STATS(TCP_IN);
            tcph = (struct tcp_hdr*)((uint8_t*)ip_head + offset);
            ret = tcp_input(m, eth_hdr, ip_head, tcph, port, 1, ip_pld_len);
            if (likely(ret < 0)) {
                return;
            }
            STATS(TCP_OUT);
            l4_tcp_output(tcph);
            m->l4_len = sizeof(struct tcp_hdr);
            m->ol_flags = PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;
            l3_output_ipv6(&(ip_head->ipv6_hdr));
            tcph->cksum = rte_ipv6_phdr_cksum((void *)ip_head, m->ol_flags);
            break;
        default:
            /* traffic except TCP and UDP is not supposed to received */
            STATS(IPv6_FILTER_DROP);
            rte_pktmbuf_free(m);
            return;
    }

    ip_head->ipv6_hdr.hop_limits = IPV6_TTL;
    l2_output(eth_hdr);
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = sizeof(struct ipv6_hdr);
    send_single_frame(m, port);
}

static inline void ipv4_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        uint8_t port)
{
    int ret;
    uint8_t l4_proto, offset;
    uint16_t ip_pld_len;
    struct udp_hdr *udh;
    struct tcp_hdr *tcph;
    union common_ip_head *ip_head;

    ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
            sizeof(struct ether_hdr));
    if (unlikely(is_valid_ipv4_pkt(&(ip_head->ipv4_hdr), m->pkt_len - ETH_HLEN,
            &ip_pld_len, &offset))
            < 0) {
        //ALOG(QUERY, ERROR, "Not valid ipv4 packet ,drop");
        STATS(IP_FILTER_DROP),
        rte_pktmbuf_free(m);
        return;
    }

    if (man_ip_blacklist_judge(ip_head->ipv4_hdr.src_addr)) {
        /*ALOG(QUERY, INFO,
                "Lcore %u (CLIENTQUERY): Client ip : %d.%d.%d.%d match ip blacklist,drop",
                rte_lcore_id(), NIP_STR(ip_head->ipv4_hdr.src_addr));*/
        STATS(BLACK_IP_DROP),
        rte_pktmbuf_free(m);
        return;
    }

    l4_proto = ip_head->ipv4_hdr.next_proto_id;
    switch (l4_proto) {
    case IPPROTO_UDP:
        STATS(UDP_IN);
        udh = (struct udp_hdr*)((uint8_t*)ip_head + offset);
        /* packets which from ipv4_input always come from IO core
         * so is_from_kni wiil be 0*/
        ret = udp_input(m, eth_hdr, ip_head, udh, port, 0, 0, ip_pld_len);
        if (likely(ret < 0)) {
            return;
        }
        STATS(UDP_OUT);
        l4_udp_output(udh);
        m->ol_flags = PKT_TX_IPV4;
        l3_output(&(ip_head->ipv4_hdr));
        udh->dgram_cksum = 0;
        break;
    case IPPROTO_TCP:   /* parse TCP DNS request */
        STATS(TCP_IN);
        tcph = (struct tcp_hdr*)((uint8_t*)ip_head + offset);
        ret = tcp_input(m, eth_hdr, ip_head, tcph, port, 0, ip_pld_len);
        if (likely(ret < 0)) {
            return;
        }
        STATS(TCP_OUT);
        l4_tcp_output(tcph);
        m->l4_len = sizeof(struct tcp_hdr);
        m->ol_flags = PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
        l3_output(&(ip_head->ipv4_hdr));
        tcph->cksum = rte_ipv4_phdr_cksum((void *)ip_head, m->ol_flags);
        break;
    default:
        STATS(IP_FILTER_DROP),
        rte_pktmbuf_free(m);
        return;
    }

    ip_head->ipv4_hdr.hdr_checksum = 0;
    ip_head->ipv4_hdr.time_to_live = IPV4_TTL;
    l2_output(eth_hdr);
    m->ol_flags |= PKT_TX_IP_CKSUM;
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = sizeof(struct ipv4_hdr);
    send_single_frame(m, port);
}

static inline void raw_input(struct rte_mbuf *m, uint8_t port)
{
    uint16_t ether_type;
    struct ether_hdr *eth_hdr;

    int dlen = ETH_HLEN + IP_HLEN + UDP_HLEN + DNS_HLEN;
    if (unlikely(rte_pktmbuf_data_len(m) < dlen)) {
/*        if (unlikely(rte_pktmbuf_data_len(m) < ETH_HLEN)) {
            ALOG(QUERY, ERROR, "Unexpected DATA len < ETH_HLEN,%d < %d",
                 rte_pktmbuf_data_len(m), ETH_HLEN);
        }
        ALOG(QUERY, ERROR,
             "DATA len < ETH_HLEN + IP_HLEN + UDP_HLEN + DNS_HLEN, %d < %d,drop",
             rte_pktmbuf_data_len(m), dlen);*/
        STATS(ETH_FILTER_DROP);
        rte_pktmbuf_free(m);
        return;
    }
    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    if (eth_hdr == NULL) {
        //ALOG(QUERY, ERROR, "Unexpected mbuf recv,eth_hdr == NULL");
        STATS(ETH_FILTER_DROP);
        rte_pktmbuf_free(m);
        return;
    }

    /* like ntohs */
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    if (ether_type != ETHER_TYPE_IPv4 && ether_type != ETHER_TYPE_IPv6) {
        /*ALOG(QUERY, ERROR, "Not ipv4 or ipv6 packet come in at port %d,queue %d", port,
             queue);*/
        STATS(ETH_FILTER_DROP);
        rte_pktmbuf_free(m);
        return;
    }

    if(nic[port].ready == 0) {//not need
        ether_addr_copy(&eth_hdr->d_addr, &nic[port].nic_mac);
        ether_addr_copy(&eth_hdr->s_addr, &nic[port].gw_mac);
        nic[port].ip = get_port_ip_net(port);
        nic[port].ready = 1;
    }
    set_active_port(port);
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    switch (ether_type) {
        case ETHER_TYPE_IPv6:
            ipv6_input(m, eth_hdr, port);
            break;
        case ETHER_TYPE_IPv4:
            ipv4_input(m, eth_hdr, port);
            break;
        default:
            rte_pktmbuf_free(m);
            return;
    }
}

void raw_input_bulk(struct rte_mbuf **m, int nb_pkts, uint8_t port) {
    int i;

    /* Prefetch first packets */
    for (i = 0; i < PREFETCH_OFFSET && i < nb_pkts; i++) {
        rte_prefetch0(rte_pktmbuf_mtod(m[i], void *));
        /* The DNS request packet is bigger than 64 bytes in most cases,
         * so pre-fetch the next cache line size. It is safe because the
         * DEFAULT_MBUF_SIZE is very big(4096).
         */
        rte_prefetch0(rte_pktmbuf_mtod(m[i], uint8_t *) + RTE_CACHE_LINE_SIZE);
    }

    /* Prefetch and forward already prefetched packets */
    for (i = 0; i < (nb_pkts - PREFETCH_OFFSET); i++) {
        rte_prefetch0(rte_pktmbuf_mtod(m[ i + PREFETCH_OFFSET], void *));
        rte_prefetch0(
                rte_pktmbuf_mtod(m[i + PREFETCH_OFFSET], uint8_t *) +
                RTE_CACHE_LINE_SIZE);
        raw_input(m[i], port);
    }

    /* Forward remaining prefetched packets */
    for (; i < nb_pkts; i++) {
        raw_input(m[i], port);
    }
}
