#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <openssl/ecdsa.h>
#include <openssl/ec.h> 
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_eth_ctrl.h>
#include "rte_core.h"

#include "adns.h"
#include "descriptor.h"
#include "consts.h"
#include "wire.h"
#include "datapath.h"
#include "net_debug.h"
#include "msg.h"
#include "dns_pkt.h"
#include "log.h"
#include "init_zone.h"
#include "iplib.h"
#include "zonedb.h"
#include "zone.h"
#include "node.h"
#include "utili_base.h"
#include "adns_stats.h"
#include "adns_conf.h"
#include "common_value.h"
#include "adns_counter.h"
#include "view_maps.h"
#include "errcode.h"
#include "syslog.h"
#include "ip_fragment.h"
#include "tolower.h"
#include "adns_log.h"
#include "dnssec.h"


#define RET_NOERROR 0
#define RET_NOERROR_SOA 1
#define RET_NXDOMAIN -1
#define RCORD_RANDOM_NUM 20
#define ADNS_SYSLOG_IP_DF        0x4000      /* Flag: "Don't Fragment"   */

#define VIEW_ARRAY_MAX 3

typedef struct __view_array_t
{
    adns_viewid_t  __IDs[VIEW_ARRAY_MAX];
    int8_t         __next_pos;
} VIEW_ARRAY_T;

#define VIEW_ARRAY(name) \
    struct __view_array_t (name); \
    (name).__next_pos = 0

#define VIEW_ARRAY_PUSH(view_array, view_id) \
    if ((view_array).__next_pos < VIEW_ARRAY_MAX) \
        (view_array).__IDs[(view_array).__next_pos++] = (view_id)

#define VIEW_ARRAY_FIRST_VIEWID(view_array) \
    (view_array).__IDs[0]

#define VIEW_ARRAY_FOR_EACH(view_array, view_id)  \
    int idx = 0; \
    for ((view_id) = (view_array).__IDs[0]; \
            idx < (view_array).__next_pos && ( ((view_id) = (view_array).__IDs[idx]) || 1); \
            idx++) 
    // let view_id be changed only when idx is in its valid range
    // we do not want to leave the view_id an invalid value outside the loop

// macro of DNSSEC ready
#define DNSSEC_READY(query, zone) \
    unlikely((query)->dnssec == 1 && (zone)->enable_dnssec == 1 && (zone)->dnssec_ok == 1)

// macro of unsigned delegation(ADNS not support DS RR type yet, so all sub domain delegations are unsigned)
#define UNSIGNED_DELEGATION(type, is_apex) \
    unlikely(((type) == ADNS_RRTYPE_NS) && ((is_apex) == 0))


extern int * g_adns_pkt_drop_counter;
extern const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
extern uint64_t g_cycles_sec;
extern const struct rte_memzone *g_adns_counter_table[RTE_MAX_NUMA_NODES][RTE_MAX_LCORE];
extern uint64_t g_cycles_defense_sec;
extern uint64_t g_data_flush_sec;
extern uint64_t g_zone_bps_defense_quota;
extern uint64_t g_zone_qps_defense_quota;
extern uint64_t g_domain_bps_defense_quota;
extern uint64_t g_domain_qps_defense_quota;
extern uint64_t g_time_interval;

extern uint32_t g_adns_counter_num;
extern uint16_t g_io_lcore_id_start;

extern char *g_hostname;
extern char g_idcname[];
extern char g_time_str[40];

static inline int adns_dname_wire_check_tcp(const uint8_t *name, const uint8_t *endp, uint8_t *lower_name);

/* The characters in dname only could be digit(48-57), alpha(65-90, 97-122), _(95), -(45), and *(42) */
static const uint8_t valid_char_table[CHAR_TABLE_SIZE] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

#define CH_HOST_NAME_LEN 15
// 8hostname4adns0
static const uint8_t ch_host_name[CH_HOST_NAME_LEN] = { 
    0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65,
    0x04, 0x61, 0x64, 0x6e, 0x73, 0x00, 
};
#define CH_VIEW_LEN 11
// 4view4adns0
static const uint8_t ch_view[CH_VIEW_LEN] = { 0x04, 0x76, 0x69, 0x65, 0x77, 0x04, 0x61, 0x64, 0x6e, 0x73, 0x00, };

static inline int
resp_put_aname_all_rr(struct adns_packet *packet, 
        const struct adns_node *node, adns_type_t type, struct adns_rrset *rrset, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl,
        int *an_nums, const adns_dname_t *query_name_cursor);
static inline int
resp_put_ans_ratio(struct adns_packet *query, const struct adns_node *node, 
        adns_type_t type, struct adns_rrset *rrset, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl,
        int *an_nums, const adns_dname_t *query_name_cursor);


static inline int 
udp_input(struct rte_mbuf *m, union common_ip_head *ip_head,
        struct udp_hdr *udh, uint8_t port, int *append_len,
        int isipv6);

void resp_set_refuse(struct dns_header *dnh)
{
    adns_wire_set_rcode((uint8_t *)dnh, ADNS_RCODE_REFUSED);
}

static inline int
packet_edns_size(struct adns_packet *query)
{
    int len = 0;

    if (!query->has_edns) {
        return 0;
    }
    len += EDNS_EMPTY_SIZE;
    // only respond ecs opt
    if (query->has_ecs) {
        struct adns_opt_rr *opt_rr = &(query->opt_rr);
        len += 8 + opt_rr->opt_ecs.addr_len;
    }

    return len;
}

/* The endp points to the next position of query's last valid octet */
static inline int adns_dname_wire_check(const uint8_t *name, const uint8_t *endp, uint8_t *lower_name)
{
    int name_len = 1; /* Keep \x00 terminal label in advance. */
    const uint8_t *next_label;

    if (unlikely(name == NULL || name == endp)){
        return -EINVAL;
    }

    while (*name != '\0') {
        /* Check label length (maximum 63 bytes allowed). */
        if (unlikely(*name > ADNS_DNAME_LABEL_MAXLEN)){
            return -1;
        }
        int lblen = *name + 1;

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
            if (likely(valid_char_table[*name])) {
                *lower_name++ = adns_tolower(*name++);
                continue;
            }
            return -1;
        } while (name < next_label);

        /* Update wire size only for noncompressed part. */
        name_len += lblen;
    }

    *lower_name = '\0';

    return name_len;
}

int ns_send_syslog_ipv4(uint8_t port, const char *fmt, ...)
{
    va_list args;
    int lcore;
    uint8_t dst_port_index = 0;
    struct timeval tv;
    int16_t udlen = 0;
    char *s = NULL;
    struct udp_hdr *udh = NULL;
    struct ipv4_hdr *iphdr = NULL;
    struct ether_hdr *eth = NULL;
    struct rte_mbuf *mbuf = NULL;

    //If the domain is not visited for long time. don't send the log.

    if (g_syslogmbuf_pool == NULL) {
        return -1;
    }

    if (port >= ADNS_SYSLOG_MAX_PORTS) {
        return -2;
    }

    /* these are learned, check if they are ready */
    lcore = rte_lcore_id();
    if (unlikely(g_syslog_ctl.ipv4_src_addr[port] == 0 ||
                is_zero_ether_addr(&app.eth_addrs[port]) ||
                is_zero_ether_addr(&g_syslog_ctl.d_addr[port]) ) ) {
       return -3;
    }

    mbuf = rte_pktmbuf_alloc(g_syslogmbuf_pool);
    if (mbuf == NULL) {
        return -4;
    }


    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ether_addr_copy(&app.eth_addrs[port], &eth->s_addr);
    ether_addr_copy(&g_syslog_ctl.d_addr[port], &eth->d_addr);

    iphdr = (struct ipv4_hdr *)&eth[1];
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->packet_id = 0;
    iphdr->fragment_offset = rte_cpu_to_be_16(ADNS_SYSLOG_IP_DF);
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->hdr_checksum = 0;
    iphdr->src_addr = g_syslog_ctl.ipv4_src_addr[port];
    iphdr->dst_addr = g_syslog_ctl.ipv4_dst_addr;

    udh = (struct udp_hdr *)&iphdr[1];
    dst_port_index = g_syslog_ctl.current_port[lcore] % g_syslog_ctl.max_port;
    g_syslog_ctl.current_port[lcore]++;
    udh->src_port = rte_cpu_to_be_16(g_syslog_ctl.src_port[lcore][dst_port_index]);
    udh->dst_port = rte_cpu_to_be_16(g_syslog_ctl.dst_port);
    udh->dgram_cksum = 0;

    gettimeofday(&tv, NULL);
    s = (char *)&udh[1];

    va_start(args, fmt);
    udlen = vsnprintf(s, 256, fmt, args);
    va_end(args);
    if (unlikely(rte_pktmbuf_append(mbuf, ETH_HLEN + sizeof(struct ipv4_hdr) + UDP_HLEN + udlen) == NULL)) {
        rte_pktmbuf_free(mbuf);
        return -5;
    }

    udh->dgram_len = adns_htons(UDP_HLEN + udlen);
    iphdr->total_length = adns_htons(sizeof(struct ipv4_hdr) + UDP_HLEN + udlen);

    mbuf->ol_flags |= PKT_TX_IP_CKSUM;
    mbuf->l2_len = sizeof(struct ether_hdr);
    mbuf->l3_len = sizeof(struct ipv4_hdr);

    log_server_info(lcore, "lcore %d, %d.%d.%d.%d:%u->%d.%d.%d.%d:%u, %s",
                    lcore,
                    NIPQUAD(iphdr->src_addr), adns_ntohs(udh->src_port),
                    NIPQUAD(iphdr->dst_addr), adns_ntohs(udh->dst_port), s);

    send_single_packet(mbuf, port);
    return 0;
}

#if ZONE_CNT
void __adns_traffic_check_qps_send (uint8_t port, struct adns_zone *zone, struct adns_node *node)
{
    uint64_t curr_node_queries = 0, curr_node_bytes = 0;
    uint64_t sub_node_queries = 0, sub_node_bytes = 0;
    char *zone_str = NULL, *qname_str = NULL;
    uint64_t curr_time = 0L, zone_time_interval;

    curr_time = rte_get_timer_cycles();
    zone_time_interval = curr_time - zone->pre_timestamp;
    if(zone_time_interval < g_cycles_defense_sec){
        return;
    }

    uint64_t curr_zone_queries = 0, curr_zone_bytes = 0;
    uint64_t sub_zone_queries = 0, sub_zone_bytes = 0;
    /* zone qps */
    adns_counter_sum_get_queries_bytes(zone->counter_id, &curr_zone_queries, &curr_zone_bytes);

    if(likely((curr_zone_queries > zone->pre_zone_queries) && (curr_zone_bytes > zone->pre_zone_bytes))){
        sub_zone_queries = curr_zone_queries - zone->pre_zone_queries;
        sub_zone_bytes = curr_zone_bytes - zone->pre_zone_bytes;
    }else{
        return;
    }

    if(sub_zone_queries > g_zone_qps_defense_quota){
        zone_str = adns_dname_to_str(zone->name);
        if (zone->max_stat_node) {
            qname_str = adns_dname_to_str(zone->max_stat_node->name);
        } else {
            qname_str = adns_dname_to_str(zone->name);
        }
        /* TZQ(threshold of zone qps) exceed limit */
        ns_send_syslog_ipv4(port, "<86>ADNS-TZQ-%s,%s,%s,%s,%s,A,%u,0,0,%u,%s\n",
             g_syslog_ctl.tag, g_time_str, g_idcname, g_hostname,
             zone_str, sub_zone_queries/g_time_interval, sub_zone_bytes/g_time_interval, qname_str);
        free(zone_str);
        free(qname_str);
    }

    zone->pre_timestamp = curr_time;
    zone->pre_zone_queries = curr_zone_queries;
    zone->pre_zone_bytes = curr_zone_bytes;
    // TODO： should we delete below three members, looks like they are not really used
    zone->max_stat_node = NULL;
    zone->max_node_queries = 0;
    zone->max_node_bytes = 0;


    /* node qps */
    if(node != NULL){
        adns_counter_sum_get_queries_bytes(node->counter_id, &curr_node_queries, &curr_node_bytes);

        if(likely((curr_node_queries > node->pre_node_queries) && (curr_node_bytes > node->pre_node_bytes))){
            sub_node_queries = curr_node_queries - node->pre_node_queries;
            sub_node_bytes = curr_node_bytes - node->pre_node_bytes;
        }else{
            return;
        }

        if((zone->max_stat_node == NULL) || ((sub_node_queries > zone->max_node_queries) && (sub_node_bytes > zone->max_node_bytes))){
            zone->max_stat_node = node;
            zone->max_node_queries = sub_node_queries;
            zone->max_node_bytes = sub_node_bytes;
        }
        if (sub_node_queries >= g_domain_qps_defense_quota) {
            zone_str = adns_dname_to_str(zone->name);
            qname_str = adns_dname_to_str(node->name);

            /* TDQ(threshold of domain qps) exceed limit */

            /* 3rd last field 0 means NXDOMAIN,
               2nd last field 0 means NOERROR.
               They are not used now, reserved for future.
               Put bps & zone name at the last, because logserver don't need
               them. So we give more than they want. */
            ns_send_syslog_ipv4(port, "<86>ADNS-TDQ-%s,%s,%s,%s,%s,A,%u,0,0,%u,%s\n",
                 g_syslog_ctl.tag, g_time_str, g_idcname, g_hostname,
                 qname_str, sub_node_queries/g_time_interval, sub_node_bytes/g_time_interval, zone_str);
            free(zone_str);
            free(qname_str);
        }

        node->pre_timestamp = curr_time;
        node->pre_node_queries = curr_node_queries;
        node->pre_node_bytes = curr_node_bytes;
    }

    return;
}
#endif

static void adns_traffic_handle(uint8_t port, struct adns_zone *zone, struct adns_node *node, uint16_t pkt_length)
{
    int lcore_id = rte_lcore_id();
    uint32_t node_counter_id = 0;
    struct counter *node_counter = NULL;
    const struct rte_memzone *lcore_counter_mz = NULL;

    lcore_counter_mz = g_adns_counter_table[0][lcore_id - g_io_lcore_id_start];

    #if ZONE_CNT
    uint32_t zone_counter_id;
    struct counter *zone_counter;
    zone_counter_id = zone->counter_id;
    if(INVALID_COUNTER_ID(zone_counter_id)){
        return;
    }
    zone_counter = (struct counter *)(lcore_counter_mz->addr) + zone_counter_id;
    zone_counter->queries++;
    zone_counter->bytes += pkt_length;
    #endif

    if(node != NULL){
        node_counter_id = node->counter_id;
        if(INVALID_COUNTER_ID(node_counter_id)){
            return;
        }
        node_counter = (struct counter *)(lcore_counter_mz->addr) + node_counter_id;
        node_counter->queries++;
        node_counter->bytes += pkt_length;
    }

    #if ZONE_CNT
    if(lcore_id == 2){
        __adns_traffic_check_qps_send(port, zone, node);
    }
    #endif
    return;
}

static inline int
adns_response_soa_to_str(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length, char *type, uint16_t qclass, uint32_t ttl)
{
    int i, len, total, dname_len;
    char *domain;
    uint8_t *dname;

    total = 0;
    if (buf == NULL || type == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_SOA_PTR_ERROR;
    }

    /*
     * header format: QNAME | TTL | CLASS | TYPE | RDLENGTH
     */
    domain = adns_dname_to_str(qname);
    len = snprintf(buf + total, maxlen - total, "\"%s %u %u %s %u ", domain, ttl, qclass, type, rdata_length);
    if (len < 0) {
        free(domain);
        return ADNS_RESPONSE_PARSE_SECTION_SOA_DATA_ERROR;
    }
    total += len;
    free(domain);

    /*
     * rdata format: primary ns, mail, searial, refresh, retry, expire, minimum
     */
    /* primary */
    if (maxlen - total <= 0) {
        return total;
    }
    dname = rdata;
    domain = adns_dname_to_str(dname);
    dname_len = adns_dname_size(dname);
    len = snprintf(buf + total, maxlen - total, "%s ", domain);

    if (len < 0) {
        free(domain);
        return ADNS_RESPONSE_PARSE_SECTION_SOA_DATA_ERROR;
    }
    total += len;
    free(domain);

    /* mail */
    if (maxlen - total <= 0) {
        return total;
    }
    dname = dname + dname_len;
    domain = adns_dname_to_str(dname);
    dname_len = adns_dname_size(dname);
    len = snprintf(buf + total, maxlen - total, "%s", domain);
    if (len < 0) {
        free(domain);
        return ADNS_RESPONSE_PARSE_SECTION_SOA_DATA_ERROR;
    }
    free(domain);
    total += len;

    /* serial */
    uint8_t *pos = (uint8_t *)dname + dname_len;
    uint32_t *num32 = (uint32_t *)pos;
    for (i = 0; i < 5; i++) {
        if (maxlen - total <= 0) {
            return total;
        }
        len = snprintf(buf + total, maxlen - total, " %u", adns_ntohl(*num32));
        if (len < 0) {
            return ADNS_RESPONSE_PARSE_SECTION_SOA_DATA_ERROR;
        }
        total += len;
        num32++;
    }

    /* end */
    if (maxlen - total <= 0) {
        return total;
    }
    len = snprintf(buf + total, maxlen - total, "\", ");
    if (len < 0) {
        return ADNS_RESPONSE_PARSE_SECTION_SOA_DATA_ERROR;
    }
    total += len;

    return total;
}


static inline int
adns_response_a_to_str(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length, char *type, uint16_t qclass, uint32_t ttl)
{
    int len = 0;
    char rdata_str[64];
    char *domain;

    if (buf == NULL || type == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_A_PTR_ERROR;
    }

    if (inet_ntop(AF_INET, rdata, rdata_str, 64) == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_A_IP_CONVERT_ERROR;
    }

    domain = adns_dname_to_str(qname);
    len = snprintf(buf, maxlen, "\"%s %u %u %s %u %s\", ", domain, ttl, qclass, type, rdata_length, rdata_str);
    if (len < 0) {
        free(domain);
        return ADNS_RESPONSE_PARSE_SECTION_A_DATA_ERROR;
    }

    free(domain);
    return len;
}


static inline int
adns_response_aaaa_to_str(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length, char *type, uint16_t qclass, uint32_t ttl)
{
    int len = 0;
    char rdata_str[64];
    char *domain;

    if (buf == NULL || type == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_AAAA_PTR_ERROR;
    }

    if (inet_ntop(AF_INET6, rdata, rdata_str, 64) == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_AAAA_IP_CONVERT_ERROR;
    }

    domain = adns_dname_to_str(qname);
    len = snprintf(buf, maxlen, "\"%s %u %u %s %u %s\", ", domain, ttl, qclass, type, rdata_length, rdata_str);
    if (len < 0) {
        free(domain);
        return ADNS_RESPONSE_PARSE_SECTION_AAAA_DATA_ERROR;
    }

    free(domain);
    return len;
}


static inline int
adns_response_domain_to_str(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length, char *type, uint16_t qclass, uint32_t ttl)
{
    int len;
    char *rdata_str;
    char *domain;

    if (buf == NULL || type == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_DOMAIN_PTR_ERROR;
    }

    domain = adns_dname_to_str(qname);
    rdata_str = adns_dname_to_str(rdata);
    len = snprintf(buf, maxlen, "\"%s %u %u %s %u %s\", ", domain, ttl, qclass, type, rdata_length, rdata_str);
    if (len < 0) {
        free(domain);
        free(rdata_str);
        return ADNS_RESPONSE_PARSE_SECTION_DOMAIN_DATA_ERROR;
    }

    free(domain);
    free(rdata_str);
    return len;
}


static inline int
adns_response_mx_to_str(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length, char *type, uint16_t qclass, uint32_t ttl)
{
    int len;
    uint16_t prefer;
    char *rdata_str;
    char *domain;

    if (buf == NULL || type == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_MX_PTR_ERROR;
    }

    domain = adns_dname_to_str(qname);
    prefer = adns_ntohs(*(uint16_t *)rdata);
    rdata_str = adns_dname_to_str(rdata + sizeof(uint16_t));

    len = snprintf(buf, maxlen, "\"%s %u %u %s %u %u %s\", ", domain, ttl, qclass, type, rdata_length, prefer, rdata_str);
    if (len < 0) {
        free(domain);
        free(rdata_str);
        return ADNS_RESPONSE_PARSE_SECTION_MX_DATA_ERROR;
    }

    free(domain);
    free(rdata_str);
    return len;
}


static inline int
adns_response_txt_to_str(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length, char *type, uint16_t qclass, uint32_t ttl)
{
    int len;
    char rdata_str[ADNS_RESPONSE_RECORD_MAX_LEN];
    char *domain;

    if (buf == NULL || type == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_TXT_PTR_ERROR;
    }

    len = ADNS_RESPONSE_RECORD_MAX_LEN - 1;
    if (len > rdata_length - 1) {
        len = rdata_length - 1;
    }

    memcpy(rdata_str, (char *)rdata + 1, len);
    rdata_str[len] = '\0';
    domain = adns_dname_to_str(qname);

    len = snprintf(buf, maxlen, "'%s %u %u %s %u\"%s\"', ", domain, ttl, qclass, type, rdata_length, rdata_str);
    if (len < 0) {
        free(domain);
        return ADNS_RESPONSE_PARSE_SECTION_TXT_DATA_ERROR;
    }

    free(domain);
    return len;
}


static inline int
adns_response_caa_to_str(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length, char *type, uint16_t qclass, uint32_t ttl)
{
    int len;
    char rdata_str[ADNS_RESPONSE_RECORD_MAX_LEN];
    char *domain;

    if (buf == NULL || type == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_CAA_PTR_ERROR;
    }
    uint8_t caa_flags = *rdata;
    uint8_t tag_len = *(rdata + 1);

    len = ADNS_RESPONSE_RECORD_MAX_LEN - 1;
    if (len > (rdata_length - 2)) {
        len = rdata_length - 2;
    }

    memcpy(rdata_str, (char * )(rdata + 2), len);
    rdata_str[len] = '\0';
    domain = adns_dname_to_str(qname);

    len = snprintf(buf, maxlen, "'%s %u %u %s %u %u %u \"%s\"', ", domain, ttl,
            qclass, type, rdata_length, caa_flags, tag_len, rdata_str);
    if (len < 0) {
        free(domain);
        return ADNS_RESPONSE_PARSE_SECTION_CAA_DATA_ERROR;
    }

    free(domain);
    return len;
}

static inline int
adns_response_srv_to_str(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length, char *type, uint16_t qclass, uint32_t ttl)
{
    int len;
    uint16_t pri, weight, port;
    char *rdata_str;
    char *domain;

    if (buf == NULL || type == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_SRV_PTR_ERROR;
    }

    pri = adns_ntohs(*(uint16_t *)rdata);
    weight = adns_ntohs(*((uint16_t *)rdata + 1));
    port = adns_ntohs(*((uint16_t *)rdata + 2));
    rdata_str = adns_dname_to_str(rdata + sizeof(uint16_t) * 3);

    domain = adns_dname_to_str(qname);

    len = snprintf(buf, maxlen, "\"%s %u %u %s %u %u %u %u %s\", ", domain, ttl, qclass, type, rdata_length, pri, weight, port, rdata_str);
    if (len < 0) {
        free(domain);
        free(rdata_str);
        return ADNS_RESPONSE_PARSE_SECTION_SRV_DATA_ERROR;
    }

    free(domain);
    free(rdata_str);
    return len;
}


static inline int
adns_response_combine_record(char *buf, int maxlen, uint8_t *qname, uint8_t *rdata, uint16_t rdata_length,
                             uint16_t qtype, uint16_t qclass, uint32_t ttl)
{
    int len;

    switch (qtype) {
        case ADNS_RRTYPE_SOA:
              len = adns_response_soa_to_str(buf, maxlen, qname, rdata, rdata_length, "SOA", qclass, ttl);
              break;
        case ADNS_RRTYPE_A:
            len = adns_response_a_to_str(buf, maxlen, qname, rdata, rdata_length, "A", qclass, ttl);
            break;
        case ADNS_RRTYPE_AAAA:
            len = adns_response_aaaa_to_str(buf, maxlen, qname, rdata, rdata_length, "AAAA", qclass, ttl);
            break;
        case ADNS_RRTYPE_NS:
            len = adns_response_domain_to_str(buf, maxlen, qname, rdata, rdata_length, "NS", qclass, ttl);
            break;
        case ADNS_RRTYPE_CNAME:
            len = adns_response_domain_to_str(buf, maxlen, qname, rdata, rdata_length, "CNAME", qclass, ttl);
            break;
        case ADNS_RRTYPE_MX:
            len = adns_response_mx_to_str(buf, maxlen, qname, rdata, rdata_length, "MX", qclass, ttl);
            break;
        case ADNS_RRTYPE_PTR:
            len = adns_response_domain_to_str(buf, maxlen, qname, rdata, rdata_length, "PTR", qclass, ttl);
            break;
        case ADNS_RRTYPE_TXT:
            len = adns_response_txt_to_str(buf, maxlen, qname, rdata, rdata_length, "TXT", qclass, ttl);
            break;
        case ADNS_RRTYPE_SRV:
            len = adns_response_srv_to_str(buf, maxlen, qname, rdata, rdata_length, "SRV", qclass, ttl);
            break;
        case ADNS_RRTYPE_CAA:
            len = adns_response_caa_to_str(buf, maxlen, qname, rdata, rdata_length, "CAA", qclass, ttl);
            break;
        default:
            len = 0;
            break;
    }

    return len;
}


static inline int
adns_response_parse_section(struct adns_response *response, int count, int max_limit_count, char *buf)
{
    int i, len, total, maxlen, qname_len, offset, combine_stop_flag = 0;
    uint16_t qtype, qclass, rdata_length;
    uint32_t ttl;
    uint8_t *wire = NULL, *qname = NULL;

    if (response == NULL || buf == NULL) {
        return ADNS_RESPONSE_PARSE_SECTION_PTR_NULL;
    }

    maxlen = ADNS_RESPONSE_RECORD_MAX_LEN;
    total = 0;

    wire = response->wire;
    for (i = 0; i < count; i++) {
        if (!combine_stop_flag && (maxlen - total <= 0)) {
            combine_stop_flag = 1;
        }

        if (!combine_stop_flag && (i >= max_limit_count)) {
            combine_stop_flag = 1;
        }

        if (adns_wire_is_pointer(wire + response->parsed) != 0) {
            offset = adns_wire_read_u16(wire + response->parsed) - 49152;
            qname = wire + offset;
        } else {
            qname = wire + response->parsed;
        }

        qname_len = adns_dname_size(wire + response->parsed);
        if (qname_len < 1) {
            return ADNS_RESPONSE_PARSE_SECTION_QNAME_ERROR;
        }
        response->parsed += qname_len;

        qtype = adns_wire_read_u16(wire + response->parsed);
        qclass = adns_wire_read_u16(wire + response->parsed + 2);
        ttl = adns_wire_read_u32(wire + response->parsed + 4);
        rdata_length = adns_wire_read_u16(wire + response->parsed + 8);
        response->parsed += ADNS_RR_HEADER_SIZE;

        if (!combine_stop_flag) {
            len = adns_response_combine_record(buf + total, maxlen - total, qname,
                                           wire + response->parsed, rdata_length, qtype, qclass, ttl);
            if (len < 0) {
                return len;
            }
            total += len;
        }
        response->parsed += rdata_length;
    }

    return 0;
}

/* static functions not used in this file, comment it to avoid gcc warning
   uncomment them if used or remove static modifier */
#if 0
static void
dump_dns_header(struct dns_header *header)
{
    printf("\n---- DNS HEADER START ----\n");
    printf("ID :%u, flags1: %x, flags2: %x, qdcount: %u, "
            "ancount: %u, nscount: %u, arcount: %u\n",
            header->id, header->flags1, header->flags2,
            header->qdcount, header->ancount, header->nscount, 
            header->arcount);
    printf("==== DNS HEADER END ====\n");
}

static void
adns_dump_mbuf(struct rte_mbuf *m, struct adns_packet *pkt)
{
    struct dns_header *dnh;
    uint8_t *pos;

    dnh = (struct dns_header *)pkt->wire;
    /* header */
    dump_dns_header(dnh);
    // questions, only allow one question
    printf("qname: %s\n", pkt->wire + ADNS_WIRE_HEADER_SIZE);

    // dump answer section
    pos = pkt->wire + ADNS_WIRE_HEADER_SIZE + pkt->qname_size + 4;
    printf("Answer secion name: %s\n", pos);
    pos += pkt->qname_size;
    // type, class, ttl, rdata length, rdata
    printf("type: %u, class: %u, ttl: %u\n", 
            adns_ntohs(*(uint16_t *)pos),
            adns_ntohs(*(uint16_t *)(pos + 2)),
            adns_ntohl(*(uint32_t *)(pos + 4)));
    pos += 8;
    printf("rdata len: %u, rdata: %s\n",
            adns_ntohs(*(uint16_t *)pos),
            pos + 2);

}
#endif

static inline uint8_t
adns_packet_opcode(const struct adns_packet *packet)
{
    uint8_t flags = adns_wire_get_flags1(packet->wire);
    return adns_wire_flags_get_opcode(flags);
}

/*
 * Parse dns header from the wire format.
 */
static inline int
dns_parse_header(const uint8_t *wire, size_t *pos, size_t size,
        struct dns_header *header)
{
    if (unlikely(wire == NULL || pos == NULL || header == NULL)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PARSE_DNS_WIRE_NULL_FAILED]);
        return -1;
    }

    if (unlikely(size - *pos < ADNS_WIRE_HEADER_SIZE)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_BAD_LENGTH]);
        return -1;
    }

    header->id = adns_wire_get_id(wire);
    header->flags1 = adns_wire_get_flags1(wire);
    header->flags2 = adns_wire_get_flags2(wire);
    header->qdcount = adns_wire_get_qdcount(wire);
    header->ancount = adns_wire_get_ancount(wire);
    header->nscount = adns_wire_get_nscount(wire);
    header->arcount = adns_wire_get_arcount(wire);

    *pos += ADNS_WIRE_HEADER_SIZE;

    return 0;
}

/*
 * Parse DNS Question entry from the wire format
 */
static inline int
adns_parse_question(const uint8_t *wire, size_t *pos, size_t size,
        struct adns_packet *packet, uint8_t *lower_name)
{
    int len;

    if (unlikely(wire == NULL || pos == NULL || packet == NULL)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PARSE_DNS_WIRE_NULL_FAILED]);
        return -1;
    }

    if (unlikely(size - *pos < ADNS_WIRE_QUESTION_MIN_SIZE)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_BAD_LENGTH]);
        log_query_info(rte_lcore_id(), "Not enough data to parse question\n");
        return -1;
    }

    len = adns_dname_wire_check(wire + packet->parsed, wire + size, lower_name);
    if (len <= 0) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_BAD_LENGTH]);
        log_query_info(rte_lcore_id(), "Malformed dns request packet\n");
        if (unlikely(packet->is_tcp)) {
            len = adns_dname_wire_check_tcp(wire + packet->parsed, wire + size, lower_name);
            if (len <= 0) {
                lower_name[0] = 0;
            }
        }
        return -1;
    }

    if (unlikely(size - len - *pos  < 4)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_BAD_LENGTH]);
        log_query_info(rte_lcore_id(), "Not enough data to parse question\n");
        return -1;
    }

    packet->qname = (uint8_t *)(wire + packet->parsed);
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
 * edns-client-subnet format
 * option-code                     uint16_t
 * option-length                   uint16_t
 * family                          uint16_t
 * souce netmask | scope netmask   uint8_t | uint8_t
 * address...                      variable
 */
static inline int
adns_parse_ecs(struct adns_packet *packet, uint16_t opt_len)
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
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_EDNS_FORMAT_FAILED]);
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
    if (unlikely(ecs->scope_mask)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_EDNS_FORMAT_FAILED]);
        return -1;
    }

    switch (family) {
        case 0:
            if (unlikely(src_mask != 0)) {
                adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_EDNS_FORMAT_FAILED]);
                return -1;
            }
            break;
        case ECS_FAMILY_IPV4:
            if (unlikely(src_mask > 32)) {
                adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_EDNS_FORMAT_FAILED]);
                return -1;
            }
            ecs->addr.v4 = 0;
            break;
        case ECS_FAMILY_IPV6:
            if (unlikely(src_mask > 128)) {
                adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_EDNS_FORMAT_FAILED]);
                return -1;
            }
            ecs->addr.v64[0] = 0;
            ecs->addr.v64[1] = 0;
            break;
        default:
            adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_EDNS_FORMAT_FAILED]);
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
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_EDNS_FORMAT_FAILED]);
        return -1;
    }
    opt_len -= addr_len;

    if (unlikely(opt_len > 0)) {
        packet->parsed += opt_len;
    }

    packet->has_ecs = 1;
    STATS_INC(ecs);

    return 0;
}

/*
 * cookie format
 * option-code                     uint16_t
 * option-length                   uint16_t, value 8 or [16, 40]
 * client cookie                   8 bytes
 * server cookie                   0 | [8, 32] bytes
 */
static inline int
adns_parse_cookie(struct adns_packet *packet, uint16_t opt_len)
{
    if (unlikely(opt_len != 8 && 
        (opt_len < 16 || opt_len > 40))) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_EDNS_FORMAT_FAILED]);
        return -1;
    }

    /* skip cookie option */
    packet->parsed += opt_len;

    if (packet->has_cookie == 0) {
        packet->has_cookie = 1;
        STATS_INC(cookie);
    }

    return 0;
}

static inline uint32_t ecs_parse_addr4(const uint8_t *addr4)
{
    return addr4[0] << 24 | addr4[1] << 16 | addr4[2] << 8 | addr4[3];
}

/* 
 * parse additional, only support edns now 
 */
static inline int
adns_parse_additional(struct adns_packet *packet)
{
    //packet->header.arcount should be 1 if it's edns.
    if (likely(packet->header.arcount == 0)) {
        return 0;
    }    

    if (packet->size - packet->parsed < EDNS_MIN_SIZE) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_BAD_LENGTH]);
        return -1;
    }


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
    uint8_t opt_owner = pkt_parse_read_u8(packet);
    uint16_t opt_type = pkt_parse_read_u16(packet);
    if (opt_owner != 0 || opt_type != EDNS_OPT) {
        return 0;
    }

    /* class - sender's UDP payload size */
    uint16_t opt_class = pkt_parse_read_u16(packet);
    if (opt_class < MAX_UDP_PAYLOAD) {
        packet->answer_max_size = MAX_UDP_PAYLOAD;
    } else if (opt_class > DNS_EDNS0_MAX_LENGTH) {
        packet->answer_max_size = DNS_EDNS0_MAX_LENGTH;
        if (packet->is_tcp) {
            packet->answer_max_size = TCP_DNS_MAX_LENGTH;
        }
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
        STATS_INC(edns_badvers);
        return 0; 
    }

    /* check DNSSEC OK */
    uint16_t *z_flag = (uint16_t *)(packet->wire + packet->parsed);
    if (((*z_flag) & EDNS_H_DO) != 0) {
        packet->dnssec = 1;
        packet->has_edns = 1;
        STATS_INC(dnssec);
    }
    packet->parsed += 2;

    /* rdlen -- describes rdata */
    uint16_t opt_rdlen = pkt_parse_read_u16(packet);
    if (likely(opt_rdlen == 0)) {
        packet->has_edns = 1;
        STATS_INC(edns);
        return 0;
    }

    if (unlikely(packet->size - packet->parsed < opt_rdlen)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_BAD_LENGTH]);
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
                ret = adns_parse_ecs(packet, opt_len);
                break;
            /* cookie */
            case EDNS_OPTION_COOKIE:
                ret = adns_parse_cookie(packet, opt_len);
                break;
            /* other option not support */
            default:
                /* skip the unsupport option */
                packet->parsed += opt_len;
                STATS_INC(edns_unknown_opt);
                break;
        }
        if (unlikely(ret < 0)) {
            return -1;
        }
    }

    packet->has_edns = 1;
    STATS_INC(edns);

    return 0;
}

/*
 * Parse dns requset from wire format, fill in the dns_packet struct.
 * return 0 on success, otherwise on failure
 */
static inline int
adns_parse(struct adns_packet *packet, const uint8_t *wire, 
		size_t size, uint8_t *lower_name)
{
    int ret = 0;

#if 0
    if (unlikely(packet == NULL || wire == NULL)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PARSE_DNS_WIRE_NULL_FAILED]);
        return -EINVAL;
    }
#endif

    packet->wire = (uint8_t *)wire;
    packet->size = size;

    /* malformed packet, should drop it */
    if (unlikely(size < 2)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_BAD_LENGTH]);
        return -EINVAL;
    }

    size_t pos = 0;
    /* Parse header to packet from wire format */
    ret = dns_parse_header(wire, &pos, size, &packet->header);
    if (unlikely(ret != 0)) {
        return ret;
    }

#if 0
    dump_dns_header(&packet->header);
#endif

    /* Only parse one question dns request */
    if (unlikely(packet->header.qdcount != 1 || packet->header.ancount > 0
                || packet->header.nscount > 0 || packet->header.arcount > 1)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_DNS_HEAD_COUNT_FAILED]);
        return -1;
    }

    /* Process opcode */
    if ((packet->header.flags1 & 0x78) != 0) {
        adns_counter_increase(g_adns_pkt_drop_counter[UNSUPPORT_OPCODE]);
        return -1;
    }

    packet->parsed = pos;
    /* Parse question */
    ret = adns_parse_question(wire, &pos, size, packet, lower_name);
    if (unlikely(ret != 0)) {
        return ret;
    }

    packet->answered = packet->parsed;
    packet->answer_section_offset = packet->parsed;
    /* parse additional */
    ret = adns_parse_additional(packet);
    if (unlikely(ret < 0)) {
        return ret;
    }

    return 0;
}

static inline size_t
adns_packet_parsed(const struct adns_packet *packet)
{
    return packet->parsed;
}

static inline size_t
adns_packet_size(const struct adns_packet *packet)
{
    return packet->size;
}


static inline adns_dname_t *
adns_packet_qname(struct adns_packet *packet)
{
    return packet->qname;
}

static inline uint16_t
adns_packet_qtype(struct adns_packet *packet)
{
    return packet->qtype;
}

static inline uint16_t
adns_packet_qclass(struct adns_packet *packet)
{
    return packet->qclass;
}

static inline int
query_is_response(struct adns_packet *query)
{
    return adns_wire_get_qr(query->wire);
}

static inline uint8_t
query_get_opcode(struct adns_packet *query)
{
    return adns_wire_get_opcode(query->wire);
}

static inline void
resp_init_header(struct dns_header *dnh)
{
    adns_wire_clear_ra((uint8_t *)dnh); /* don't support recursion */
    adns_wire_set_aa((uint8_t *)dnh);	/* authority server */
    adns_wire_clear_ad((uint8_t *)dnh); /* clear AD bit */
    adns_wire_set_qdcount((uint8_t *)dnh, 1);	/* only one question */
    adns_wire_set_qr((uint8_t *)dnh); /* set QR bit */
    adns_wire_clear_tc((uint8_t *)dnh); /* don't support truncation */
    adns_wire_clear_z((uint8_t *)dnh);  /* clear Z flag (See RFC1035, 4.1.1. Header section format)*/
}

static inline void
resp_set_header(struct dns_header *dnh, int an_cnt, int ns_cnt, int ar_cnt)
{
    adns_wire_add_ancount((uint8_t *)dnh, an_cnt); 
    adns_wire_set_nscount((uint8_t *)dnh, ns_cnt);	/* only one answer */
    adns_wire_set_arcount((uint8_t *)dnh, ar_cnt);	/* ignore additional question */
}

static inline int
answer_put_additional(struct adns_packet *packet)
{
    int ret;

    if (likely(packet->header.arcount == 0)){
        return 0;
    }

    if (!packet->has_edns){
        return 0;
    }

    ret = pkt_answer_length_enough(packet, 9); // 9 is check the length next 4 function. u8+u16+u16+u32 = 9
    if(ret != 0){
        log_server_warn(rte_lcore_id(), "%s: No enough for answer has_edns:%u, has_ecs:%u\n", __FUNCTION__, packet->has_edns, packet->has_ecs);
        return ret;
    }
    
    /* put edns0 */
    struct adns_opt_rr *opt_rr = &packet->opt_rr;
    pkt_answer_write_u8(packet, 0); /* name must be root domain */
    pkt_answer_write_u16(packet, EDNS_OPT);
    pkt_answer_write_u16(packet, packet->answer_max_size); /* requestor's UDP payload size */
    /* if edns version is not zero */
    if (unlikely(opt_rr->version != 0)) {
        /* set exrcode to BADVERS */
        pkt_answer_write_u8(packet, 1);
        pkt_answer_write_u8(packet, 0);
    }
    else {
        pkt_answer_write_u16(packet, 0); /* extended RCODE and version */
    }

    if (unlikely(packet->dnssec != 0)) {
        pkt_answer_write_u16(packet, EDNS_DO);
    }
    else {
        pkt_answer_write_u16(packet, 0);
    }

    /* for now, we don't respond cookie and only handle the first ecs, so the following code works, 
       if we respond cookie in future, should modify the code */
    if (packet->has_ecs) {
        /* opt_rdata_size(2 bytes) + ecs_header_size(8 bytes) + address_len */
        ret = pkt_answer_length_enough(packet, 10 + opt_rr->opt_ecs.addr_len); //10 is check for next 7 function. u16+u16+u16+u16+u8+u8+opt_rr->opt_ecs.addr_len
        if(ret != 0){
            log_server_warn(rte_lcore_id(), "%s: No enough for answer. has_ecs:%u\n", __FUNCTION__, packet->has_ecs);
            return ret;
        }
        
        /* since we only respond the first ecs, so the opt rdata size is the size of the first ecs
           including the ecs_header_size(8 bytes) + address_len */
        pkt_answer_write_u16(packet, 8 + opt_rr->opt_ecs.addr_len);

        pkt_answer_write_u16(packet, EDNS_OPTION_ECS);
        pkt_answer_write_u16(packet, 4 + opt_rr->opt_ecs.addr_len);
        pkt_answer_write_u16(packet, opt_rr->opt_ecs.family);
        /* mirror the source mask in response */
        pkt_answer_write_u8(packet, opt_rr->opt_ecs.src_mask);
        /* TODO: write the real scope mask of view lookup */
        /* for now we set scope mask as 0 for ipv6 ecs query, according to the google pubdns guides */
        if (likely(opt_rr->opt_ecs.family == ECS_FAMILY_IPV4)) {
            pkt_answer_write_u8(packet, 24);
        } else {
            pkt_answer_write_u8(packet, 0);
        }
        
        if (opt_rr->opt_ecs.addr_len) {
            pkt_answer_write(packet, opt_rr->opt_ecs.addr.v61, opt_rr->opt_ecs.addr_len);
        }
    } else {
        ret = pkt_answer_length_enough(packet, 2); // 2 is the length of u16.
        if(ret != 0){
            log_server_warn(rte_lcore_id(), "%s: No enough for answer. has_ecs:0\n", __FUNCTION__);
            return ret;
        }
        
        pkt_answer_write_u16(packet, 0);
    }
    uint16_t arcount = adns_wire_get_arcount(packet->wire);
    adns_wire_set_arcount(packet->wire, arcount + 1);

    return 0;
}

static inline int dns_post_process(struct rte_mbuf *m, struct udp_hdr *udh,
                int append_len)
{
    if (likely(append_len >= 0)) {
        if (unlikely(rte_pktmbuf_append(m, append_len) == NULL))
            return -1;
    }
    else {
        if (unlikely(rte_pktmbuf_trim(m, -append_len)))
            return -1;
    }


    /* updata udp header length field, clear cksum */
    udh->dgram_len = adns_htons(adns_ntohs(udh->dgram_len) + append_len);
    udh->dgram_cksum = 0;

    return 0;
}

static inline void 
make_wildcard_dname(adns_dname_t *src, uint8_t *dst)
{
    uint8_t src_size = adns_dname_size(src);
    uint8_t offset = *(uint8_t *)src + 1;

    dst[0] = 1;
    dst[1] = '*';

    memcpy(dst + 2, src + offset, src_size - offset);
}

static inline void 
make_upper_dname(adns_dname_t *src, uint8_t *dst)
{
    uint8_t src_size = adns_dname_size(src);
    uint8_t offset = *(uint8_t *)src + 1;

    memcpy(dst, src + offset, src_size - offset);
}


static inline int qname_check(adns_dname_t *qname)
{
    int size = adns_dname_size(qname);

    int i;
    for (i = 0; i < size; i++) {
        if (isupper(qname[i]))
            return -1;
    }

    return 0;
}



#define SOA_ANSWER 0
#define SOA_AUTHORITY 1

static inline int
next_owner_len(uint8_t *owner_wire, uint8_t owner_size, adns_nsec_bitmap_type bitmap_type)
{
    uint8_t left_most_label_len = *owner_wire;
    // if left most label or domain is full, increment the last octet of left most label
    if (left_most_label_len == ADNS_DNAME_LABEL_MAXLEN || owner_size >= ADNS_DNAME_MAXLEN - 1) {
        return owner_size;
    } else {
        // for delegation point, apend \000 to left most label
        if (bitmap_type == DELEGATION_POINT) {
            return owner_size + 1;
        } else { // add 0x0100 label
            return owner_size + 2;
        }
    }
}

static inline int
negative_resp_put_next_owner(uint8_t *pos,
                             uint8_t *owner_wire,
                             uint8_t owner_size,
                             adns_nsec_bitmap_type bitmap_type)
{
    uint8_t left_most_label_len = *owner_wire;
    uint8_t last_char;
    // If the length of the left mode lable is maximum or the domain length is maximum
    // synthesize the next owner by incrementing the last octet of the left most label of the qname
    if (left_most_label_len == ADNS_DNAME_LABEL_MAXLEN || owner_size >= ADNS_DNAME_MAXLEN - 1) {
        // cp the left most label len + the label itself except for the last octet
        rte_memcpy(pos, owner_wire, left_most_label_len);
        pos += left_most_label_len;
        // the last octet of the left most label
        last_char = *(owner_wire + left_most_label_len);
        *pos = last_char + 1;
        pos += 1;
        // copy the rest part of the domain
        rte_memcpy(pos, owner_wire + (left_most_label_len + 1), owner_size - (left_most_label_len + 1));

        return owner_size;
    } else {
        // in delegation point case, next owner of abc.com is abc\000.com
        if (bitmap_type == DELEGATION_POINT) {
            // increment label len
            *pos = left_most_label_len + 1;
            pos += 1;
            // copy the left most label
            rte_memcpy(pos, owner_wire + 1, left_most_label_len);
            pos += left_most_label_len;
            // append \000
            *pos = 0;
            pos += 1;
            // cpoy the rest domain
            rte_memcpy(pos, owner_wire + (left_most_label_len + 1), owner_size - (left_most_label_len + 1));

            return owner_size + 1;
        } else { // in non delegation point case, the next owner of abc.com is \000.abc.com
            /* next owner = 0x0100 + qname */
            *(uint16_t *)pos = adns_htons(NSEC_NEXT_OWNER_NULL_LABEL);
            pos += 2;
            // next owner must not be compressed
            rte_memcpy(pos, owner_wire, owner_size);

            return owner_size + 2;
        }
    }
}

static inline int
resp_put_non_exist_proof(struct adns_packet *query,
                        uint8_t *pos,
                        const struct adns_zone *zone,
                        uint8_t *owner_wire,
                        uint8_t owner_size,
                        adns_nsec_bitmap_type bitmap_type)
{
    adns_rr_index rr_index;
    int len = 0, next_owner_len;
    int ret;
    uint8_t *nsec_rdlen_pos;
    int offset;

    /* fill owner name in pointer */
    /* 2 possible cases:
     * 1: matching qname: NSEC's owner == qname, data error(noerror + SOA)
     * 2: matching delegation point: NSEC's owner == qname or partial qname
     *
     * in conclusion, owner is equal to or partial of the qname, so NSEC'owner
     * can be expressed by a name pointer(2 bytes)
     */
    // offset is certainlly >= 0
    offset = query->qname_size - owner_size;
    adns_wire_put_pointer(pos, ADNS_WIRE_HEADER_SIZE + offset);
    pos += sizeof(uint16_t);

    adns_nsec_bitmap *bm = get_nsec_bitmap(query->qtype, bitmap_type);

    /* fill type, class, ttl */
    rr_index.pos = pos;

    *(uint16_t *)pos = adns_htons(ADNS_RRTYPE_NSEC);
    pos += 2;
    *(uint16_t *)pos = adns_htons(ADNS_CLASS_IN);
    pos += 2;
    *(uint32_t *)pos = adns_htonl(zone->soa.ttl); // NSEC's TTL should be the minTTL field of SOA, for ADNS, it is SOA's TTL
    pos += 4;

    // record rdlen pos and skip it
    nsec_rdlen_pos = pos;
    pos += 2;

    // synthesize the next owner
    next_owner_len = negative_resp_put_next_owner(pos, owner_wire, owner_size, bitmap_type);
    pos += next_owner_len;
    // set nsec rdlen
    *(uint16_t *)nsec_rdlen_pos = adns_htons(next_owner_len + bm->len);

    /* fill bitmap */
    rte_memcpy(pos, bm->data, bm->len);
    pos += bm->len;
    rr_index.len = ADNS_RR_HEADER_SIZE + next_owner_len + bm->len;

    /* sign the non-existence proof */
    ret = adns_dnssec_sign_rrset(query,
                    pos,
                    &rr_index,
                    1,
                    zone,
                    owner_wire, // NSEC's owner could be qname or delegation point name
                    owner_size,
                    ADNS_RRTYPE_NSEC,
                    0,          // only default view
                    zone->soa.ttl,
                    NULL);             // so as the qname_cursor, it is set NULL
    if (ret < 0) { //if sign NSEC failure, will not return neither NSEC nor NSEC rrsig
        return -1;
    }
    pos += ret;
    // add NSEC rr length
    len += sizeof(uint16_t) + rr_index.len;
    // add NSEC RRSIG length
    len += ret;

    return len;
}

static inline int 
resp_put_soa(struct dns_header *dnh, const struct adns_zone *zone,
        struct adns_packet *query, int type, adns_nsec_bitmap_type bitmap_type)
{
    int name_size = adns_dname_size(zone->name);
    uint8_t *pos = query->wire + query->answered;
    #if PVT_ZONE_PREFIX
    int offset = query->qname_size - name_size - query->qname_size_postfix + 1;
    #else
    int offset = query->qname_size - name_size;
    #endif
    int len = ADNS_RR_HEADER_SIZE + zone->soa.len;
    adns_rr_index rr_index;
    int rr_cnt = 0;
    int ret = 0;

    int dnssec_content_len = 0;
    // if query with dnssec and dnssec is ready should consider dnssec content length when check max response len
    if (DNSSEC_READY(query, zone)) {
        // negative response, count NSEC + NSEC's rrsig len
        if (unlikely(type == SOA_AUTHORITY)) {
            adns_nsec_bitmap *bm = get_nsec_bitmap(query->qtype, bitmap_type);
            // NSEC len: qname pointer(2 bytes) + ADNS_RR_HEADER_SIZE(type + class + ttl + rdlen (10 bytes)) + next owner len + bitmap len
            dnssec_content_len += 2 + ADNS_RR_HEADER_SIZE + next_owner_len(query->qname, query->qname_size, bitmap_type) + bm->len; 
        }
        // count rrsig len: qname pointer(2 bytes) + ADNS_RR_HEADER_SIZE(type + class + ttl + rdlen (10 bytes)) + rrsig rdata len
        dnssec_content_len += RRSIG_RR_LEN(zone);
        // since DO bit must be set in DNSSEC response, count also edns size in dnssec_content_len
        dnssec_content_len += packet_edns_size(query);

        // set TC bit in DNSSEC response
        if (query->answered + 2 + len + dnssec_content_len > query->answer_max_size) {
            // if query via UDP, set TC bit
            if (!query->is_tcp) {
                adns_wire_set_tc((uint8_t *)dnh);
            }
            resp_set_header(dnh, 0, 0, 0);
            return 0;
        }
    }

    /* fill query domain name */
    if ((offset >= 0) && 
        #if PVT_ZONE_PREFIX
            (!memcmp(query->qname + offset, zone->name, name_size-1))) {
        #else
            (!memcmp(query->qname + offset, zone->name, name_size))) {
        #endif
        if(sizeof(uint16_t) + query->answered + len + dnssec_content_len > query->answer_max_size){
            resp_set_header(dnh, 0, 0, 0);
            return 0;
        }
        adns_wire_put_pointer(pos, ADNS_WIRE_HEADER_SIZE + offset);
        pos += sizeof(uint16_t);
        len += sizeof(uint16_t);
    }
    else {
        if(name_size + query->answered + len + dnssec_content_len > query->answer_max_size){
            resp_set_header(dnh, 0, 0, 0);
            return 0;
        }
        rte_memcpy(pos, zone->name, name_size);
        pos += name_size;
        len += name_size;
        #if PVT_ZONE_PREFIX
        rte_memcpy(pos - 1, query->qname_postfix,
                query->qname_size_postfix);
        pos += query->qname_size_postfix - 1;
        len += query->qname_size_postfix - 1;
        #endif
    }

    /* fill type, class, ttl */
    rr_index.pos = pos;
    rr_index.len = ADNS_RR_HEADER_SIZE + zone->soa.len;

    *(uint16_t *)pos = adns_htons(zone->soa.type);
    pos += 2;
    *(uint16_t *)pos = adns_htons(zone->soa.rclass);
    pos += 2;
    *(uint32_t *)pos = adns_htonl(zone->soa.ttl);
    pos += 4;
    /* rdata length */
    *(uint16_t *)pos = adns_htons(zone->soa.len);
    pos += 2;
    /* rdata */
    rte_memcpy(pos, zone->soa.data, zone->soa.len);
    pos += zone->soa.len;
    rr_cnt ++;

    
    /* if query with dnssec and zone is dnssec enabled and dnssec is OK*/
    if (DNSSEC_READY(query, zone)) {
        ret = adns_dnssec_sign_rrset(query,
                            pos,
                            &rr_index,
                            rr_cnt,
                            zone,
                            zone->name,   // owner of SOA's rrsig is zone name
                            zone->name_len,
                            zone->soa.type,
                            0,            // only default view for SOA query
                            zone->soa.ttl,
                            NULL);         // so as the qname_cursor, it is set NULL 
        if (ret < 0) { //if sign SOA error, just return SOA
            goto put_soa_done;
        }
        len += ret;
        pos += ret;
        rr_cnt ++;

        /* non-existence proof, black lie proves that no data error, so owner of NSEC is query name */
        if (type == SOA_AUTHORITY) {
            ret = resp_put_non_exist_proof(query, pos, zone, query->lower_qname, query->qname_size, bitmap_type);
            if (ret < 0) {
                goto put_soa_done;
            }
            len += ret;
            pos += ret;
            // NSEC, NSEC RRSIG count together
            rr_cnt += 2;
        }
    }

put_soa_done:
    if (type == SOA_ANSWER)
        resp_set_header(dnh, rr_cnt, 0, 0);
    else
        resp_set_header(dnh, 0, rr_cnt, 0);
    return len;
}

static inline int 
resp_put_answer_soa(struct dns_header *dnh, struct adns_zone *zone,
        struct adns_packet *query)
{
    return resp_put_soa(dnh, zone, query, SOA_ANSWER, ZONE_APEX);
}


static inline int 
resp_put_authority_soa(struct dns_header *dnh, struct adns_zone *zone,
        struct adns_packet *query, adns_nsec_bitmap_type bitmap_type)
{
    return resp_put_soa(dnh, zone, query, SOA_AUTHORITY, bitmap_type);
}

static inline int 
resp_put_dnskey(struct dns_header *dnh, const struct adns_zone *zone,
        struct adns_packet *query)
{
    uint8_t *pos = query->wire + query->answered;
    int len = 0, ans_len = 0;
    adns_dnssec_key *key;
    int rr_cnt = 0;
    adns_rr_index rr_index[MAX_DNSKEY_NUM];
    adns_rr_index *p_index = rr_index;
    adns_dnskey_rdata *dnskey_rdata;
    adns_zsk_ctr_t *zsk_ctr;

    // get zone's adns_zsk_ctr
    zsk_ctr = zone->adns_zsk_ctr;
    if (zsk_ctr == NULL) {
        goto put_dnskey_done;
    }
    // dnskey list
    adns_key_array_t dnskey_list;
    memset(&dnskey_list, 0, sizeof(adns_key_array_t));
    // push global ksk
    KEY_ARRAY_PUSH(dnskey_list, *g_dnssec_ksk);
    // push active zsk
    KEY_ARRAY_PUSH(dnskey_list, adns_get_zsk_by_key_tag(zsk_ctr->active_zsk));
    // push alt zsk
    if (zsk_ctr->size > 1) {
        KEY_ARRAY_PUSH(dnskey_list, adns_get_zsk_by_key_tag(zsk_ctr->alt_zsk));
    }
    // if query with dnssec, must not return partial answer, since must set DO bit, should
    // consider edns size in advance
    if (likely(query->dnssec == 1 && zone->enable_dnssec == 1)) {
        // dnskey size
        ans_len += DNS_DNSKEY_RR_LEN * KEY_ARRAY_SIZE(dnskey_list);
        // rrsig size
        ans_len += RRSIG_RR_LEN(zone);
        // edns size
        ans_len += packet_edns_size(query);
        if (query->answered + ans_len > query->answer_max_size) {
            // if query via UDP, set TC bit
            if (!query->is_tcp) {
                adns_wire_set_tc((uint8_t *)dnh);
            }
            goto put_dnskey_done;
        }
    }

    KEY_ARRAY_FOR_EACH(dnskey_list, key) {
        if (key != NULL) {
            // if query with no dnssec, try our best to return DNSKEY
            if (query->answered + DNS_DNSKEY_RR_LEN > query->answer_max_size) {
                goto put_dnskey_done;
            }

            /* fill query domain name */
            adns_wire_put_pointer(pos, ADNS_WIRE_HEADER_SIZE);
            pos += sizeof(uint16_t);
            len += sizeof(uint16_t);

            /* record DNSKEY rdata start point and rdata length */
            p_index->pos = pos;
            p_index->len = ADNS_RR_HEADER_SIZE + sizeof(adns_dnskey_rdata) + key->pubkey_data_len;
            p_index ++;

            /* fill type, class, ttl */
            *(uint16_t *)pos = adns_htons(ADNS_RRTYPE_DNSKEY);
            pos += 2;
            *(uint16_t *)pos = adns_htons(zone->soa.rclass);
            pos += 2;
            *(uint32_t *)pos = adns_htonl(DNS_DNSKEY_TTL);
            pos += 4;
            /* rdata length */
            *(uint16_t *)pos = adns_htons(sizeof(adns_dnskey_rdata) + key->pubkey_data_len);
            pos += 2;

            /* rdata */
            dnskey_rdata = (adns_dnskey_rdata *)pos;
            /* set dnskey flags */
            if (key->is_ksk) {
                dnskey_rdata->flags = adns_htons(DNS_KEY_SIGNING_KEY_FLAGS);
            } else {
                dnskey_rdata->flags = adns_htons(DNS_ZONE_SIGNING_KEY_FLAGS);
            }
            /* set dnskey protocol */
            dnskey_rdata->protocol = DNS_DNSKEY_PROTOCOL;
            /* set dnskey algorithm */
            dnskey_rdata->algorithm = ECDSA_P256_ALGO;
            /* set dnskey pub key */
            rte_memcpy(dnskey_rdata->pubkey, key->pubkey_data, key->pubkey_data_len);
            pos += sizeof(adns_dnskey_rdata) + key->pubkey_data_len;

            len += ADNS_RR_HEADER_SIZE + sizeof(adns_dnskey_rdata) + key->pubkey_data_len;
            rr_cnt ++;
        }
    }

    /* it is likely query DNSKEY with dnssec */
    if (likely(query->dnssec == 1 && zone->enable_dnssec == 1)) {
        // get dnskey rrsig
        struct adns_rdata *dnskey_rrsig = zsk_ctr->dnskey_rrsig;

        /* fill query domain name */
        adns_wire_put_pointer(pos, ADNS_WIRE_HEADER_SIZE);
        pos += sizeof(uint16_t);
        len += sizeof(uint16_t);

        /* fill type, class, ttl */
        *(uint16_t *)pos = adns_htons(ADNS_RRTYPE_RRSIG);
        pos += 2;
        *(uint16_t *)pos = adns_htons(ADNS_CLASS_IN);
        pos += 2;
        *(uint32_t *)pos = adns_htonl(DNS_DNSKEY_TTL);
        pos += 4;
        /* rdata length */
        *(uint16_t *)pos = adns_htons(dnskey_rrsig->len);
        pos += 2;
        rte_memcpy(pos, dnskey_rrsig->data, dnskey_rrsig->len);
        rr_cnt ++;
        len += dnskey_rrsig->len + ADNS_RR_HEADER_SIZE;
    }

put_dnskey_done:
    resp_set_header(dnh, rr_cnt, 0, 0);

    return len;
}

static inline int
resp_fill_rdata_ctl(struct adns_packet *query, const struct adns_node *node, struct adns_rrset *rrset,
            struct adns_rdata *rdata, const adns_dname_t *query_name_cursor, adns_rr_index **p_index)
{
    if (p_index == NULL) {
        return -1;
    }
    adns_rr_index *index = *p_index;

    uint8_t *packet_pointer = query->wire + query->answered;
    int len = ADNS_RR_HEADER_SIZE + rdata->len;

    int dnssec_content_len = 0;
    int node_name_size = node->name_len;
    int ptr_offset, query_name_pos;
    if(query_name_cursor == NULL) {
        /* fill rr for domain in query segement */
        #if PVT_ZONE_PREFIX
        ptr_offset = query->qname_size_prefix - node_name_size;
        #else
        ptr_offset = query->qname_size - node_name_size;
        #endif
        query_name_pos = ADNS_WIRE_HEADER_SIZE;
    } else {
        /* fill rr for domain in answer segement (additional seg filling) */
        int query_name_size = adns_dname_size(query_name_cursor);
        query_name_cursor = adns_wire_seek_label(query_name_cursor, query->wire);
        ptr_offset = node_name_size - query_name_size;
        query_name_pos = query_name_cursor - query->wire; //relative to dns frame head
    }

    // if query with dnssec and dnssec is ready should consider dnssec content length when check max response len
    if (DNSSEC_READY(query, node->zone)) {
        // unsigned delegtion(ADNS not support DS for instant), count NSEC + NSEC's rrsig len
        if (UNSIGNED_DELEGATION(rrset->type, node->name_len == node->zone->name_len)) {
            adns_nsec_bitmap *bm = get_nsec_bitmap(ADNS_RRTYPE_NS, DELEGATION_POINT);
            // NSEC len: qname pointer(2 bytes) + ADNS_RR_HEADER_SIZE(type + class + ttl + rdlen (10 bytes)) + next owner len + bitmap len
            dnssec_content_len += 2 + ADNS_RR_HEADER_SIZE + next_owner_len(node->name, node->name_len, DELEGATION_POINT) + bm->len;
        }
        // count rrsig len: qname pointer(2 bytes) + ADNS_RR_HEADER_SIZE(type + class + ttl + rdlen (10 bytes)) + rrsig rdata len
        dnssec_content_len += RRSIG_RR_LEN(node->zone);
        // edns space check is done later, so no need to check here
    }

    if (unlikely(query->is_tcp)) {
        uint16_t max_len = sizeof(uint16_t) + query->answered + len + dnssec_content_len;
        if (query->has_edns==1) {
            max_len += 11 + query->has_ecs?0:(8+query->opt_rr.opt_ecs.addr_len);  
        }
        if (max_len > TCP_DNS_MAX_LENGTH) {
            return -1;
        }
    } else if((query->has_edns != 1)
            && (sizeof(uint16_t) + query->answered + len + dnssec_content_len > UDP_DNS_MAX_LENGTH)
            && (rrset->type != ADNS_RRTYPE_TXT)){
        return -1;
    } else if((query->has_edns != 1)
           && ((rrset->type == ADNS_RRTYPE_TXT)
           && (sizeof(uint16_t) + query->answered + len + dnssec_content_len > UDP_DNS_TXT_MAX_LENGTH))
      ){
            log_server_warn(rte_lcore_id(), "%s: TXT answer must less than %d\n", __FUNCTION__, UDP_DNS_TXT_MAX_LENGTH);
            return -1;
    } else if(query->has_edns == 1) {
        /* has no ecs */
        if (!query->has_ecs) {
            /* if it's edns0 query, must left room for additional records, 11 bytes for edns0 */
            if (sizeof(uint16_t) + query->answered + len + dnssec_content_len + 11 > query->answer_max_size) {
                return -1;
            }
        } else {
            /* ecs_head_size(8 bytes) + address_len */
            if (sizeof(uint16_t) + query->answered + len + dnssec_content_len + 11 + 8 + query->opt_rr.opt_ecs.addr_len > query->answer_max_size) {
                return -1;
            }
        }
    }

    /* fill query domain name */
    if (likely(node->parent == NULL )) {
        /*not wild domain*/
        if (ptr_offset >= 0) {
            adns_wire_put_pointer(packet_pointer, query_name_pos + ptr_offset);
            packet_pointer += sizeof(uint16_t);
            len += sizeof(uint16_t);
        } else {
            return -2;
        }
    } else {
        /*wild domain*/
        adns_wire_put_pointer(packet_pointer, query_name_pos);
        packet_pointer += sizeof(uint16_t);
        len += sizeof(uint16_t); 
    }
    /* record rdata start point and rdata length */
    index->pos = packet_pointer;
    index->len = ADNS_RR_HEADER_SIZE + rdata->len;
    // type
    *(uint16_t *)packet_pointer = adns_htons(rrset->type);
    packet_pointer += 2;
    // class
    *(uint16_t *)packet_pointer = adns_htons(rrset->rclass);
    packet_pointer += 2;
    // TTL
    *(uint32_t *)packet_pointer = adns_htonl(rrset->ttl);
    packet_pointer += 4;
    // rdata length
    *(uint16_t *)packet_pointer = adns_htons(rdata->len);
    packet_pointer += 2;
    // rdata
    rte_memcpy(packet_pointer, rdata->data, rdata->len);
    packet_pointer += rdata->len;
    // update answer len
    query->answered += len;
    return 0;
}

static inline int
resp_put_normal(struct adns_packet *query, const struct adns_node *node, 
        adns_type_t type, struct adns_rrset *rrset, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl,
        int *an_nums,
        int ignore_weight, const adns_dname_t *query_name_cursor)
{
    int i;
    uint8_t start;
    struct adns_rdata *iter;
    int ret;


    if (likely(rdata_ctl->rdata_count <= RCORD_RANDOM_NUM)) {
        start = 0; 
    } else {
        srand((int)time(0));
        start = rand()%rdata_ctl->rdata_count;
    }
    struct list_head *h_list = &(rdata_ctl->list);

    adns_rr_index index_list[rdata_ctl->rdata_count];
    adns_rr_index *p_index = index_list;
    i = 0;

    list_for_each_entry(iter, h_list, list) {
        if ((i++ >= start) && (ignore_weight || iter->cw)) {
            if (resp_fill_rdata_ctl(query, node, rrset, iter, query_name_cursor, &p_index) < 0) {
                break; 
            }
            ++(*an_nums);
            p_index ++;
        }
    }

    i = 0;
    list_for_each_entry(iter, h_list, list) {
        if ((i++ < start) && (ignore_weight || iter->cw)) {
            if (resp_fill_rdata_ctl(query, node, rrset, iter, query_name_cursor, &p_index) < 0) {
                break; 
            }
            ++(*an_nums);
            p_index ++;
        }
    }

    /* if query with dnssec and zone is dnssec enabled, sign the rrset */
    if (DNSSEC_READY(query, node->zone)) {
        // ex. qname=a.b.c.test, zone=test
        // node could be:
        //   a.b.c.test: normal node
        //   *.b.c.test: wildcard matching
        //   *.c.test:   wildcard fallback matching 
        // should pass real answer rr number
        uint8_t *rrset_owner;
        uint8_t rrset_owner_len;
        // if node is wildcard node
        if (adns_dname_is_wildcard(node->name)) {
            rrset_owner = query->lower_qname;
            rrset_owner_len = query->qname_size;
        } else {
            rrset_owner = node->name;
            rrset_owner_len = node->name_len;
        }
        // unsigned delegation delegation
        if (UNSIGNED_DELEGATION(type, node->name_len == node->zone->name_len)) {
            ret = resp_put_non_exist_proof(query, query->wire + query->answered, node->zone, rrset_owner, rrset_owner_len, DELEGATION_POINT);
            if (ret < 0) {
                return 0;
            }
            (*an_nums) += 2;
        } else {
            // if sign rrset failure, query->answered and an_nums stay unchanged, perform no DNSSEC sign
            ret = adns_dnssec_sign_rrset(query,
                                NULL,
                                index_list,
                                *an_nums,
                                node->zone,
                                rrset_owner,
                                rrset_owner_len,
                                rrset->type,
                                view_id,
                                rrset->ttl,
                                query_name_cursor);
            if ( ret < 0) {
                return 0;
            }
            ++(*an_nums);
        }
        query->answered += ret;
    }

    return 0;
}

/* Allow schedule algorithm applied
    A: all-rr or ratio
    AAAA: all-rr or ratio
    CNAME: only ratio
*/
static inline int
resp_put_aname(struct adns_packet *packet, 
        const struct adns_node *node, adns_type_t type, adns_viewid_t view_id,
        int *an_nums, const adns_dname_t *query_name_cursor)
{
    uint8_t schd_mode = SCHEDULE_MODE_RATIO;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;

    rrset = adns_node_get_rrset(node, type);
    if (unlikely(rrset == NULL)) {
        return -1; 
    }

    if (unlikely(view_id >= g_view_max_num)) {
        rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)(view_id - g_view_max_num));
    }
    else {
        rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
    }
    
    if (unlikely(rdata_ctl == NULL || rdata_ctl->rdata_count == 0)) {
        return -1; 
    }

    if (type == ADNS_RRTYPE_CNAME) {
        if (rdata_ctl->tw == 0) {
            return resp_put_normal(packet, node, type, rrset, view_id, rdata_ctl, an_nums, 1, query_name_cursor);
        } else {
            return resp_put_ans_ratio(packet, node, type, rrset, view_id, rdata_ctl, an_nums, query_name_cursor);
        }
    } else if (type == ADNS_RRTYPE_AAAA) {
        schd_mode = node->AAAA_schedule_mode;
    } else {
        schd_mode = node->A_schedule_mode;
    }

    if (rdata_ctl->schedule_mode != SCHEDULE_MODE_UNKNOWN) {
        schd_mode = rdata_ctl->schedule_mode;
    }

    if (schd_mode == SCHEDULE_MODE_ALLRR || rdata_ctl->tw == 0) {
        return resp_put_aname_all_rr(packet, node, type, rrset, view_id, rdata_ctl, an_nums, query_name_cursor);
    } else {
        return resp_put_ans_ratio(packet, node, type, rrset, view_id, rdata_ctl, an_nums, query_name_cursor);
    }
}


static inline int
resp_put_aname_all_rr(struct adns_packet *packet, 
        const struct adns_node *node, adns_type_t type, struct adns_rrset *rrset, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl,
        int *an_nums, const adns_dname_t *query_name_cursor)
{
    if (unlikely(resp_put_normal(packet, node, type, rrset, view_id, rdata_ctl, an_nums, 0, query_name_cursor) < 0)) {
        return -1; 
    }
    if (likely(*an_nums)) {
        return 0; 
    }

    return resp_put_normal(packet, node, type, rrset, view_id, rdata_ctl, an_nums, 1, query_name_cursor);
}


static inline int
resp_put_ans_ratio(struct adns_packet *query, const struct adns_node *node, 
        adns_type_t type, struct adns_rrset *rrset, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl,
        int *an_nums, const adns_dname_t *query_name_cursor)
{
    struct adns_rdata * rdata;
    int ret;
    uint64_t random_cnt = rte_rdtsc();
    random_cnt >>= 1;
    int sign_ret;

    random_cnt %= rdata_ctl->tw;
    struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        if (random_cnt < rdata->cw) {
            /* fill this rdata to answer */
            adns_rr_index index;
            adns_rr_index *p_index = &index;
            ret = resp_fill_rdata_ctl(query, node, rrset, rdata, query_name_cursor, &p_index);
            if (likely(ret == 0)) {
                /* updata current weight */
                *an_nums = 1;
                /* if query with dnssec and zone is dnssec enabled, sign the rrset */
                if (DNSSEC_READY(query, node->zone)) {
                    uint8_t *rrset_owner;
                    uint8_t rrset_owner_len;
                    if (adns_dname_is_wildcard(node->name)) {
                        rrset_owner = query->lower_qname;
                        rrset_owner_len = query->qname_size;
                    } else {
                        rrset_owner = node->name;
                        rrset_owner_len = node->name_len;
                    }
                    // if sign rrset failure, query->answered and an_nums stay unchanged, perform no DNSSEC sign
                    sign_ret = adns_dnssec_sign_rrset(query,
                                        NULL,
                                        &index,
                                        1,
                                        node->zone,
                                        rrset_owner,
                                        rrset_owner_len,
                                        rrset->type,
                                        view_id,
                                        rrset->ttl,
                                        query_name_cursor);
                    if ( sign_ret > 0) {
                        // sign rrset succeed, increment dnssec_ans count
                        query->answered += sign_ret;
                        *an_nums = 2;
                    }
                }
            }
            return ret;
        }
        random_cnt -= rdata->cw;
    }

    return -1;
}

/*
 * Put specified rdata_ctl into answer section. merge with normal rdata_ctl API
 * No schedule algorithm applied
 */
static inline int
resp_put_not_aname(struct adns_packet *packet, 
        const struct adns_node *node, adns_type_t type, adns_viewid_t view_id,
        int *an_nums, const adns_dname_t *query_name_cursor)
{
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;

    rrset = adns_node_get_rrset(node, type);
    if (unlikely(rrset == NULL)) {
        return -1; 
    }

    if (unlikely(view_id >= g_view_max_num)) {
        rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)(view_id - g_view_max_num));
    }
    else {
        rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
    }
    
    if (unlikely(rdata_ctl == NULL || rdata_ctl->rdata_count == 0)) {
        return -1; 
    }

    return resp_put_normal(packet, node, type, rrset, view_id, rdata_ctl, an_nums, 1, query_name_cursor);
}


/*
 * Put specified rdata_ctl into answer section. merge with normal rdata_ctl API
 */
static inline int
ns_answer_domain_rrset(struct dns_header *dnh, 
        struct adns_packet *query, const struct adns_node *node,
        adns_type_t type, adns_viewid_t view_id, int *an_num)
{
    int ret;

    switch (type) {
    /* process query type A|AAAA|CNAME */
    case ADNS_RRTYPE_A:
    case ADNS_RRTYPE_AAAA:
    case ADNS_RRTYPE_CNAME:
        /* Schedule algorithm could be applied */
        ret = resp_put_aname(query, node, type, view_id, an_num, NULL);
        break;
    default:
        /* Schedule algorithm not allow to be applied */
        ret = resp_put_not_aname(query, node, type, view_id, an_num, NULL);
        break;
    }

    if(ret != 0){
        return ret;
    }
    resp_set_header(dnh, *an_num, 0, 0);

    return 0;
}


/*
 * Put ns rdata_ctl into answer section. merge with normal rdata_ctl API
 */
static inline int
ns_answer_domain_rrset_ns(struct dns_header *dnh, 
        struct adns_packet *query, const struct adns_node *node, adns_viewid_t view_id, int *ns_num)
{
    int ret;

    ret = resp_put_not_aname(query, node, ADNS_RRTYPE_NS, view_id, ns_num, NULL);
    if(unlikely(ret != 0)){
        return ret;
    }
    resp_set_header(dnh, 0, *ns_num, 0);
    adns_wire_clear_aa((uint8_t *)dnh);	/* authority server */

    return 0;
}

static inline int
ns_answer_type_any(struct dns_header *dnh, struct adns_packet *packet, struct adns_zone *zone)
{
    uint8_t *packet_pointer = packet->wire + packet->answered;
    const char *hinfo = "RFC8482";
    uint16_t rdlen = strlen(hinfo);
    // X07RFC8482\0
    int len = ADNS_RR_HEADER_SIZE + rdlen + 2;
    int ret;
    adns_rr_index rr_index;
    int dnssec_content_len = 0;
    int rr_cnt = 0;

    // Truncate check
    if (DNSSEC_READY(packet, zone)) {
        // count rrsig len: qname pointer(2 bytes) + ADNS_RR_HEADER_SIZE(type + class + ttl + rdlen (10 bytes)) + rrsig rdata len
        dnssec_content_len += RRSIG_RR_LEN(zone);
        // since DO bit must be set in DNSSEC response, count also edns size in dnssec_content_len
        dnssec_content_len += packet_edns_size(packet);

        // set TC bit in DNSSEC response
        if (packet->answered + 2 + len + dnssec_content_len > packet->answer_max_size) {
            // if query via UDP, set TC bit
            if (!packet->is_tcp) {
                adns_wire_set_tc((uint8_t *)dnh);
            }
            resp_set_header(dnh, 0, 0, 0);
            return 0;
        }
    }

    // name (qname pointer)
    adns_wire_put_pointer(packet_pointer, ADNS_WIRE_HEADER_SIZE);
    len += 2;
    packet_pointer += 2;

    // set rr_index
    rr_index.pos = packet_pointer;
    rr_index.len = len;

    // type (HINFO)
    *(uint16_t *)packet_pointer = adns_htons(ADNS_RRTYPE_HINFO);
    packet_pointer += 2;
    // class (IN)
    *(uint16_t *)packet_pointer = adns_htons(ADNS_CLASS_IN);
    packet_pointer += 2;
    // TTL
    *(uint32_t *)packet_pointer = adns_htonl(3600);
    packet_pointer += 4;
    // rdata len
    // HINFO rdata contains 2 <caracter string>, the second one is an empty string
    *(uint16_t *)packet_pointer = adns_htons(rdlen + 2);
    packet_pointer += 2; 
    // rdata
    *packet_pointer ++ = rdlen;
    rte_memcpy(packet_pointer, hinfo, rdlen);
    packet_pointer += rdlen;
    *packet_pointer ++ = '\0';
    rr_cnt += 1;

    if (DNSSEC_READY(packet, zone)) {
        ret = adns_dnssec_sign_rrset(packet,
                            packet_pointer,
                            &rr_index,
                            1,
                            zone,
                            packet->qname,      // owner is qname
                            packet->qname_size, // qname len
                            ADNS_RRTYPE_HINFO,
                            0,                  // HINFO record not exist actually, viewid not useful
                            3600,
                            NULL); // so as the qname_cursor, it is set NULL
        if (ret > 0) {
            rr_cnt += 1;
            len += ret;
        }
    }

    resp_set_header(dnh, rr_cnt, 0, 0);

    return len;
}

static bool adns_node_check_if_ns_exists(const struct adns_node *node, adns_viewid_t view_id) {
    struct adns_rrset *rrset = adns_node_get_rrset(node, ADNS_RRTYPE_NS);
    struct adns_rdata_ctl *rdata_ctl = NULL;

    if (unlikely(rrset == NULL)) {
        return false; 
    }

    if (view_id >= g_view_max_num) {
        rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)(view_id - g_view_max_num));
    }
    else {
        rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
    }
    if (unlikely(rdata_ctl == NULL || rdata_ctl->rdata_count == 0)) {
        return false; 
    }

    return true;
}

static inline bool zone_has_wild_domain(const struct adns_zone *zone, adns_viewid_t view_id) {

    return ( zone->wild_tag[view_id >> ADNS_8_LOG2] & (1 << (view_id & ADNS_8_MAC)) );
}

static inline int adns_zone_lookup_multi_nodes(struct adns_packet *query, 
        const struct adns_zone *zone, const uint8_t **p_dname_ptr_array, int ns_num, VIEW_ARRAY_T * view_array)
{
    int ar_num = 0;
    int i = 0;
    adns_viewid_t view_id;

    for (i = 0; i < ns_num; i++) {
        struct adns_node *node = NULL, *parent_node = NULL, *wild_node = NULL;
        const adns_dname_t *dname = *(p_dname_ptr_array + i);

        node = adns_zone_lookup_node(zone, dname);
        if (node != NULL) {
            VIEW_ARRAY_FOR_EACH(*view_array, view_id) {
                if (GET_TAG(node->node_tag, view_id)) {
                    if(adns_node_check_if_ns_exists(node, view_id) == false) {
                        int ar_num_a = 0, ar_num_aaaa = 0;
                        int ret1, ret2;
                        ret1 = resp_put_not_aname(query, node, ADNS_RRTYPE_A, view_id, &ar_num_a, dname);
                        ret2 = resp_put_not_aname(query, node, ADNS_RRTYPE_AAAA, view_id, &ar_num_aaaa, dname);
                        ar_num += ar_num_a + ar_num_aaaa;
                        if( (ret1 == 0 || ret2 == 0) && (ar_num_a + ar_num_aaaa > 0) ) {
                            break;
                        }
                    }
                }
            }
        }

        parent_node = adns_zone_lookup_node_lsm(zone, dname, zone->domain_max_label);
        if (unlikely( (parent_node != NULL))) {
            VIEW_ARRAY_FOR_EACH(*view_array, view_id) {
                 if (GET_TAG(parent_node->node_tag, view_id) ) {
                    if (adns_node_check_if_ns_exists(parent_node, view_id) == false) {
                        if (unlikely(zone_has_wild_domain(zone, view_id) == true)) {
                            wild_node = parent_node->wildcard_child;
                            if (likely((wild_node != NULL) && GET_TAG(wild_node->node_tag, view_id))) {
                                if( adns_node_check_if_ns_exists(wild_node, view_id) == false ) {
                                    int ar_num_a = 0, ar_num_aaaa = 0;
                                    int ret1, ret2;
                                    ret1 = resp_put_not_aname(query, wild_node, ADNS_RRTYPE_A, view_id, &ar_num_a, dname);
                                    ret2 = resp_put_not_aname(query, wild_node, ADNS_RRTYPE_AAAA, view_id, &ar_num_aaaa, dname);
                                    ar_num += ar_num_a + ar_num_aaaa;
                                    if( (ret1 == 0 || ret2 == 0) && (ar_num_a + ar_num_aaaa > 0) ) {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return ar_num;
}

static inline int answer_put_additional_ns(struct dns_header *dnh,
    struct adns_packet *query, const struct adns_zone *zone, int ns_num, VIEW_ARRAY_T * view_array)
{
    int i = 0;
    int ar_num = 0;
    uint8_t *ns_entry_start_pos = NULL;
    const adns_dname_t * dname_ptr_array[DNS_EDNS0_MAX_LENGTH/ADNS_RR_HEADER_SIZE] = {0};

    /* 1, extract NS domain names from the packet */
    ns_entry_start_pos = query->wire + query->answer_section_offset;
    while(i < ns_num){
        int ns_entry_dname_size = adns_dname_size(ns_entry_start_pos);
        int ns_entry_rdata_size = adns_wire_read_u16(ns_entry_start_pos + ns_entry_dname_size + 8);
        int ns_entry_other_size = ADNS_RR_HEADER_SIZE;
        //support name compression in ns_rdata
        dname_ptr_array[i] = adns_wire_seek_label(
                ns_entry_start_pos + ns_entry_dname_size + ns_entry_other_size, query->wire);
        ns_entry_start_pos += ns_entry_dname_size + ns_entry_other_size + ns_entry_rdata_size;
        i++;
    }

    /* 2, lookup each NS's A/AAAA record and fill up packet*/
    // aa bit is cleared in delegation process, set query's aa flag
    // non authoritative data will not be signed(delegation and delagation glues)
    query->is_aa = adns_wire_get_aa((uint8_t *)dnh);
    ar_num = adns_zone_lookup_multi_nodes(query, zone, dname_ptr_array, ns_num, view_array);
    resp_set_header(dnh, 0, ns_num, ar_num);
    return 0;
}

static inline int answer_put_additional_mx(struct dns_header *dnh,
    struct adns_packet *query, const struct adns_zone *zone, int an_num, VIEW_ARRAY_T * view_array)
{
    int i = 0;
    int ar_num = 0;
    int check_num = 0;
    uint8_t *ns_entry_start_pos = NULL;
    const adns_dname_t * dname_ptr_array[DNS_EDNS0_MAX_LENGTH/ADNS_RR_HEADER_SIZE] = {0};

    /* 1, extract MX domain names from the packet */
    ns_entry_start_pos = query->wire + query->answer_section_offset;
    check_num = 0;
    while(i < an_num){
        int ns_entry_dname_size = adns_dname_size(ns_entry_start_pos);
        int ns_entry_rdata_size = adns_wire_read_u16(ns_entry_start_pos + ns_entry_dname_size + 8);
        int ns_entry_other_size = ADNS_RR_HEADER_SIZE;
        adns_type_t entry_type = adns_wire_read_u16(ns_entry_start_pos + ns_entry_dname_size);
        if(entry_type == ADNS_RRTYPE_MX) {
            dname_ptr_array[check_num] = adns_wire_seek_label(
                    ns_entry_start_pos + ns_entry_dname_size + ns_entry_other_size + 2, query->wire);
            check_num++;
        }
        ns_entry_start_pos += ns_entry_dname_size + ns_entry_other_size + ns_entry_rdata_size;
        i++;
    }

    /* 2, lookup each MX's A/AAAA record and fill up packet*/
    ar_num = adns_zone_lookup_multi_nodes(query, zone, dname_ptr_array, check_num, view_array);
    resp_set_header(dnh, 0, 0, ar_num);
    return 0;
}

static inline adns_private_route_id_t __attribute__ ((always_inline))
adns_custom_view_ipset_lookup(uint32_t client_ip, struct adns_zone *zone)
{
    uint8_t private_route_enable;
    adns_ipset_t *ipset = NULL;

    private_route_enable = zone->private_route_enable;
    ipset = zone->ipset;

    if (unlikely(private_route_enable == 1 && ipset != NULL)) {
        return adns_ipset_lookup(ipset, client_ip);
    }
    
    return (adns_private_route_id_t)IPSET_LOOKUP_MISS;
}

/*
 *
 * if already find CNAME-rr, then try to find the A-rr for the domain in CNAME-RDATA
 * return:
 *     0 : end up in getting A-rr
 *         end up in get REFUSED
 *         end up in get NXDOMAIN
 *         domain name in cname-rr rdata is delegated out thru NS-rr
 *         exceed max recur time
 * if find a CNAME-rr, go recursively
 *
 */
static inline int
ns_answer_domain_cname_cascade(struct dns_header *dnh,
        struct adns_packet *query, const uint8_t *ns_entry_start_pos, int cur_recur_time, VIEW_ARRAY_T * view_array)
{
    if (cur_recur_time <= 0) {
        return 0;
    }
    //parse cname rr
    int ns_entry_dname_size = adns_dname_size(ns_entry_start_pos);
    int ns_entry_rdata_size = adns_wire_read_u16(ns_entry_start_pos + ns_entry_dname_size + 8);
    int ns_entry_other_size = ADNS_RR_HEADER_SIZE;
    const uint8_t *ns_entry_finish_pos = ns_entry_start_pos + ns_entry_dname_size + ns_entry_rdata_size + ns_entry_other_size;
    const adns_dname_t * dname = adns_wire_seek_label(      //support name compression
            ns_entry_start_pos + ns_entry_dname_size + ns_entry_other_size, query->wire);

    //begin searching
    struct adns_zone *zone = NULL;
    struct adns_node *node = NULL, *parent_node = NULL, *wild_node = NULL;
    bool find_domain_succeed = false;

    adns_viewid_t view_id;

    zone = adns_zonedb_lookup(g_datacore_db, dname);
    if (zone == NULL) {
        return 0;
    }

    node = adns_zone_lookup_node(zone, dname);
    if(node != NULL) {
        VIEW_ARRAY_FOR_EACH(*view_array, view_id) {
            if (GET_TAG(node->node_tag, view_id)) {
                find_domain_succeed = true;

                int ar_num_a = 0, ar_num_aaaa = 0, ar_num_cname = 0;

                int ret3 = resp_put_aname(query, node, ADNS_RRTYPE_CNAME, view_id, &ar_num_cname, dname);
                if ( (ret3 == 0) && (ar_num_cname > 0)) {
                    ns_answer_domain_cname_cascade(dnh, query, ns_entry_finish_pos, --cur_recur_time, view_array);
                    resp_set_header(dnh, ar_num_cname, 0, 0);
                    return 0;
                }

                if (adns_node_check_if_ns_exists(node, view_id) == true) {
                    return 0;
                }
                int ret1, ret2;
                ret1 = resp_put_aname(query, node, ADNS_RRTYPE_A, view_id, &ar_num_a, dname);
                ret2 = resp_put_aname(query, node, ADNS_RRTYPE_AAAA, view_id, &ar_num_aaaa, dname);
                if( (ret1 == 0 || ret2 == 0) && (ar_num_a + ar_num_aaaa > 0) ) {
                    resp_set_header(dnh, ar_num_a + ar_num_aaaa, 0, 0);
                    return 0;
                }
            }
        }
    }

    parent_node = adns_zone_lookup_node_lsm(zone, dname, zone->domain_max_label);
    if (parent_node != NULL) {
        VIEW_ARRAY_FOR_EACH(*view_array, view_id) {
            if (GET_TAG(parent_node->node_tag, view_id)) {
                if (adns_node_check_if_ns_exists(parent_node, view_id) == true) {
                    return 0;
                }
                if (find_domain_succeed == false) {
                    if(unlikely(zone_has_wild_domain(zone, view_id) == true)) {
                        wild_node = parent_node->wildcard_child;
                        if (likely((wild_node != NULL) && GET_TAG(wild_node->node_tag, view_id))) {
                            int ar_num_a = 0, ar_num_aaaa = 0, ar_num_cname = 0;

                            int ret3 = resp_put_aname(query, wild_node, ADNS_RRTYPE_CNAME, view_id, &ar_num_cname, dname);
                            if ( (ret3 == 0) && (ar_num_cname > 0)) {
                                ns_answer_domain_cname_cascade(dnh, query, ns_entry_finish_pos, --cur_recur_time, view_array);
                                resp_set_header(dnh, ar_num_cname, 0, 0);
                                return 0;
                            }

                            if (adns_node_check_if_ns_exists(wild_node, view_id) == true) {
                                return 0;
                            }
                            int ret1, ret2;
                            ret1 = resp_put_aname(query, wild_node, ADNS_RRTYPE_A, view_id, &ar_num_a, dname);
                            ret2 = resp_put_aname(query, wild_node, ADNS_RRTYPE_AAAA, view_id, &ar_num_aaaa, dname);
                            if( (ret1 == 0 || ret2 == 0) && (ar_num_a + ar_num_aaaa > 0) ) {
                                resp_set_header(dnh, ar_num_a + ar_num_aaaa, 0, 0);
                                return 0;
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/* check if domain node has specified type records in view */
static inline bool
domain_has_type(struct adns_node *node, adns_type_t type, adns_viewid_t view_id)
{
    struct adns_rrset *rrset = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    rrset = adns_node_get_rrset(node, type);
    if (rrset != NULL) {
        if (view_id >= g_view_max_num) {
            rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t) (view_id - g_view_max_num));
        } else {
            rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
        }
        if (rdata_ctl != NULL && rdata_ctl->rdata_count != 0) {
            return true;
        }
    }
    return false;
}

/***********************************************
 *
 * return 0, succeed
 * return -1, fail to find certain type of rr
 *
***********************************************/

static inline int
ns_answer_normal_domain(struct dns_header *dnh, 
        struct adns_packet *query, const struct adns_zone *zone,
        const struct adns_node *node, adns_viewid_t view_id, VIEW_ARRAY_T * view_array, bool skip_view_switch)
{
    int ret;

    if (likely(node->name_len != zone->name_len)) {
        /* Node is a subdomain
         * Node is exact matching or wildcard/wildcard fallback matching
         * Node has delegation, which means we are its registrar
         * Query node's DS record, we are its authoritative
         * DS is not support yet, so return NOERROR + SOA
         * return NSEC matching delegation
         */
        #if PVT_ZONE_PREFIX
        if ((query->qname_size_prefix == node->name_len || adns_dname_is_wildcard(node->name)) &&
        #else
        if ((query->qname_size == node->name_len || adns_dname_is_wildcard(node->name))&&
        #endif
            query->qtype == ADNS_RRTYPE_DS &&
            domain_has_type(node, ADNS_RRTYPE_NS, view_id)) {
            query->answered += resp_put_authority_soa(dnh, zone, query, DELEGATION_POINT);
            return 0;
        }
        /* If the domain name is not zone name which means it's not querying @,
         * the special process is as follow:
         *     1.Return NS first if there is NS record
         *     2.If skip view switch is set, do not return CNAME,
         *       if skip view switch is not set, return CNAME if exists.
         *     3.Return non-CNAME rrset if exists.
         */
        int ns_num = 0;
        if (ns_answer_domain_rrset_ns(dnh, query, node, view_id, &ns_num)
                > -1) {
            answer_put_additional_ns(dnh, query, zone, ns_num, view_array);
            return 0;
        }

        if (skip_view_switch == true) {
            return -1;
        }
        int an_num = 0;
        ret = ns_answer_domain_rrset(dnh, query, node, ADNS_RRTYPE_CNAME,
                view_id, &an_num);
        if (ret == 0) {
            if ((zone->enable_cname_cascade != 0)) {
                ns_answer_domain_cname_cascade(dnh, query,
                        query->wire + query->answer_section_offset, ADNS_MAX_CNAME_CASCADE, view_array);
            }
            return 0;
        }
    } else {
        /* If the domain name is zone name which means it's querying @,
         * the special process is as follow:
         *      If skip view switch is set, do not return CNAME,
         *      if skip view switch is not set, when qtype == A|AAAA|CNAME, return CNAME if exists.
         */
        if (skip_view_switch == true) {
            return -1;
        }
        if (query->qtype == ADNS_RRTYPE_A ||
            query->qtype == ADNS_RRTYPE_AAAA) {
            /* Check if node CNAME rrset exist, if exist, use cname for response */
            int an_num = 0;
            ret = ns_answer_domain_rrset(dnh, query, node, ADNS_RRTYPE_CNAME,
                    view_id, &an_num);
            if (ret == 0) {
                if ((zone->enable_cname_cascade != 0)) {
                    ns_answer_domain_cname_cascade(dnh, query,
                            query->wire + query->answer_section_offset, ADNS_MAX_CNAME_CASCADE, view_array);
                }
                return 0;
            }
        }
    }

    /* Requested Type */
    int an_num = 0;
    if (likely(ns_answer_domain_rrset(dnh, query, node, query->qtype, view_id, &an_num) > -1)) {
        if (query->qtype == ADNS_RRTYPE_MX) {
            answer_put_additional_mx(dnh, query, zone, an_num, view_array);
        }
        return 0;
    }
    return -1;
}

/* check if domain node has specified type records in higher priori view */
static inline bool
domain_has_A_AAAA_in_high_level_view(struct adns_node *node, VIEW_ARRAY_T * view_array, adns_viewid_t cur_view_id)
{
    struct adns_rrset *a_rrset = NULL, *aaaa_rrset = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    adns_viewid_t view_id = 0;

    a_rrset = adns_node_get_rrset(node, ADNS_RRTYPE_A);
    aaaa_rrset = adns_node_get_rrset(node, ADNS_RRTYPE_AAAA);

    VIEW_ARRAY_FOR_EACH(*view_array, view_id) {
        if (view_id == cur_view_id) {
            break;
        }
        if (GET_TAG(node->node_tag, view_id)) {
            if (a_rrset != NULL) {
                if (view_id >= g_view_max_num) {
                    rdata_ctl = adns_rrset_get_private_rdata_ctl(a_rrset, (adns_private_route_id_t) (view_id - g_view_max_num));
                } else {
                    rdata_ctl = adns_rrset_get_rdata_ctl(a_rrset, view_id);
                }
                if (rdata_ctl != NULL && rdata_ctl->rdata_count != 0) {
                    return true;
                }
            }
            if (aaaa_rrset != NULL) {
                if (view_id >= g_view_max_num) {
                    rdata_ctl = adns_rrset_get_private_rdata_ctl(aaaa_rrset, (adns_private_route_id_t) (view_id - g_view_max_num));
                } else {
                    rdata_ctl = adns_rrset_get_rdata_ctl(aaaa_rrset, view_id);
                }
                if (rdata_ctl != NULL && rdata_ctl->rdata_count != 0) {
                    return true;
                }
            }
        }
    }

    return false;
}

static inline int
ns_answer_domain(uint8_t port, struct dns_header *dnh, uint16_t pkt_length, struct adns_packet *query, 
        struct adns_zone *zone, const adns_dname_t *qname, adns_viewid_t *final_view_id)
{
    /* Indicate that if the domain is found or not */
    bool find_domain_succeed = false;
    // save the initialization here
    int ret;
    const adns_dname_t *orig_qname = NULL;
    struct adns_node * node, * parent_node, * wild_node, * orig_parent_node = NULL;
    bool skip_view_switch = false;     // flag indicates if process view switch in data error case(name exists, required type not exist in view)
    bool check_view_switch = false;    // flag indicates if need to check view switch

    adns_viewid_t view_id = 0;
    adns_viewid_t first_view_id = 0;
    VIEW_ARRAY(view_array);

    query->custom_view_id = adns_custom_view_ipset_lookup(query->client_ip, zone);
    if (query->custom_view_id != IPSET_LOOKUP_MISS) {
        VIEW_ARRAY_PUSH(view_array, query->custom_view_id + g_view_max_num);
    }

    if (query->cli_view_id != 0) {
        VIEW_ARRAY_PUSH(view_array, query->cli_view_id);
    }
    VIEW_ARRAY_PUSH(view_array, 0);

    first_view_id = VIEW_ARRAY_FIRST_VIEWID(view_array);

    /* Only check whether need to process view switch when query A or AAAA */
    if (query->qtype == ADNS_RRTYPE_A || query->qtype == ADNS_RRTYPE_AAAA) {
        check_view_switch = true;
    }

    node = adns_zone_lookup_node(zone, qname);
    if (node != NULL) {
        VIEW_ARRAY_FOR_EACH(view_array, view_id) {
            /* check if node has records in view */
            if (GET_TAG(node->node_tag, view_id)) {
                /* check view swtich if necessary */
                if (view_id != first_view_id && check_view_switch == true) {
                    /* view switch */
                    /* If node has records in higher prior view */
                    if (find_domain_succeed == true) {
                        /* If node has CNAME in current prior view */
                        /* and node has A|AAAA in higher prior view */
                        if (domain_has_type(node, ADNS_RRTYPE_CNAME, view_id) == true &&
                            domain_has_A_AAAA_in_high_level_view(node, &view_array, view_id) == true) {
                            skip_view_switch = true;
                        }
                    }
                }
                find_domain_succeed = true;
                ret = ns_answer_normal_domain(dnh, query, zone, node, view_id, &view_array, skip_view_switch);
                if (ret == 0) {
                    adns_traffic_handle(port, zone, node, pkt_length);
                    ret = RET_NOERROR;
                    goto end;
                }
            }
        }
    }

    parent_node = adns_zone_lookup_node_lsm(zone, qname, zone->domain_max_label);

    /* If domain node is found, but qtype is not found */
    /* no need to handle wildcard query or wildcard fallback */
    /* only need to find NS on parent node */
    if (find_domain_succeed == true) {
        if (parent_node != NULL) {
            if (parent_node->name_len != zone->name_len) {
                VIEW_ARRAY_FOR_EACH(view_array, view_id) {
                    if (GET_TAG(parent_node->node_tag, view_id)) {
                        int ns_num = 0;
                        ret = ns_answer_domain_rrset_ns(dnh, query, parent_node, view_id, &ns_num);
                        if(ret == 0){
                            answer_put_additional_ns(dnh, query, zone, ns_num, &view_array);
                            adns_traffic_handle(port, zone, parent_node, pkt_length);
                            ret = RET_NOERROR;
                            goto end;
                        }
                    }
                }
            }
        }
    } else {
        if (unlikely(zone->wildcard_fallback_enable == 1)) {
            orig_parent_node = parent_node;
            orig_qname = qname;
        }
        VIEW_ARRAY_FOR_EACH(view_array, view_id) {
WILDCARD_FALLBACK:
            if ( unlikely(parent_node != NULL) && GET_TAG(parent_node->node_tag, view_id) ) {
                if (parent_node->name_len != zone->name_len) {
                    /* parent domain NS */
                    int ns_num = 0;
                    ret = ns_answer_domain_rrset_ns(dnh, query, parent_node, view_id, &ns_num);
                    if(ret == 0){
                        answer_put_additional_ns(dnh, query, zone, ns_num, &view_array);
                        adns_traffic_handle(port, zone, parent_node, pkt_length);
                        ret = RET_NOERROR;
                        goto end;
                    }
                }
                /* if NS not found at parent node in current view, continue to find wildcard matching qname in current view */
                if (zone_has_wild_domain(zone, view_id) == true) {
                    wild_node = parent_node->wildcard_child;
                    if ( (wild_node != NULL) && GET_TAG(wild_node->node_tag, view_id) ) {
                        if (view_id != first_view_id && check_view_switch == true) {
                            /* view switch */
                            /* If wildcard node has records in higher prior view */
                            if (find_domain_succeed == true) {
                                /* If node has CNAME in current prior view */
                                /* and node has A|AAAA in higher prior view */
                                if (domain_has_type(wild_node, ADNS_RRTYPE_CNAME, view_id) == true &&
                                    domain_has_A_AAAA_in_high_level_view(wild_node, &view_array, view_id) == true) {
                                    skip_view_switch = true;
                                }
                            }
                        }
                        /* wildcard domain exists in current pirio view */
                        find_domain_succeed = true;
                        ret = ns_answer_normal_domain(dnh, query, zone, wild_node, view_id, &view_array, skip_view_switch);
                        if (ret == 0)  {
                            adns_traffic_handle(port, zone, wild_node, pkt_length);
                            ret = RET_NOERROR;
                            goto end;
                        }
                    }
                }
            }
            if (unlikely(zone->wildcard_fallback_enable == 1)) {
                if (parent_node == NULL || parent_node->name_len == zone->name_len) {
                    // This is the ending condition of wildcard fallback searching
                    parent_node = orig_parent_node;
                    qname = orig_qname;
                } else {
                    // wildcard fallback will not handle qtype missing on qname node or wildcard node matching qname
                    if (find_domain_succeed == false) {
                        parent_node = adns_zone_lookup_node_lsm(zone, qname, zone->wildcard_max_label);
                        qname = adns_wire_next_label(qname);
                        goto WILDCARD_FALLBACK;
                    }
                }
            }
        }
    }

    if (find_domain_succeed == true) {
        adns_traffic_handle(port, zone, node, pkt_length);
        #if PVT_ZONE_PREFIX
        query->answered += resp_put_authority_soa(dnh, zone, query, query->qname_size_prefix == zone->name_len? ZONE_APEX : NORMAL_DOMAIN);
        #else
        query->answered += resp_put_authority_soa(dnh, zone, query, query->qname_size == zone->name_len? ZONE_APEX : NORMAL_DOMAIN);
        #endif
        ret = RET_NOERROR_SOA;
        goto end;
    }

    adns_traffic_handle(port, zone, NULL, pkt_length);
    ret = RET_NXDOMAIN;

end:
    *final_view_id = view_id;
    return ret;
}


/* copy from dpdk app test-pmd */
static inline uint16_t get_16b_sum(const uint16_t *ptr16, uint32_t nr)
{
	uint32_t sum = 0;
	while (nr > 1)
	{
		sum += *ptr16;
		nr -= sizeof(uint16_t);
		ptr16++;
		if (sum > UINT16_MAX)
			sum -= UINT16_MAX;
	}

	/* If length is in odd bytes */
	if (nr)
		sum += *((const uint8_t *)ptr16);

	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum &= 0x0ffff;
	return (uint16_t)sum;
}

/* copy from dpdk app test-pmd */
static inline uint16_t get_ipv4_cksum(const struct ipv4_hdr *ipv4_hdr)
{
	uint16_t cksum;
	cksum = get_16b_sum((const uint16_t *)ipv4_hdr, sizeof(struct ipv4_hdr));
	return (uint16_t)((cksum == 0xffff) ? cksum : ~cksum);
}

static inline void syslog_src_ip_learn(uint32_t src_ip, struct ether_addr * s_addr, uint8_t port)
{
    static int step = 0;
    if ( unlikely( (rte_lcore_id() == app.lcore_io_start_id) && (++step == 10) ) ) {
        step = 0;
        g_syslog_ctl.ipv4_src_addr[port] = src_ip;
        g_syslog_ctl.cur_using_port = port;
        return;
    }
    else {
        return;
    }
}

static inline void tcp_send_rst(struct rte_mbuf *m, struct ipv4_hdr * iph, struct ether_hdr * eth_hdr, uint8_t port)
{
    struct tcp_hdr * tcph;

    if (unlikely(is_valid_tcp_pkt(m, &tcph, 0) < 0)) {
        rte_pktmbuf_free(m);
        return ;
    }

    if ((BE_53 != tcph->dst_port) || !(tcph->tcp_flags & TCP_SYN_FLAG)) {
        rte_pktmbuf_free(m);
        return ;
    }
    
    STATS_INC(tcp_in_53);
    m->l4_len = sizeof(struct tcp_hdr);
    // tcp checksum
    m->ol_flags = PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
    tcph->cksum = get_psd_sum((void *)iph, ETHER_TYPE_IPv4, m->ol_flags);
    //set rst packets
    l4_rst_output(tcph);

    /* updata ip header total length field */
    //do nothing for total_length,  ip_head->ipv4_hdr.total_length = xx;
    iph->hdr_checksum = 0;
    iph->time_to_live = IPV4_TTL;
    /* L3 layer output process */
    l3_output(iph);
    /* L2 layer output process */
    l2_output(eth_hdr);

    m->ol_flags |= PKT_TX_IP_CKSUM;
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = sizeof(struct ipv4_hdr);

    if(likely(MTU_SIZE >= ((int)m->pkt_len - (int)sizeof(struct ether_hdr)))){
        send_single_packet(m, port);
    } else {
        //drop frag syn
        STATS_INC(fragment_out);
        rte_pktmbuf_free(m);
    }
}

static inline void ipv4_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        uint8_t port)
{
    uint8_t l4_proto;
    struct udp_hdr *udh;
    union common_ip_head *ip_head;
    int ret;
    int append_len;

#if 0
    net_pkt_dump((void *)eth_hdr);
#endif

    STATS_INC(ipv4);

    ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
            sizeof(struct ether_hdr));
    if (is_valid_ipv4_pkt(&(ip_head->ipv4_hdr), (int)m->pkt_len - (int)ETH_HLEN) < 0) {
        adns_counter_increase(g_adns_pkt_drop_counter[IPV4_HEADER_INVALID]);
        goto drop_pkt;
    }

    l4_proto = ip_head->ipv4_hdr.next_proto_id;
    switch (l4_proto) {
        case IPPROTO_UDP:
            syslog_src_ip_learn(ip_head->ipv4_hdr.dst_addr, &(eth_hdr->d_addr), port);
            udh = adns_udp_hdr(&(ip_head->ipv4_hdr));
            ret = udp_input(m, ip_head, udh, port, &append_len, 0);
            if (likely(ret == ADNS_PKT_ACCEPT)) {
                break;
            }
            goto drop_pkt;
        case IPPROTO_TCP:
            /* TCP is assumed to be received here, then dropped */
            STATS_INC(tcp_in);
            return tcp_send_rst(m, &(ip_head->ipv4_hdr), eth_hdr, port);

        default:
            /* traffic except TCP and UDP is not supposed to received */
            goto drop_pkt;
    }
    /* updata ip header total length field */
    ip_head->ipv4_hdr.total_length = adns_htons(adns_ntohs(ip_head->ipv4_hdr.total_length) + append_len);
    ip_head->ipv4_hdr.hdr_checksum = 0;
    ip_head->ipv4_hdr.time_to_live = IPV4_TTL;
    /* L3 layer output process */
    l3_output(&(ip_head->ipv4_hdr));
    /* L2 layer output process */
    l2_output(eth_hdr);

	m->ol_flags |= PKT_TX_IP_CKSUM;
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = sizeof(struct ipv4_hdr);

    if(likely(MTU_SIZE >= ((int)m->pkt_len - (int)sizeof(struct ether_hdr)))){
        send_single_packet(m, port);
    }else{
        STATS_INC(fragment_out);
        fragment_output(m, port, MTU_SIZE, 0);
    }

    return;

drop_pkt:
    rte_pktmbuf_free(m);
	return;
}

static inline void ipv6_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        uint8_t port)
{
    uint8_t l6_proto, offset;
    union common_ip_head *ip_head;
    struct udp_hdr *udh;
    int ret;
    int append_len;

    STATS_INC(ipv6);
    ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
            sizeof(struct ether_hdr));
    if (is_valid_ipv6_pkt(&(ip_head->ipv6_hdr), (int)m->pkt_len - (int)ETH_HLEN) < 0) {
        adns_counter_increase(g_adns_pkt_drop_counter[IPV6_HEADER_INVALID]);
        goto drop_pkt;
    }
    ret = ipv6_skip_exthdr(&(ip_head->ipv6_hdr), &offset);
    if (ret < 0) {
        adns_counter_increase(g_adns_pkt_drop_counter[IPV6_EXTHEADER_INVALID]);
        goto drop_pkt;
    }
    l6_proto = (uint8_t)ret;
    switch (l6_proto) {
        case IPPROTO_UDP:
            udh = (struct udp_hdr*)((uint8_t*)ip_head + offset);
            ret = udp_input(m, ip_head, udh, port, &append_len, 1);
            if (likely(ret == ADNS_PKT_ACCEPT)) {
                break;
            }
            goto drop_pkt;
        case IPPROTO_TCP:
            /* TCP is assumed to be received here, then dropped */
            goto drop_pkt;
        default:
            /* traffic except TCP and UDP is not supposed to received */
            goto drop_pkt;
    }
    ip_head->ipv6_hdr.payload_len = adns_htons(adns_ntohs(ip_head->ipv6_hdr.payload_len) + append_len);
    ip_head->ipv6_hdr.hop_limits = IPV6_TTL;
    /* L2 layer output process */
    l2_output(eth_hdr);
    /* L3 layer output process */
    l3_output_ipv6(&(ip_head->ipv6_hdr));
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = sizeof(struct ipv6_hdr);
    m->l4_len = sizeof(struct udp_hdr);
    m->ol_flags = PKT_TX_IPV6 | PKT_TX_UDP_CKSUM;
    udh->dgram_cksum = get_psd_sum((void *)&ip_head->ipv6_hdr,
            ETHER_TYPE_IPv6, m->ol_flags);

    send_single_packet(m, port);
    return;

drop_pkt:
    rte_pktmbuf_free(m);
    return;
}

static inline void raw_input(struct rte_mbuf *m, uint8_t port)
{
    uint16_t ether_type;
    struct ether_hdr *eth_hdr;

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

#if 0
    net_pkt_dump((void *)eth_hdr);
#endif

    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    switch (ether_type) {
        case ETHER_TYPE_IPv6:
            ipv6_input(m, eth_hdr, port);
            break;
        case ETHER_TYPE_IPv4:
            ipv4_input(m, eth_hdr, port);
            break;
        case ETHER_TYPE_ARP:
            rte_pktmbuf_free(m);
            return;
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

#ifdef FUZZ
#include "rte_core.h"

#include "daemon.h"
#include "adns.h"

// init DPDK and ADNS for Fuzzing test
int fuzz_init(bool *Initialized) {
    // since LLVMFuzzerTestOneInput will be called mutiple times, init should be done once
    if (*Initialized == false) {
        int ret;
        unsigned lcore;
        int arg_num;
        char *argp[14], args[13][64];
        int i = 0;
        strcpy(args[i++], "fuzz-dns-parse");
        strcpy(args[i++], "-c");
        strcpy(args[i++], "0x3ff");
        strcpy(args[i++], "-n");
        strcpy(args[i++], "4");
        arg_num = i;

        printf("arg num; %d\n", arg_num);
        for (i = 0; i < arg_num; i++) {
            argp[i] = args[i];
        }

        ret = rte_eal_init(arg_num, (char **)&argp[0]);
        if (ret < 0) {
            printf("Cannot init EAL\n");
            return -1;
        }

        /* since query process will not run on core 0, fix core number to 3*/
        RTE_PER_LCORE(_lcore_id) = 3;

        rte_delay_ms(1000);
        i = 0;
        strcpy(args[i++], "--");
        strcpy(args[i++], "-p");
        strcpy(args[i++], "0x3");
        strcpy(args[i++], "-f");
        strcpy(args[i++], "/home/adns/etc/adns.conf");
        arg_num = i;
        for (i = 0; i < arg_num; i++) {
            argp[i] = args[i];
        }

        ret = adns_parse_args(arg_num, (char **)&argp[0]);
        if (ret < 0) {
            printf("Failed to parse arguments\n");
            return -1;
        }

        ret = adns_init();
        if (ret < 0) {
            RTE_LOG(INFO, ADNS, "Failed to init adns, error: %d\n", ret);
            return -1;
        }

        rte_delay_ms(3000);
        /* Dump server parameter */
        app_print_params();

        *Initialized = true;
    }
    return 0;
}

// Fuzzing test entry for adns_parse
#ifdef FUZZ_DNS_PARSE
bool Initialized = false;
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int ret;

    ret = fuzz_init(&Initialized);
    if (ret != 0) {
        exit(1);
    }

    struct adns_packet packet;

    packet.has_ecs = 0;
    packet.has_edns = 0;
    packet.has_cookie = 0;
    packet.wire = NULL;
    packet.lower_qname[0] = 0;

    adns_parse(&packet, data, size, packet.lower_qname);

    return 0;
}
#endif

// Fuzzing test entry for raw_input
#ifdef FUZZ_RAW_INPUT

#include "mbuf.h"

bool Initialized = false;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int ret;

    ret = fuzz_init(&Initialized);
    if (ret != 0) {
        exit(1);
    }

    int lcore = 3;
    uint8_t dst_port_index = 0;
    struct ether_hdr *eth = NULL;
    struct rte_mbuf* mbuf = NULL;
    char *s = NULL;
    struct udp_hdr *udh = NULL;
    struct ipv4_hdr *iphdr = NULL;


    mbuf = mbuf_alloc();
    if (mbuf == NULL) {
        printf("allocate mbuffer error\n");
        return 0;
    }

    eth = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
    eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ether_addr_copy(&app.eth_addrs[0], &eth->s_addr);
    ether_addr_copy(&g_syslog_ctl.d_addr[0], &eth->d_addr);

    iphdr = (struct ipv4_hdr *)&eth[1];
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->packet_id = 0;
    iphdr->fragment_offset = rte_cpu_to_be_16(ADNS_SYSLOG_IP_DF);
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->hdr_checksum = 0;
    iphdr->src_addr = g_syslog_ctl.ipv4_src_addr[0];
    iphdr->dst_addr = g_syslog_ctl.ipv4_dst_addr;

    udh = (struct udp_hdr *)&iphdr[1];
    dst_port_index = g_syslog_ctl.current_port[lcore] % g_syslog_ctl.max_port;
    g_syslog_ctl.current_port[lcore]++;
    udh->src_port = rte_cpu_to_be_16(g_syslog_ctl.src_port[lcore][dst_port_index]);
    udh->dst_port = rte_cpu_to_be_16(g_syslog_ctl.dst_port);
    udh->dgram_cksum = 0;

    s = (char *)&udh[1];
    memcpy(s, data, size);
    if (unlikely(rte_pktmbuf_append(mbuf, ETH_HLEN + sizeof(struct ipv4_hdr) + UDP_HLEN + size) == NULL)) {
        return 0;
    }

    udh->dgram_len = adns_htons(UDP_HLEN + size);
    iphdr->total_length = adns_htons(sizeof(struct ipv4_hdr) + UDP_HLEN + size);

    mbuf->ol_flags |= PKT_TX_IP_CKSUM;
    mbuf->l2_len = sizeof(struct ether_hdr);
    mbuf->l3_len = sizeof(struct ipv4_hdr);
    raw_input(mbuf, 0);

    return 0;
}
#endif

#endif

/* Answer CH class query:
    CH view.adns TXT: return source IP and matching view name
    CH hostname.adns TXT: return ADNS hostname
*/
#define MAX_VIEW_ADNS_LEN (VIEW_NAME_LEN << 1)
static inline int
ns_answer_chaos(struct adns_packet *query, struct dns_header *dnh, uint8_t *lower_qname)
{
    uint8_t *pos, *rdata_p;
    uint8_t rdata_len;
    int len = 0;
    char *client_view_name = NULL;
    char view_adns[MAX_VIEW_ADNS_LEN] = {0}; //"source_IP view_name"
    int view_adns_len = 0;

    // CH class query only allow TXT type
    if (unlikely(query->qtype != ADNS_RRTYPE_TXT)) {
        return -1;
    }

    if (query->qname_size == CH_HOST_NAME_LEN && 
        memcmp(ch_host_name, lower_qname, CH_HOST_NAME_LEN) == 0) {
        // hostname.adns
        rdata_p = (uint8_t *)g_hostname;
        rdata_len = g_hostname_len;
    } else if (query->qname_size == CH_VIEW_LEN &&
        memcmp(ch_view, lower_qname, CH_VIEW_LEN) == 0) { // view.adns
        if (query->cli_view_id == 0) {
            client_view_name = "default";
        } else {
            client_view_name = (char *)view_id_to_name(query->cli_view_id);
        }
        if (unlikely(client_view_name == NULL)) {
            return -1;
        }
        // IPv4
        if (query->is_ipv6_view == 0) {
            view_adns_len = snprintf(view_adns, MAX_VIEW_ADNS_LEN, NIPQUAD_FMT " %s", NIPQUAD(query->client_ip), client_view_name);
        } else { // IPv6
            view_adns_len = snprintf(view_adns, MAX_VIEW_ADNS_LEN, NIP6_FMT " %s", NIP6_ADDR(query->client_ipv6), client_view_name);
        }
        // error occurs or truncated
        if (view_adns_len < 0 || view_adns_len >= MAX_VIEW_ADNS_LEN) {
            return -1;
        }
        rdata_p = (uint8_t *)view_adns;
        rdata_len = view_adns_len;
    } else {
        return -1;
    }

    pos = query->wire + query->answered;
    /* fill query domain name */
    adns_wire_put_pointer(pos, ADNS_WIRE_HEADER_SIZE);
    pos += sizeof(uint16_t);
    len += sizeof(uint16_t);
    /* fill type, class, ttl */
    *(uint16_t *)pos = adns_htons(ADNS_RRTYPE_TXT);
    pos += 2;
    *(uint16_t *)pos = adns_htons(ADNS_CLASS_CH);
    pos += 2;
    *(uint32_t *)pos = 0;
    pos += 4;
    /* fill rdlen */
    *(uint16_t *)pos = adns_htons(rdata_len + 1);
    pos += 2;
    /* fill txt len */
    *pos = rdata_len;
    pos ++;
    /* fill txt */
    rte_memcpy(pos, rdata_p, rdata_len);

    len += ADNS_RR_HEADER_SIZE + 1 + rdata_len;
    resp_set_header(dnh, 1, 0, 0);

    return len;
}

static inline int 
l4_ns_answer_process(struct rte_mbuf *m, uint8_t port, struct udp_hdr *udh, 
            struct adns_packet *query, uint16_t pkt_length,
            struct dns_header *dnh, adns_viewid_t *final_view_id, uint8_t *lower_qname, int *ansflag)
{
    struct adns_zone *zone;
    uint16_t qtype;
    uint16_t qclass;
    int new_len = 0;
    int ret;

    /* if opt version is not 0, return BADVERS */
    if (unlikely(query->opt_rr.version != 0)) {
        adns_wire_set_qr((uint8_t *)dnh);
        resp_set_header(dnh, 0, 0, 0);
        goto fill_done;
    }

    qtype = adns_packet_qtype(query);
    if (unlikely( ((qtype >= ADNS_RRSET_MAX) && (qtype != ADNS_RRTYPE_CAA)) ||
                  qtype == 0) )
        goto notimpl_done;

    qclass = adns_packet_qclass(query);
    // only support IN and CH class
    if (unlikely(qclass != ADNS_CLASS_IN &&
                 qclass != ADNS_CLASS_CH)) {
        goto notimpl_done;
    }
    // process CHAOS query
    if (unlikely(qclass == ADNS_CLASS_CH)) {
        ret = ns_answer_chaos(query, dnh, lower_qname);
        if (ret < 0) {
            goto notimpl_done;
        }
        query->answered += ret;
        goto fill_done;
    }

    struct adns_zonedb *zonedb = g_datacore_db;

    #if PVT_ZONE_PREFIX
    uint8_t lower_qname_prefix[256];
    if (adns_dname_prefix(lower_qname, lower_qname_prefix)) {
        zone = NULL;
    } else {
        zone = adns_zonedb_lookup(zonedb, lower_qname_prefix);
        query->qname_size_prefix = adns_dname_size(lower_qname_prefix); 
        strncpy(query->qname_postfix, query->qname+query->qname_size_prefix-1, PVT_ZONE_POSTFIX_MAX);
        query->qname_postfix[PVT_ZONE_POSTFIX_MAX-1] = 0;
        query->qname_size_postfix = adns_dname_size(query->qname_postfix); 
    }
    #else
    zone = adns_zonedb_lookup(zonedb, lower_qname);
    #endif
    /* in order to hide the RR types on the domain node, when qtype == RRSIG, return refused */
    if (zone == NULL || query->qtype == ADNS_RRTYPE_RRSIG) {

        /* 
         * The name server refuses to perform the specified for policy reasons.
         * For example, a name server may not wish to provide the infomation to
         * the particular requester, or a name server may not wish to perform a
         * particular operation(e.g., zone transfer) for particular data.
         */
        /* TODO: refused answer keep the same edns option as query, different behavior
         * from other query process(NOERROR, NXDOMAIN)
         */
        resp_set_refuse(dnh);
        /* set response */
        adns_wire_set_qr((uint8_t *)dnh);
        *ansflag = ADNS_RCODE_REFUSED;
        return 0;
    }

    /* DNSKEY process */
    if (unlikely(query->qtype == ADNS_RRTYPE_DNSKEY &&
                #if PVT_ZONE_PREFIX
                query->qname_size_prefix == zone->name_len &&
                #else
                query->qname_size == zone->name_len &&
                #endif
                zone->dnssec_ok == 1 && zone->enable_dnssec == 1)) {
        new_len = resp_put_dnskey(dnh, zone, query);
        query->answered += new_len;
        adns_traffic_handle(port, zone, NULL, pkt_length);
        goto fill_done;
    }

    /*
     * SOA process, All have the same name zones in different view should
     * have the same SOA rdata, this is checked on zone load stage.
     * check if query type is SOA, if not SOA, goto view answer step
     */
    // Only zone apex is allowed to have SOA, the sub domain SOA query will be processed later
    if (unlikely(query->qtype == ADNS_RRTYPE_SOA &&
                #if PVT_ZONE_PREFIX
                 query->qname_size_prefix == zone->name_len)) {
                #else
                 query->qname_size == zone->name_len)) {
                #endif
        new_len = resp_put_answer_soa(dnh, zone, query);
        query->answered += new_len;
        adns_traffic_handle(port, zone, NULL, pkt_length);
        goto fill_done;
    }

    /*
     * ANY type query process, return HINFO for any type query, no matter the domain exist or not
     */
    if (unlikely(query->qtype == ADNS_RRTYPE_ANY)) {
        new_len = ns_answer_type_any(dnh, query, zone);
        query->answered += new_len;
        goto fill_done;
    }

    /*
     * view lookup logic: first locate view by client ip, we call it normal view,
     * if normal view exist, lookup exact domain in normal view; if normal view does
     * not exist, use default view. normal view does not have wilcdcrad logic, only
     * default view has wildcard answer logic.
     */
    #if PVT_ZONE_PREFIX
    ret = ns_answer_domain(port, dnh, pkt_length, query, zone, lower_qname_prefix, final_view_id);
    #else
    ret = ns_answer_domain(port, dnh, pkt_length, query, zone, lower_qname, final_view_id);
    #endif
    if(unlikely (ret == RET_NXDOMAIN)) {
        goto nxdomain;
    }

fill_done:
    resp_set_noerror(dnh);
    ret = answer_put_additional(query);
    if (ret < 0){
        adns_counter_increase(g_adns_pkt_drop_counter[FILL_DONE_PROCESS_FAILED]);
		return -1;
	}
    *ansflag = ADNS_RCODE_NOERROR;
    return 0;

nxdomain:
    #if PVT_ZONE_PREFIX
    new_len = resp_put_authority_soa(dnh, zone, query, query->qname_size_prefix == zone->name_len? ZONE_APEX : NORMAL_DOMAIN);
    #else
    new_len = resp_put_authority_soa(dnh, zone, query, query->qname_size == zone->name_len? ZONE_APEX : NORMAL_DOMAIN);
    #endif
    query->answered += new_len;
    // put edns0
    ret = answer_put_additional(query);
    if (ret < 0){
        adns_counter_increase(g_adns_pkt_drop_counter[FILL_DONE_PROCESS_FAILED]);
		return -1;
	}
    // If query zone apex, zone apex certainly exists because that it must has a SOA
    // should set Rcode to NOERROR other than NXDOMAIN
    // in DNSSEC case, return noerror + SOA for all NXDOMAIN answers
    #if PVT_ZONE_PREFIX
    if (likely(query->qname_size_prefix != zone->name_len &&
    #else
    if (likely(query->qname_size != zone->name_len &&
    #endif
               (query->dnssec == 0 || zone->enable_dnssec == 0 || zone->dnssec_ok == 0 ))) {
        resp_set_nxdomain(dnh);
        *ansflag = ADNS_RCODE_NXDOMAIN;
    } else {
        resp_set_noerror(dnh);
        *ansflag = ADNS_RCODE_NOERROR;
    }
    return 0;

notimpl_done:
    resp_set_notimpl(dnh);
    *ansflag = ADNS_RCODE_NOTIMPL;
    return 0;
}

/* udp process*/
static inline int 
ns_answer_process(struct rte_mbuf *m, uint8_t port, struct udp_hdr *udh, struct adns_packet *query,
            struct dns_header *dnh, adns_viewid_t *final_view_id, uint8_t *lower_qname, int *ansflag) {
   uint16_t pkt_length = rte_pktmbuf_pkt_len(m);
   return l4_ns_answer_process(m, port, udh, 
                                query, pkt_length,
                                dnh, final_view_id, lower_qname, ansflag); 
}

/* tcp process*/
static inline int 
ndns_ns_answer_process(uint8_t port, struct adns_packet *query,
            struct dns_header *dnh, adns_viewid_t *final_view_id, uint8_t *lower_qname, int *ansflag,
            int buf_len) {
   return l4_ns_answer_process(NULL, port, NULL, 
                                query, buf_len,
                                dnh, final_view_id, lower_qname, ansflag); 
}

static inline void __attribute__ ((always_inline))
ndns_fill_answer_log_data(struct dns_header *dnh, struct adns_packet *packet, int ret, answer_log_data_t * answer_log)
{
	answer_log->ret = ret;
	answer_log->ip_ver = packet->ip_ver;
	
	adns_qname_to_str_fast(packet->qname, answer_log->domain_name_a); //malloc

	answer_log->qtype 		= packet->qtype;
	answer_log->view_name 	= packet->final_view_name;
	answer_log->cli_view_name = packet->cli_view_name;
	answer_log->cur_tsc 	= rte_rdtsc();
	answer_log->has_ecs 	= packet->has_ecs;
	answer_log->has_cookie 	= packet->has_cookie;
	answer_log->dns_id 		= dnh->id;

	if (!ret) {
		answer_log->flags2 = dnh->flags2;
		answer_log->ancount = dnh->ancount;
		answer_log->nscount = dnh->nscount;
		answer_log->arcount = dnh->arcount;
	}
}

static inline int 
l4_dns_input(struct rte_mbuf *m, union common_ip_head *ip_head,
        struct udp_hdr *udh, uint8_t port, 
        int *append_len, int isipv6, int isudp,
        char * tcp_input, int tcp_len, int buf_len, uint32_t sip, struct in6_addr * sip6, char * query_buf, struct answer_log_data * log_data)
{
    int ret;
    size_t size;
    uint8_t *wire;
    struct dns_header *dnh;
    struct adns_packet packet;
    adns_viewid_t final_view_id = 0;
    char * final_view_name = NULL, * cli_view_name = NULL;
    int new_len = 0, ansflag = 0;

    /* Drop non-dns packet */
    if (isudp && udh->dst_port != BE_53) {
        adns_counter_increase(g_adns_pkt_drop_counter[ERROR_PORT]);
        goto drop_pkt;
    }

	STATS_INC(query);

    if (unlikely(isudp && 
                    ((adns_ntohs(udh->dgram_len) <= UDP_HLEN + DNS_HLEN) || 
                     ((int)m->pkt_len - (int)((uint8_t *)udh - rte_pktmbuf_mtod(m, uint8_t *)) < (int)adns_ntohs(udh->dgram_len) )))) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_BAD_LENGTH]);
        goto drop_pkt;
    }

    if (likely(isudp)) {
        dnh = (struct dns_header *)((uint8_t *)udh + UDP_HLEN);
        wire = (uint8_t *)dnh;
    } else {
        dnh = (struct dns_header *)tcp_input;
        wire = (uint8_t *)dnh;
    }

    /* check whether the dns packet is response */
    if (unlikely(adns_wire_get_qr(wire) == 0x80)) {
        adns_counter_increase(g_adns_pkt_drop_counter[PACKAGE_IS_RESPONSE]);
        goto drop_pkt;
    }

    /* Dues to the performance issue, does not clear the packet structure,
     * has confirmed except has_ecs and has_edns two fields, all other fields
     * has been initialized before using. Refer to the structure definition
     * for details. Must make sure never use these fields before they have been
     * really initialized.
     */
    packet.has_ecs = 0;
    packet.has_edns = 0;
    packet.has_cookie = 0;
    packet.dnssec = 0;
    packet.opt_rr.version = 0;
    packet.is_ipv6_view = 0;
    if (isipv6) {
        packet.ip_ver = 6;
        packet.is_ipv6_view = 1;
    } else {
        packet.ip_ver = 4;
    }
    // by default, authoritative answer flag is set
    packet.is_aa = 1;

    /* Dues to the performance issue, does not clear the lower_qname buffer,
     * will and '\0' in the adns_dname_wire_check function, should not use this
     * buffer before that function.
     */
    //memset(lower_qname, 0, sizeof(lower_qname));
    /* pre-parse dns packet */
    packet.lower_qname[0] = 0;
    packet.is_tcp = !isudp;
    if (packet.is_tcp) {
        packet.answer_max_size = TCP_DNS_MAX_LENGTH;
    } else {
        packet.answer_max_size = MAX_UDP_PAYLOAD;
    }
    size = isudp ? adns_ntohs(udh->dgram_len) - UDP_HLEN : tcp_len;
    ret = adns_parse(&packet, wire, size, packet.lower_qname);
    if (unlikely(ret)) {
        if (unlikely(!isudp)) {
            packet.lower_qname[ADNS_DNAME_MAXLEN] = 0;
            adns_qname_to_str_fast(packet.lower_qname, query_buf);
            log_data->qtype = packet.qtype;
        }
        goto drop_pkt;
    }


    if (unlikely(packet.has_ecs)) {
        if(packet.opt_rr.opt_ecs.family == ECS_FAMILY_IPV4) {
            packet.client_ip = packet.opt_rr.opt_ecs.addr.v4;
            packet.is_ipv6_view = 0;
        } else {
            memcpy(&packet.client_ipv6, packet.opt_rr.opt_ecs.addr.v61, sizeof(struct in6_addr));
            packet.is_ipv6_view = 1;
        }
    } else {
        if (packet.ip_ver == 4) {
            packet.client_ip = sip;
        } else {
            if (likely(isudp))
                memcpy(&packet.client_ipv6, &ip_head->ipv6_hdr.src_addr, sizeof(struct in6_addr));
            else {
                if (sip6)
                    memcpy(&packet.client_ipv6, sip6, sizeof(struct in6_addr));
            }
        }
    }

    if (packet.is_ipv6_view == 0) {
        packet.cli_view_id = ip_bitmap_get(packet.client_ip, 0); //Only socket 0 has the data.
    } else {
#ifdef __IPV6_SUPPORT
        packet.cli_view_id = ipv6_bitmap_get(packet.client_ipv6, 0);
#else
        packet.cli_view_id = 0;
        packet.client_ip = 0;
#endif
    }
    if (packet.cli_view_id >= g_view_max_num) {
        adns_counter_increase(g_adns_pkt_drop_counter[VIEW_EXCEED_MAX_NUMBER]);
        goto drop_pkt;
    }

    // init DNS header
    resp_init_header(dnh);

    if (likely(isudp)) {
        ret = ns_answer_process(m, port, udh, &packet, dnh, &final_view_id, packet.lower_qname, &ansflag);
    } else {
        ret = ndns_ns_answer_process(0, &packet, dnh, &final_view_id, packet.lower_qname, &ansflag, buf_len);
        adns_qname_to_str_fast(packet.qname, query_buf);
    }

    if (!isudp || unlikely(adns_log_switch == ADNS_LOG_SWITCH_UP)) {
        if (packet.cli_view_id == 0) {
            cli_view_name = "default";
        } else {
            cli_view_name = (char *)view_id_to_name(packet.cli_view_id);
        }
        if (cli_view_name == NULL) {
            adns_counter_increase(g_adns_pkt_drop_counter[VIEW_NAME_IS_NOT_EXISTED]);
            goto drop_pkt;
        }
        packet.cli_view_name = cli_view_name;

        if (final_view_id >= g_view_max_num) {
            final_view_name = (char *)custom_view_id_to_name(final_view_id - g_view_max_num);
        }
        else {
            if (final_view_id == 0) {
                final_view_name = "default";
            } else {
                final_view_name = (char *)view_id_to_name(final_view_id);
            }
        }
        if (final_view_name == NULL){
            adns_counter_increase(g_adns_pkt_drop_counter[VIEW_NAME_IS_NOT_EXISTED]);
            goto drop_pkt;
        }
        packet.final_view_name = final_view_name;

        if (likely(isudp)) {
            ns_response_record_log(ip_head, udh, dnh, &packet, ret);
        } else {
            ndns_fill_answer_log_data(dnh, &packet, ret, log_data);
        }
    }

    if (ret){
        goto drop_pkt;
    }
    *append_len = 0;
    if (ansflag != ADNS_RCODE_REFUSED && ansflag != ADNS_RCODE_NOTIMPL) {
        new_len = (int)packet.answered - (int)packet.size;
        if (likely(isudp)) {
            if (dns_post_process(m, udh, new_len) < 0) {
                adns_counter_increase(g_adns_pkt_drop_counter[FILL_DONE_PROCESS_FAILED]);
                goto drop_pkt;
            }
        } else {
            if (packet.answered > buf_len) {
                log_query_info(rte_lcore_id(), "Not enough data to store answer\n");
                adns_counter_increase(g_adns_pkt_drop_counter[FILL_DONE_PROCESS_FAILED]);
                goto drop_pkt;
            }
        }
        *append_len = new_len;
    }

    STATS_INC(answer);
    if (likely(isudp)) {
        udh->dgram_cksum = 0;
        /* L4 layer UDP output process */
        l4_udp_output(udh);
    }

    return ADNS_PKT_ACCEPT;


drop_pkt:
    return ADNS_PKT_DROP;
}

static inline int 
udp_input(struct rte_mbuf *m, union common_ip_head *ip_head,
        struct udp_hdr *udh, uint8_t port, int *append_len,
        int isipv6) {
    return l4_dns_input(m, ip_head,
                        udh, port, 
                        append_len, isipv6, 1,
                        NULL, 0, 0, ip_head->ipv4_hdr.src_addr, NULL, NULL, NULL) ;
}

int ndns_tcp_input(int *append_len, char * tcp_input, int tcp_len, int buf_len, uint32_t sip, struct in6_addr * sip6, int isipv6, char * qname_str, struct answer_log_data * log_data) {
    return l4_dns_input(NULL, NULL,
                    NULL, 0,
                    append_len, isipv6, 0,
                    tcp_input, tcp_len, buf_len, sip, sip6, qname_str, log_data);
}

static inline int adns_dname_wire_check_tcp(const uint8_t *name, const uint8_t *endp, uint8_t *lower_name)
{
    int name_len = 1; /* Keep \x00 terminal label in advance. */
    const uint8_t *next_label;
    if (unlikely(name == NULL || name == endp)){
        return -EINVAL;
    }
    while (*name != '\0') {
        /* Check label length (maximum 63 bytes allowed). */
        if (unlikely(*name > ADNS_DNAME_LABEL_MAXLEN)){
            return -1;
        }
        int lblen = *name + 1;
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
            if (likely(isprint(*name))) {
                *lower_name++ = adns_tolower(*name++);
                continue;
            }
            return -1;
        } while (name < next_label);
        /* Update wire size only for noncompressed part. */
        name_len += lblen;
    }
    *lower_name = '\0';
    return name_len;
}