#ifndef __ADNS_LOG__
#define __ADNS_LOG__

#include <sys/time.h>

typedef struct answer_log_data {
	int32_t ret;
	uint16_t ip_ver;
	uint16_t sport;
	uint16_t dport;
	uint16_t dns_id;
	union {
    	uint32_t sip;
    	uint8_t sip6[16];
	};
	union {
    	uint32_t dip;
    	uint8_t dip6[16];
	};
	char * domain_name;
    char * cli_view_name;  /* the view where the client resource IP address is located */
    char * view_name;      /* the real view where the query result is located */
    uint64_t cur_tsc;

	/* part of dns_header*/
    uint8_t has_edns:1,    /* flag indicates if query has edns0 */
            has_ecs:1,     /* flag indicates if query has ecs */
            has_cookie:1;  /* flag indicates if query has cookie */
	uint8_t dnssec;        /* flag indicates if query is DNSSEC */
    uint8_t flags2;
    uint16_t qtype;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
	char domain_name_a[ADNS_DNAME_MAXLEN + 1];

    char msg[0];
} answer_log_data_t;
#define ANSWER_LOG_DATA_MSG_SIZE (LOG_MSG_DATA_SIZE - sizeof(answer_log_data_t))

typedef enum EXCEED_QPS_TYPE {
    EXCEED_DNSSEC_QPS_SRC_IP = 0,
    EXCEED_DNSSEC_QPS_ZONE,
    EXCEED_DNSSEC_QPS_GLOBAL,
}EXCEED_QPS_TYPE_T;

typedef struct exceed_qps_log_data {
    EXCEED_QPS_TYPE_T type;
    uint16_t ip_ver;
    union {
        uint32_t sip;
        uint8_t sip6[16];
    };
    uint16_t qtype;
    uint32_t qps_limit_quota;
    char domain_name_a[ADNS_DNAME_MAXLEN + 1];
    uint64_t cur_tsc;

    char msg[0];
} exceed_qps_log_data_t;
#define EXCEED_QPS_LOG_DATA_MSG_SIZE (LOG_MSG_DATA_SIZE - sizeof(exceed_qps_log_data_t))

extern uint64_t HZ;
extern char log_level_str[4][10];

static inline void __attribute__ ((always_inline))
calculate_timestamp(struct timeval *ts, uint32_t lcore_id, uint64_t cur_tsc) {
    struct timeval cur_time;
    struct lcore_params *lp;
    uint64_t cycles;

    lp = &app.lcore_params[lcore_id];
    cycles = cur_tsc - lp->start_cycles;
    cur_time.tv_sec = cycles / HZ;
    cur_time.tv_usec = (cycles % HZ) * 1e6 / HZ;
    timeradd(&lp->start_time, &cur_time, ts);
}

static inline void __attribute__ ((always_inline))
adns_qname_to_str_fast(const adns_dname_t *qname, char * buff)
{
    uint8_t lblen;
    uint16_t str_len = 0;

    if(unlikely((lblen = *qname) == 0)) {
        buff[0] = '.';
        buff[1] = '\0';

        return;
    }

    while (lblen != 0) {
        qname++;
        rte_memcpy(buff+str_len, qname, lblen);
        str_len += lblen;
        qname += lblen;
        lblen = *qname;
        // Write label separation.
        buff[str_len++] = '.';
    }

    // String_termination.
    buff[str_len] = '\0';
}

static inline log_msg_t * __attribute__ ((always_inline))
fill_answer_log_data(union common_ip_head *ip_head, struct udp_hdr *udh, struct dns_header *dnh, struct adns_packet *packet, int ret)
{
    struct log_msg * lmsg;
    answer_log_data_t * answer_log;

    lmsg = log_alloc_level(DNS_LOG_INFO);
    if (lmsg == NULL) {
        return NULL;
    }

    answer_log = (answer_log_data_t *)lmsg->data;
	
	answer_log->ret = ret;
	answer_log->ip_ver = packet->ip_ver;
	
	adns_qname_to_str_fast(packet->qname, answer_log->domain_name_a); //malloc

	if (4 == answer_log->ip_ver) {
		answer_log->sip = ip_head->ipv4_hdr.src_addr;
		answer_log->dip = ip_head->ipv4_hdr.dst_addr;
	} else {
		rte_memcpy(answer_log->sip6, ip_head->ipv6_hdr.src_addr, 16);
		rte_memcpy(answer_log->dip6, ip_head->ipv6_hdr.dst_addr, 16);
	}

	answer_log->sport = udh->src_port;
	answer_log->dport = udh->dst_port;

	answer_log->qtype 		= packet->qtype;
	answer_log->view_name 	= packet->final_view_name;
	answer_log->cli_view_name = packet->cli_view_name;
	answer_log->cur_tsc 	= rte_rdtsc();
	answer_log->has_ecs 	= packet->has_ecs;
	answer_log->has_cookie 	= packet->has_cookie;
	answer_log->dns_id 		= dnh->id;
	answer_log->dnssec      = packet->dnssec;

	if (!ret) {
		answer_log->flags2 = dnh->flags2;
		answer_log->ancount = dnh->ancount;
		answer_log->nscount = dnh->nscount;
		answer_log->arcount = dnh->arcount;
	}
    //fill the answer_log end

    return lmsg;
}

static inline log_msg_t * __attribute__ ((always_inline))
fill_exceed_qps_log_data(EXCEED_QPS_TYPE_T type, struct adns_packet *packet, uint32_t dnssec_qps_quota)
{
    struct log_msg * lmsg;
    exceed_qps_log_data_t * qps_limit_log;

    lmsg = log_alloc_level(DNS_LOG_INFO);
    if (lmsg == NULL) {
        return NULL;
    }

    qps_limit_log = (exceed_qps_log_data_t *)lmsg->data;
    qps_limit_log->type = type;
    qps_limit_log->cur_tsc = rte_rdtsc();

    qps_limit_log->ip_ver = packet->ip_ver;
    adns_qname_to_str_fast(packet->qname, qps_limit_log->domain_name_a);

    if (4 == qps_limit_log->ip_ver) {
        qps_limit_log->sip = packet->client_ip;
    } else {
        rte_memcpy(qps_limit_log->sip6, &(packet->client_ipv6), 16);
    }
    qps_limit_log->qtype = packet->qtype;

    qps_limit_log->qps_limit_quota = dnssec_qps_quota;

    return lmsg;
}

char * answer_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size);

char * exceed_qps_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size);

static inline void __attribute__ ((always_inline))
ns_response_record_log(union common_ip_head *ip_head, struct udp_hdr *udh, struct dns_header *dnh, struct adns_packet *packet, int ret)
{
    if (rte_ring_free_count(g_log_query_rings[rte_lcore_id()]) > 0) {
        log_query_custom(answer_fmt,
                fill_answer_log_data(ip_head, udh, dnh, packet, ret));
    }
}


#endif
