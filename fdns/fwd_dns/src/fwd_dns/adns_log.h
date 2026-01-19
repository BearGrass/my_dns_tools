#ifndef __ADNS_LOG__
#define __ADNS_LOG__

#include <sys/time.h>

#include "log.h"
#include "ldns.h"
#include "dname.h"
#include "fwd_ip_user_tbl.h"

#define LOG_ACTION_DROP 0
#define LOG_ACTION_ANSWER 1
#define LOG_ACTION_FORWARD 2
#define LOG_ACTION_HIJACK 3
#define LOG_ACTION_ERROR 4


typedef struct answer_log_data {
    uint16_t ip_ver;
    union {
        uint32_t sip;
        uint8_t sip6[16];
    };
    union {
        uint32_t dip;
        uint8_t dip6[16];
    };
    uint16_t sport;
    uint16_t dport;
    adns_viewid_t cli_view;
    struct dns_header header;
    uint16_t qtype;
    uint16_t qclass;
    char domain_name_a[ADNS_DNAME_MAXLEN + 1];
    uint8_t zname_offset;
    uint8_t has_edns; /* flag indicates if query has edns0 */
    uint8_t has_ecs; /* flag indicates if query has ecs */
            //has_cookie :1, /* flag indicates if query has cookie */
            //do_dnssec :1; /* flag indicates if query require dnssec */
    uint8_t srv_type;
    uint64_t cur_tsc;
    uint8_t is_tcp;
    uint8_t is_from_kni;
    uint8_t action;
    uint32_t uid;

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

static inline log_msg_t * __attribute__ ((always_inline))
fill_query_log_data(union common_ip_head *ip_head, union common_l4_head *l4_hdr,
        int is_tcp, int is_from_kni, struct dns_packet *packet, int action) {
    struct log_msg * lmsg;
    answer_log_data_t * answer_log;

    lmsg = LOG_ALLOC_LEVEL(QUERY, INFO);
    if (lmsg == NULL) {
        return NULL;
    }

    answer_log = (answer_log_data_t *) lmsg->data;
    answer_log->ip_ver = packet->ip_ver;

    if (4 == answer_log->ip_ver) {
        answer_log->sip = ip_head->ipv4_hdr.src_addr;
        answer_log->dip = ip_head->ipv4_hdr.dst_addr;
    } else {
        rte_memcpy(answer_log->sip6, ip_head->ipv6_hdr.src_addr, 16);
        rte_memcpy(answer_log->dip6, ip_head->ipv6_hdr.dst_addr, 16);
    }

    answer_log->sport = *(uint16_t *)l4_hdr;
    answer_log->dport = *(((uint16_t *)l4_hdr) + 1);
    answer_log->cli_view = packet->cli_view;
    answer_log->header = packet->header;
    answer_log->qtype = packet->qtype;
    answer_log->qclass = packet->qclass;
    rte_memcpy(answer_log->domain_name_a, packet->dname, packet->dname_len);
    answer_log->zname_offset = packet->zname_offset;
    answer_log->has_edns = packet->has_edns;
    answer_log->has_ecs = packet->has_ecs;
    //answer_log->has_cookie = packet->has_cookie;
    //answer_log->do_dnssec = packet->do_dnssec;
    answer_log->cur_tsc = rte_rdtsc();
    answer_log->is_from_kni = (uint8_t)is_from_kni;
    answer_log->is_tcp = (uint8_t)is_tcp;
    answer_log->action = (uint8_t)action;
    answer_log->srv_type = packet->srv_type;
    //fill the query_log end

    return lmsg;
}

static inline log_msg_t * __attribute__ ((always_inline))
fill_answer_log_data(union common_ip_head *ip_head,
        union common_l4_head *l4_hdr, int is_tcp, int is_from_kni, int is_ipv6,
        uint32_t view_id, struct dns_header *dnh, int has_ecs, uint8_t srv_type,
        uint8_t zname_offset) {
    struct log_msg * lmsg;
    answer_log_data_t * answer_log;
    const uint8_t *pos;

    lmsg = log_alloc();
    if (lmsg == NULL) {
        return NULL;
    }

    answer_log = (answer_log_data_t *) lmsg->data;
    answer_log->ip_ver = is_ipv6 ? 6 : 4;

    // output packet, should swap the source and dest
    if (4 == answer_log->ip_ver) {
        answer_log->dip = ip_head->ipv4_hdr.src_addr;
        answer_log->sip = ip_head->ipv4_hdr.dst_addr;
    } else {
        rte_memcpy(answer_log->dip6, ip_head->ipv6_hdr.src_addr, 16);
        rte_memcpy(answer_log->sip6, ip_head->ipv6_hdr.dst_addr, 16);
    }

    // output packet, should swap the source and dest
    answer_log->dport = *(uint16_t *)l4_hdr;
    answer_log->sport = *(((uint16_t *)l4_hdr) + 1);
    answer_log->cli_view = view_id;
    answer_log->header = *dnh;
    pos = adns_qname_to_str_fast((const uint8_t *) (dnh + 1),
            answer_log->domain_name_a);
    answer_log->zname_offset = zname_offset;
    answer_log->qtype = adns_wire_read_u16(pos);
    answer_log->qclass = adns_wire_read_u16(pos + 2);
    //answer_log->has_cookie = 0;
    //answer_log->do_dnssec = 0;
    if (has_ecs) {
        answer_log->has_ecs = 1;
        answer_log->has_edns = 1;
    } else {
        answer_log->has_ecs = 0;
        answer_log->has_edns = 0;
    }
    answer_log->cur_tsc = rte_rdtsc();
    answer_log->is_from_kni = (uint8_t)is_from_kni;
    answer_log->is_tcp = (uint8_t)is_tcp;
    answer_log->action = LOG_ACTION_ANSWER;
    // TODO: Add correct type later.
    answer_log->srv_type = srv_type;
    //fill the query_log end

    return lmsg;
}

static inline log_msg_t* __attribute__ ((always_inline))
fill_secure_log_data(union common_ip_head *ip_head,
		union common_l4_head *l4_hdr, int is_tcp, int is_from_kni, int is_ipv6,
		uint32_t view_id, struct dns_header *dnh, int has_ecs, uint8_t srv_type,
		uint8_t zname_offset, uint32_t uid) {
	struct log_msg *lmsg;

	lmsg = fill_answer_log_data(ip_head, l4_hdr, is_tcp, is_from_kni, is_ipv6,
			view_id, dnh, has_ecs, srv_type, zname_offset);
	if (lmsg != NULL) {
		answer_log_data_t *answer_log = (answer_log_data_t*) lmsg->data;
		answer_log->uid = uid;
	}

	return lmsg;
}

static inline log_msg_t * __attribute__ ((always_inline))
fill_exceed_qps_log_data(EXCEED_QPS_TYPE_T type, struct dns_packet *packet,
        uint32_t dnssec_qps_quota) {
    struct log_msg * lmsg;
    exceed_qps_log_data_t * qps_limit_log;

    lmsg = log_alloc();
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

char * query_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size);
char * answer_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size);
char * secure_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size);

char * exceed_qps_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size);

static inline void __attribute__ ((always_inline))
log_query_info(union common_ip_head *ip_head, union common_l4_head *l4_hdr,
        int is_tcp, int is_from_kni, struct dns_packet *packet, int action) {
    if (rte_ring_free_count(g_log_rings[rte_lcore_id()]) > 0) {
        DLOG(QUERY, INFO, query_fmt,
                fill_query_log_data(ip_head, l4_hdr, is_tcp, is_from_kni, packet, action));
    }
}

static inline void __attribute__ ((always_inline)) log_answer_info(
		union common_ip_head *ip_head, union common_l4_head *l4_hdr, int is_tcp,
		int is_from_kni, int is_ipv6, uint32_t view_id, struct dns_header *dnh,
		int has_ecs, uint8_t srv_type, uint8_t zname_offset) {
	if (rte_ring_free_count(g_log_rings[rte_lcore_id()]) > 0) {
		// TODO: support ipv6 src in vip judging
		if (unlikely(
				!is_ipv6 && vip_judge(ip_head->ipv4_hdr.src_addr))) {
			fwd_user_t *user_info;

			user_info = fwd_ip_user_tbl_lookup_v4_fast(
					ip_head->ipv4_hdr.src_addr);
			if (user_info != NULL && user_info->status == USER_STATUS_SERVING) {
				DLOG(SECURE, INFO, secure_fmt,
						fill_secure_log_data(ip_head, l4_hdr, is_tcp,
								is_from_kni, is_ipv6, view_id, dnh, has_ecs,
								srv_type, zname_offset, user_info->user_id));
				return;
			}
		}

		DLOG(ANSWER, INFO, answer_fmt,
				fill_answer_log_data(ip_head, l4_hdr, is_tcp, is_from_kni,
						is_ipv6, view_id, dnh, has_ecs, srv_type, zname_offset));
	}
}


#endif
