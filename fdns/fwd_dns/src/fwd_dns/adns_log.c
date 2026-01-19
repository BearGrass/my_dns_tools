#include <stdint.h>
#include <stdio.h>


#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include "rte_core.h"

#include "descriptor.h"
#include "consts.h"
#include "wire.h"
#include "net_debug.h"
#include "dns_pkt.h"
#include "adns_log.h"
#include "qtype.h"
#include "view.h"

const char *g_srv_type_string[SRV_TYPE_NUM] = {
        [SRV_TYPE_REC] = "rec",
        [SRV_TYPE_AUTH] = "auth",
        [SRV_TYPE_SEC] = "sec",
};

inline char *
query_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size) {
    int ret_sz = 0;
    struct tm tm;
    struct timeval tv_res;

    answer_log_data_t *answer_log = (answer_log_data_t *) data;

    calculate_timestamp(&tv_res, lcore_id, answer_log->cur_tsc);
    localtime_r((const time_t *)&(tv_res.tv_sec), &tm);
    ret_sz += snprintf(answer_log->msg+ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
                "%04d-%02d-%02d %02d:%02d:%02d.%ld [%s]: ", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv_res.tv_usec/1000,
                log_level_str[LOG_INFO]);

    if (4 == answer_log->ip_ver)
        ret_sz += snprintf(answer_log->msg+ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
                "%d.%d.%d.%d %u > %d.%d.%d.%d %u, qname: %s, zname: %s, ",
                NIPQUAD(answer_log->sip), adns_ntohs(answer_log->sport),
                NIPQUAD(answer_log->dip), adns_ntohs(answer_log->dport),
                answer_log->domain_name_a,
                answer_log->zname_offset == ADNS_DNAME_MAXLEN ?
                        "NULL" :answer_log->domain_name_a + answer_log->zname_offset);
    else
        ret_sz += snprintf(answer_log->msg+ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
                NIP6_FMT " %u > " NIP6_FMT " %u, qname: %s, zname: %s, ",
                NIP6(answer_log->sip6), adns_ntohs(answer_log->sport),
                NIP6(answer_log->dip6), adns_ntohs(answer_log->dport),
                answer_log->domain_name_a,
                answer_log->zname_offset == ADNS_DNAME_MAXLEN ?
                        "NULL" :answer_log->domain_name_a + answer_log->zname_offset);
    ret_sz +=
            snprintf(answer_log->msg + ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
                    //"id: %u, qtype: %s, qclass: %u, view: %s, edns: %u, ecs: %u, cookie: %u, dnssec: %u, kni: %u, tcp: %u, drop: %u\n",
                    "id: %u, qtype: %s, qclass: %u, view: %s, edns: %u, ecs: %u, kni: %u, tcp: %u, action: %u, stype: %s\n",
                    adns_ntohs(answer_log->header.id), QT(answer_log->qtype),
                    answer_log->qclass, view_id_to_name(answer_log->cli_view),
                    answer_log->has_edns, answer_log->has_ecs,
                    /*answer_log->has_cookie, answer_log->do_dnssec,*/
                    answer_log->is_from_kni, answer_log->is_tcp,
                    answer_log->action, g_srv_type_string[answer_log->srv_type]);
    *size = (uint16_t) ret_sz;

    return answer_log->msg;
}

char *
answer_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size) {
    answer_log_data_t *answer_log = (answer_log_data_t *) data;

    query_fmt(lcore_id, data, size);
    // erase the last '\n'
    (*size)--;
    *size += snprintf(answer_log->msg + *size,
            ANSWER_LOG_DATA_MSG_SIZE-*size,
            ", rcode: %u, is_tc:%d, answer: %u, authority: %u, additional: %u\n",
            answer_log->header.flags2 & LDNS_WIRE_RCODE_MASK,
            ldns_wire_get_tc((uint8_t * )&answer_log->header),
            adns_ntohs(answer_log->header.ancount),
            adns_ntohs(answer_log->header.nscount),
            adns_ntohs(answer_log->header.arcount));
    return answer_log->msg;
}

char *
secure_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size) {
	int ret_sz = 0;
	struct tm tm;
	struct timeval tv_res;

	answer_log_data_t *answer_log = (answer_log_data_t*) data;

	calculate_timestamp(&tv_res, lcore_id, answer_log->cur_tsc);
	localtime_r((const time_t*) &(tv_res.tv_sec), &tm);
	ret_sz += snprintf(answer_log->msg + ret_sz,
			ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
			"%04d-%02d-%02d %02d:%02d:%02d.%ld [%s]: ", tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			tv_res.tv_usec, log_level_str[LOG_INFO]);

	if (4 == answer_log->ip_ver)
		ret_sz += snprintf(answer_log->msg + ret_sz,
				ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
				"%d.%d.%d.%d %u > %d.%d.%d.%d %u, ", NIPQUAD(answer_log->sip),
				adns_ntohs(answer_log->sport), NIPQUAD(answer_log->dip),
				adns_ntohs(answer_log->dport));
	else
		ret_sz += snprintf(answer_log->msg + ret_sz,
				ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
				NIP6_FMT " %u > " NIP6_FMT " %u, ", NIP6(answer_log->sip6),
				adns_ntohs(answer_log->sport), NIP6(answer_log->dip6),
				adns_ntohs(answer_log->dport));

	ret_sz +=
			snprintf(answer_log->msg + ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
					"pt: %s, uid: %u, qn: %s, id: %u, qt: %s, qc: %u, view: %s, edns: %u, ecs: %u, act: %u, rc: %u, tc: %u, an: %u, au: %u, ad: %u\n",
					answer_log->is_tcp ? "tcp" : "udp", answer_log->uid,
					answer_log->domain_name_a,
					adns_ntohs(answer_log->header.id), QT(answer_log->qtype),
					answer_log->qclass, view_id_to_name(answer_log->cli_view),
					answer_log->has_edns, answer_log->has_ecs,
					answer_log->action,
					answer_log->header.flags2 & LDNS_WIRE_RCODE_MASK,
					ldns_wire_get_tc((uint8_t* )&answer_log->header),
					adns_ntohs(answer_log->header.ancount),
					adns_ntohs(answer_log->header.nscount),
					adns_ntohs(answer_log->header.arcount));
	*size = (uint16_t) ret_sz;

	return answer_log->msg;
}

char *
exceed_qps_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size)
{
    int ret_sz = 0;
    struct tm tm;
    struct timeval tv_res;

    exceed_qps_log_data_t *qps_limit_log = (exceed_qps_log_data_t *)data;

    calculate_timestamp(&tv_res, lcore_id, qps_limit_log->cur_tsc);
    localtime_r((const time_t *)&(tv_res.tv_sec), &tm);
    ret_sz += snprintf(qps_limit_log->msg + ret_sz, EXCEED_QPS_LOG_DATA_MSG_SIZE - ret_sz,
                "%04d-%02d-%02d %02d:%02d:%02d.%ld"" lcore:%u ", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv_res.tv_usec/1000, lcore_id);

    if (4 == qps_limit_log->ip_ver)
        ret_sz += snprintf(qps_limit_log->msg + ret_sz, EXCEED_QPS_LOG_DATA_MSG_SIZE - ret_sz,
                "%d.%d.%d.%d, qname: %s, ",
                NIPQUAD(qps_limit_log->sip), qps_limit_log->domain_name_a);
    else
        ret_sz += snprintf(qps_limit_log->msg + ret_sz, EXCEED_QPS_LOG_DATA_MSG_SIZE - ret_sz,
                NIP6_FMT ", qname: %s, ",
                NIP6(qps_limit_log->sip6), qps_limit_log->domain_name_a);

    switch (qps_limit_log->type) {
        case EXCEED_DNSSEC_QPS_SRC_IP:
            ret_sz += snprintf(qps_limit_log->msg + ret_sz, EXCEED_QPS_LOG_DATA_MSG_SIZE - ret_sz,
                "src_ip_dnssec qos: %u\n", qps_limit_log->qps_limit_quota);
            break;

        case EXCEED_DNSSEC_QPS_ZONE:
            ret_sz += snprintf(qps_limit_log->msg + ret_sz, EXCEED_QPS_LOG_DATA_MSG_SIZE - ret_sz,
                "zone_dnssec qos: %u\n", qps_limit_log->qps_limit_quota);
            break;

        case EXCEED_DNSSEC_QPS_GLOBAL:
            ret_sz += snprintf(qps_limit_log->msg + ret_sz, EXCEED_QPS_LOG_DATA_MSG_SIZE - ret_sz,
                "dnssec qos: %u\n", qps_limit_log->qps_limit_quota);
            break;
        default:
            break;
    }

    *size = (uint16_t) ret_sz;
    return qps_limit_log->msg;
}
