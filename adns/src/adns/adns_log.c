#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>


#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include "rte_core.h"

#include "adns.h"
#include "descriptor.h"
#include "consts.h"
#include "wire.h"
#include "datapath.h"
#include "net_debug.h"
#include "dns_pkt.h"
#include "adns_stats.h"
#include "adns_conf.h"
#include "common_value.h"
#include "adns_counter.h"
#include "adns_log.h"

char * 
answer_fmt(uint32_t lcore_id, uint8_t *data, uint16_t *size) {
    int ret_sz = 0;
    struct tm tm;
    struct timeval tv_res;

    answer_log_data_t *answer_log = (answer_log_data_t *) data;

    calculate_timestamp(&tv_res, lcore_id, answer_log->cur_tsc);
    localtime_r((const time_t *)&(tv_res.tv_sec), &tm);
    ret_sz += snprintf(answer_log->msg+ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz, 
                "%04d-%02d-%02d %02d:%02d:%02d.%ld"" [%s]: ", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv_res.tv_usec/1000,
                log_level_str[DNS_LOG_INFO]);

    if (4 == answer_log->ip_ver) 
        ret_sz += snprintf(answer_log->msg+ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
                NIPQUAD_FMT ":%u->" NIPQUAD_FMT ":%u, qname: %s, ",
                NIPQUAD(answer_log->sip), adns_ntohs(answer_log->sport), NIPQUAD(answer_log->dip), adns_ntohs(answer_log->dport), answer_log->domain_name_a); 
    else
        ret_sz += snprintf(answer_log->msg+ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,  
                NIP6_FMT ":%u->" NIP6_FMT ":%u, qname: %s, ",
                NIP6(answer_log->sip6), adns_ntohs(answer_log->sport),
                NIP6(answer_log->dip6), adns_ntohs(answer_log->dport),
                answer_log->domain_name_a);
    ret_sz += snprintf(answer_log->msg+ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
                "qtype: %u, client_view: %s, view: %s, ecs: %u, cookie: %u, dnssec: %u, id: %u, ret: %d, ",
                answer_log->qtype, answer_log->cli_view_name, answer_log->view_name, answer_log->has_ecs, answer_log->has_cookie, answer_log->dnssec, adns_ntohs(answer_log->dns_id), answer_log->ret);

    if (!answer_log->ret)
        ret_sz += snprintf(answer_log->msg+ret_sz, ANSWER_LOG_DATA_MSG_SIZE-ret_sz,
                "rcode: %u, answer: %u, authority: %u, additional: %u\n",
                answer_log->flags2 & ADNS_WIRE_RCODE_MASK, adns_ntohs(answer_log->ancount), adns_ntohs(answer_log->nscount), adns_ntohs(answer_log->arcount));

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
                NIPQUAD_FMT ", qname: %s, ",
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
