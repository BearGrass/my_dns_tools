/*
 * qos.h
 *
 *  Created on: 2019年12月2日
 *      Author: mogu.lwp
 */

#ifndef FWD_DNS_SRC_FWD_DNS_QOS_H_
#define FWD_DNS_SRC_FWD_DNS_QOS_H_

#include <stdint.h>
#include <stdlib.h>
#include <rte_atomic.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_cycles.h>
#include "dns_pkt.h"
#include "fwd_type.h"
#include "common.h"
#include "net_debug.h"


#define IPPROTO_OSPF     89
#define PROTO_BGP_BE     45824 /* htons(179) */
#define PROTO_DOHS_BE    47873 /* htons(443) */
#define PROTO_DOH_BE     20480 /* htons(80) */
#define PROTO_DOT_BE     21763 /* htons(853) */
#define IPLIMIT_SIZE    (1 << 25)

uint64_t TSC_HZ;
uint64_t TSC_100MS;

// single core QPS limit function
typedef struct qps_limit_st{
        uint64_t        check_cycle;
        int32_t         tokens;
        uint8_t         is_print;
} qps_limit_st_t;

extern qps_limit_st_t kni_limit_tbl[FWD_QPSLIMIT_MAX_NUM];
extern uint32_t    g_fwd_qps_limit_on[FWD_QPSLIMIT_MAX_NUM];
extern uint32_t    g_fwd_qps_quota[FWD_QPSLIMIT_MAX_NUM];
extern char *qpslimit_id_name_map[];
extern uint8_t g_kni_qps_limit_on_status;
extern qps_limit_st_t *fwd_ip_limit_tbl[RTE_MAX_LCORE];


int fwd_qps_limit_init();


static inline int
rate_proc(qps_limit_st_t *lim, int qps, uint8_t *print)
{
    uint64_t now, check_cycle;
    int64_t diff, toks;

    now = rte_rdtsc();
    check_cycle = lim->check_cycle;
    /* The rdtsc is not synchronized on different cores, so maybe
     * the now is less than check_cycle
     */
    diff = now - check_cycle;

    if(diff < TSC_100MS) {
        goto xmit;
    }

    toks = (diff * qps) / TSC_HZ + lim->tokens;
    if (toks > qps) {
        lim->tokens = qps;
    } else {
        lim->tokens = (int32_t)toks;
    }
    lim->check_cycle = now;
    lim->is_print = 1;

xmit:
    *print = 0;
    // 同一个vpc的包可能命中不同核，导致tokens可能是负数，所以改成int64_t类型
    if(lim->tokens > 0){
        lim->tokens--;
        return 1;
    }

    // 在超过一个周期时打印log，周期内再继续超过的不再打印
    if (lim->is_print) {
        lim->is_print = 0;
        *print = 1;
    }
    return 0;
}

static inline int __attribute__ ((always_inline))
ipv4_pass(uint32_t sip, int qps) {
    uint8_t print = 0;
    uint32_t index = rte_jhash_1word(sip, 0) % IPLIMIT_SIZE;

	if (!rate_proc(fwd_ip_limit_tbl[rte_lcore_id()] + index, qps, &print)) {
        if (unlikely(print)) {
            ALOG(SERVER, WARN, "FWD QOS: drop packet on IPv4 %d.%d.%d.%d\n",
                    NIPQUAD(sip));
        }
        return IO_RET_DROP;
    }

    return IO_RET_PASS;
}

static inline int __attribute__ ((always_inline))
ipv6_pass(uint8_t *sip6, int qps) {
    uint8_t print = 0;
    uint32_t index = rte_jhash(sip6, 16, 0) % IPLIMIT_SIZE;

	if (!rate_proc(fwd_ip_limit_tbl[rte_lcore_id()] + index, qps, &print)) {
        if (unlikely(print)) {
            ALOG(SERVER, WARN, "FWD QOS: drop packet on IPv6 " NIP6_FMT "\n",
                    NIP6(sip6));
        }
        return IO_RET_DROP;
    }

    return IO_RET_PASS;
}

static inline int __attribute__ ((always_inline))
kni_pass(uint8_t num)
{
    uint8_t print = 0;
    if (!rate_proc(kni_limit_tbl + num, g_fwd_qps_quota[num], &print)) {
        if (unlikely(print)) {
            ALOG(SERVER, WARN, "KNI QOS: drop [%s] packet\n",
                    qpslimit_id_name_map[num]);
        }
        return IO_RET_DROP;
    }

    return IO_RET_PASS;
}

#endif /* FWD_DNS_SRC_FWD_DNS_QOS_H_ */
