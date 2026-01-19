#ifndef _QPS_LIMIT_H_
#define _QPS_LIMIT_H_

#include <stdint.h>
#include "adns_conf.h"
#include <rte_cycles.h>
#include <rte_jhash.h>
#include <rte_memory.h>

#define IPLIMIT_SIZE	(1 << 25)

extern uint64_t TSC_HZ;
extern uint64_t TSC_100MS;

extern struct qps_limit_st *dnssec_zone_limit_tbl;
extern struct qps_limit_st *dnssec_ip_limit_tbl;
extern struct qps_limit_st *dnssec_global_limit;
extern struct qps_limit_st *ip_limit_tbl;

extern uint32_t g_dnssec_qps_limit_on;
extern uint32_t g_dnssec_zone_qps_quota;
extern uint32_t g_dnssec_ip_qps_quota;
extern uint32_t g_dnssec_qps_quota;
extern int sysctl_tcp_in_53_drop;
extern int sysctl_tcp_in_53_rate;
extern int sysctl_tcp_in_53_quota;
extern int sysctl_tcp_in_53_total_quota;
extern int sysctl_tcp_in_53_total_pps_quota;

typedef struct qps_limit_st{
        uint64_t        check_cycle;
        int64_t         tokens;
        uint8_t         is_print;
} __rte_cache_aligned qps_limit_st_t;

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

	toks = (diff * qps) / TSC_HZ;
	lim->tokens += toks;
	lim->check_cycle = now;
	lim->is_print = 1;

	if(lim->tokens > qps)
		lim->tokens = qps;
xmit:
	*print = 0;
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
dnssec_zone_pass(uint8_t *qname, uint16_t name_len, int qps, uint8_t *print)
{
	uint32_t index = rte_jhash(qname, name_len, 0) % g_dnssec_zone_max_num;
	return rate_proc(dnssec_zone_limit_tbl + index, qps, print);
}

static inline int __attribute__ ((always_inline))
dnssec_ip_pass(uint32_t sip, int qps, uint8_t *print)
{
	uint32_t index = rte_jhash_1word(sip, 0) % IPLIMIT_SIZE;
	return rate_proc(dnssec_ip_limit_tbl + index, qps, print);
}

static inline int __attribute__ ((always_inline))
dnssec_pass(int qps, uint8_t *print)
{
	return rate_proc(dnssec_global_limit, qps, print);
}

static inline int __attribute__ ((always_inline))
kni_in_pps_pass(uint8_t *print)
{
	return rate_proc(ip_limit_tbl + IPLIMIT_SIZE + 1, sysctl_tcp_in_53_total_pps_quota, print);
}

int qps_limit_init();

#endif /* _QPS_LIMIT_H_ */
