#ifndef _ADNS_STATS_H_
#define _ADNS_STATS_H_


#include <stdint.h>
#include <rte_memory.h>
#include <rte_lcore.h>


#define STATS_ADD(name, num) \
	do {	\
		int lcore_id = rte_lcore_id();	\
		gstats[lcore_id].name += num;	\
	} while (0)


#define STATS_INC(name) \
	do {	\
		int lcore_id = rte_lcore_id();	\
		gstats[lcore_id].name++;	\
	} while (0)


#define STATS_SUB(name, num) \
	do {	\
		int lcore_id = rte_lcore_id();	\
		gstats[lcore_id].name -= num;	\
	} while (0)


#define STATS_DEC(name) \
	do {	\
		int lcore_id = rte_lcore_id();	\
		gstats[lcore_id].name--;	\
	} while (0)


/* stats */
struct adns_stats {
    uint64_t qps;
    uint64_t query;
    uint64_t answer;
    uint64_t edns;
    uint64_t edns_badvers;              /* EDNS BADVERS query */
    uint64_t edns_unknown_opt;          /* EDNS unknown option query */
    uint64_t dnssec;                    /* DNSSEC query */
    uint64_t dnssec_ans;                /* DNSSEC response */
    uint64_t dnssec_qps;                /* DNSSEC QPS */
    uint64_t dnssec_cache_hit;          /* DNSSEC cache hit total count */
    uint64_t dnssec_cache_expire;       /* DNSSEC cache expire count */
    uint64_t dnssec_cache_qps;          /* DNSSEC cache hit qps */
    uint64_t dnssec_cache_new_err;      /* DNSSEC cache allocation error */
    uint64_t dnssec_cache_msg_send_err; /* DNSSEC cache msg send error */
    uint64_t ecs;
    uint64_t cookie;
    uint64_t kni;
    uint64_t drop;
    uint64_t ipv4;
    uint64_t ipv6;
    uint64_t fragment_out;
    uint64_t tcp_in;
    uint64_t tcp_in_53;
    uint64_t tcp_in_53_drop;
    uint64_t log_server_fail;
    uint64_t log_query_fail;
    uint64_t log_answer_fail;
    uint64_t log_query_statis_fail;
    uint64_t rcu_cnt;
    uint64_t rcu_qps;
} __attribute__((__aligned__(64)));
typedef struct adns_stats adns_stats_t;

extern struct adns_stats *gstats;


void adns_stats_sum(struct adns_stats *st);
void adns_tcpstats_sum(struct adns_stats *st);
void adns_stats_qps(int second);
int adns_stats_init(void);
void adns_stats_cleanup(void);


#endif


