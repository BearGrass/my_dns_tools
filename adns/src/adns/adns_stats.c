#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "utili_base.h"
#include "adns_stats.h"


struct adns_stats * gstats;
static uint64_t query_prev = 0;
static uint64_t qps = 0;
static uint64_t query_prev_tcp = 0;
static uint64_t qps_tcp = 0;
static uint64_t prev_rcu = 0;
static uint64_t qps_rcu = 0;
static uint64_t qps_dnssec = 0;
static uint64_t dnssec_prev = 0;
static uint64_t dnssec_cache_prev = 0;
static uint64_t dnssec_cache_qps = 0;

extern int adns_istcpcore(int i);

void adns_stats_sum(struct adns_stats *st)
{
	int i;

	memset(st, 0, sizeof(struct adns_stats));
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		st->query += gstats[i].query;
		st->answer += gstats[i].answer;
		st->edns += gstats[i].edns;
		st->edns_badvers += gstats[i].edns_badvers;
		st->edns_unknown_opt += gstats[i].edns_unknown_opt;
		st->dnssec += gstats[i].dnssec;
		st->dnssec_ans += gstats[i].dnssec_ans;
		st->dnssec_cache_hit += gstats[i].dnssec_cache_hit;
		st->dnssec_cache_expire += gstats[i].dnssec_cache_expire;
		st->dnssec_cache_new_err += gstats[i].dnssec_cache_new_err;
		st->dnssec_cache_msg_send_err += gstats[i].dnssec_cache_msg_send_err;
		st->ecs += gstats[i].ecs;
		st->cookie += gstats[i].cookie;
        st->kni += gstats[i].kni;
		st->drop += gstats[i].drop;
		st->ipv4 += gstats[i].ipv4;
		st->ipv6 += gstats[i].ipv6;
        st->fragment_out += gstats[i].fragment_out;
        st->tcp_in += gstats[i].tcp_in;
        st->tcp_in_53 += gstats[i].tcp_in_53;
        st->tcp_in_53_drop += gstats[i].tcp_in_53_drop;
        st->log_server_fail += gstats[i].log_server_fail;
        st->log_query_fail += gstats[i].log_query_fail;
        st->log_answer_fail += gstats[i].log_answer_fail;
        st->log_query_statis_fail += gstats[i].log_query_statis_fail;
	}
	st->qps = qps;
	st->dnssec_qps = qps_dnssec;
	st->dnssec_cache_qps = dnssec_cache_qps;
	st->rcu_qps = qps_rcu;
}

void adns_tcpstats_sum(struct adns_stats *st)
{
	int i;

	memset(st, 0, sizeof(struct adns_stats));
	for (i = 0; i < RTE_MAX_LCORE; i++) {
        if (0== adns_istcpcore(i))
            continue;
		st->query += gstats[i].query;
		st->answer += gstats[i].answer;
		st->edns += gstats[i].edns;
		st->edns_badvers += gstats[i].edns_badvers;
		st->edns_unknown_opt += gstats[i].edns_unknown_opt;
		st->ecs += gstats[i].ecs;
		st->cookie += gstats[i].cookie;
        st->kni += gstats[i].kni;
		st->drop += gstats[i].drop;
		st->ipv4 += gstats[i].ipv4;
		st->ipv6 += gstats[i].ipv6;
        st->fragment_out += gstats[i].fragment_out;
        st->tcp_in += gstats[i].tcp_in;
        st->tcp_in_53 += gstats[i].tcp_in_53;
        st->tcp_in_53_drop += gstats[i].tcp_in_53_drop;
        st->log_server_fail += gstats[i].log_server_fail;
        st->log_query_fail += gstats[i].log_query_fail;
        st->log_answer_fail += gstats[i].log_answer_fail;
        st->log_query_statis_fail += gstats[i].log_query_statis_fail;
	}
	st->qps = qps_tcp;
}

void adns_stats_qps(int second)
{
	int i;
	uint64_t total = 0;
	uint64_t tcp_total = 0;
	uint64_t dnssec_total = 0;
	uint64_t dnssec_cache_total = 0;
	uint64_t rcu_total = 0;

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		total += gstats[i].query;
		if (adns_istcpcore(i) == 1) {
			tcp_total += gstats[i].query;
		}
		dnssec_total += gstats[i].dnssec_ans;
		dnssec_cache_total += gstats[i].dnssec_cache_hit;
	}

    rcu_total = gstats[0].rcu_cnt;
	qps = (total - query_prev) / second;
	query_prev = total;
	qps_dnssec = (dnssec_total - dnssec_prev) / second;
	dnssec_prev = dnssec_total;
	qps_tcp = (tcp_total - query_prev_tcp) / second;
	query_prev_tcp = tcp_total;
	qps_rcu = (rcu_total - prev_rcu) / second;
	prev_rcu = rcu_total;
	dnssec_cache_qps = (dnssec_cache_total - dnssec_cache_prev) / second;
	dnssec_cache_prev = dnssec_cache_total;
}

int adns_stats_init(void)
{
	int i;
    int size = sizeof(struct adns_stats) * RTE_MAX_LCORE;

    gstats = rte_malloc(NULL, size, RTE_CACHE_LINE_SIZE);
    if (gstats == NULL) {
        fprintf(stderr, "[%s]: Failed to alloc memory for gstats table\n", __FUNCTION__);
        return -1;
    }

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		memset(&gstats[i], 0, sizeof(struct adns_stats));
	}

	return 0;
}


void adns_stats_cleanup(void)
{
}
