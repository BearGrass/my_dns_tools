#ifndef _RING_LIST_H_
#define _RING_LIST_H_

#include <rte_memory.h>

#define QUERY_STA_SEND_INTERVAL (g_syslog_ctl.sta_send_interval * 60 * HZ)
#define QUERY_STA_BURST_SLOT (QUERY_STA_SEND_INTERVAL / (g_syslog_ctl.estimated_domain_num / QUERY_STA_BURST_CNT) )
#define QUERY_STA_BURST_CNT (32)

struct rlist_head
{
  struct rlist_head *next;
};

struct query_sta_list {
    volatile struct rlist_head *rtail;
    volatile uint32_t node_num; // not thread safe, just for reference
} __rte_cache_aligned;
extern struct query_sta_list g_sta_list[RTE_MAX_LCORE];

int rlist_add_tail(struct rlist_head * newly_added, int io_core_id);

int rlist_iterate(int io_core_id);

#endif
