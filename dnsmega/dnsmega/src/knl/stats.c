/*
 * Copyright (C)
 * Filename: stats.c
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 * show all mega stats.
 */

#include <linux/proc_fs.h>
#include <linux/seq_file_net.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/cpumask.h>
#include <linux/threads.h>
#include <linux/string.h>
#include "stats.h"
#include "util.h"
#include "control.h"

#ifdef CONFIG_PROC_FS

struct dm_estats_mib *dm_esmib;

static struct dm_mib mib_stats[] = {
    DM_MIB_ITEM("accept_local_in_l3", DM_ACCEPT_LOCAL_IN_L3),
    DM_MIB_ITEM("accept_local_in_l4", DM_ACCEPT_LOCAL_IN_L4),
    DM_MIB_ITEM("accept_local_in_l7", DM_ACCEPT_LOCAL_IN_L7),
    DM_MIB_ITEM("accept_linearize_in", DM_ACCEPT_LINEARIZE_IN),
    //DM_MIB_ITEM("accept_loopback_in", DM_ACCEPT_LOOPBACK_IN),
    DM_MIB_ITEM("accept_local_out_l3", DM_ACCEPT_LOCAL_OUT_L3),
    DM_MIB_ITEM("accept_local_out_l4", DM_ACCEPT_LOCAL_OUT_L4),
    DM_MIB_ITEM("accept_local_out_l7", DM_ACCEPT_LOCAL_OUT_L7),
    DM_MIB_ITEM("accept_linearize_out", DM_ACCEPT_LINEARIZE_OUT),
    DM_MIB_ITEM("accept_loopback_out", DM_ACCEPT_LOOPBACK_OUT),
    DM_MIB_ITEM("accept_nosupport", DM_ACCEPT_NOSUPPORT),
    DM_MIB_ITEM("drop_ip_ratelimit", DM_DROP_SINGLEIP_RATELIMIT),
    DM_MIB_ITEM("drop_ip_rec_ratelimit", DM_DROP_REC_RATELIMIT),
    DM_MIB_ITEM("drop_pac_incomplete", DM_DROP_PAC_INCOMPLETE),
    DM_MIB_ITEM("drop_pac_oversize", DM_DROP_PAC_OVERSIZE),
    DM_MIB_ITEM("drop_parse_error", DM_DROP_PARSE_ERROR),
    DM_MIB_ITEM("drop_waitlist_full", DM_DROP_WAITLIST_FULL),
    DM_MIB_ITEM("drop_forward_ratelimit", DM_DROP_FORWARD_RATELIMIT),
    DM_MIB_ITEM("drop_nomem_request", DM_DROP_NOMEM_REQUEST),
    DM_MIB_ITEM("drop_genpac_error", DM_DROP_GENPAC_ERROR),
    DM_MIB_ITEM("drop_hold_timeout", DM_DROP_HOLD_TIMEOUT),
    DM_MIB_ITEM("drop_same_request", DM_DROP_SAME_REQUEST),
    DM_MIB_ITEM("request_in", DM_REQUEST_IN),
    DM_MIB_ITEM("request_out", DM_REQUEST_OUT),
    DM_MIB_ITEM("request_hit", DM_REQUEST_HIT),
    DM_MIB_ITEM("request_hold", DM_REQUEST_HOLD),
    DM_MIB_ITEM("request_prefetch", DM_REQUEST_PREFETCH),
    DM_MIB_ITEM("request_recursive", DM_REQUEST_REC),
    DM_MIB_ITEM("cache_expired", DM_CACHE_EXPIRED),
    DM_MIB_ITEM("error_nomem_request", DM_ERROR_NOMEM_REQUEST),
    DM_MIB_ITEM("error_nomen_skb", DM_ERROR_NOMEM_SKB),
    DM_MIB_ITEM("error_big_append", DM_ERROR_BIG_APPEND),
    DM_MIB_ITEM("error_waitlist", DM_ERROR_WAITLIST),
    DM_MIB_ITEM("error_update_rt", DM_ERROR_UPDATE_RT),
    DM_MIB_ITEM("error_response_no_cache", DM_ERROR_RESPONSE_NO_CACHE),
    DM_MIB_ITEM("error_nomem_node", DM_ERROR_NOMEM_NODE),
    DM_MIB_ITEM("error_nomem_node_val", DM_ERROR_NOMEM_NODE_VAL),
    DM_MIB_ITEM("error_nomem_node_key", DM_ERROR_NOMEM_NODE_KEY),
    DM_MIB_ITEM("error_recursive_noanswer", DM_ERROR_RECURSIVE_NOANS),
    DM_MIB_ITEM("fwd_logic_response", DM_FWD_LOGIC_RESPONSE),
    DM_MIB_ITEM("fwd_real_response", DM_FWD_REAL_RESPONSE),
    DM_MIB_ITEM("fwd_real_timeout", DM_FWD_REAL_TIMEOUT),
    DM_MIB_ITEM("fwd_queries", DM_FWD_QUERIES),
    //以上是counters
    //以下是stats

    DM_MIB_ITEM("cache_with_answer_num", DM_CACHE_WITH_ANSWER_NUM),
    DM_MIB_ITEM("cache_without_answer_num", DM_CACHE_WITHOUT_ANSWER_NUM),
    DM_MIB_ITEM("wait_request_num", DM_WAIT_REQUEST_NUM),

    DM_MIB_LAST,
};

/*
 * add all online cpus' stats entry.
 */
long fold_field(const struct dm_estats_mib *mib, int stats_num)
{
    long res = 0;
    int i;
    for_each_online_cpu(i) {
        res += per_cpu_ptr(mib, i)->mibs[stats_num];
    }
    return res;
}

void dm_estats_clear(struct dm_estats_mib *mib, int stats_entry)
{
    int i, j;
    for (i = 0; i < DM_FWD_QUERIES; i++) {
        if (mib_stats[i].entry == stats_entry) {
            for_each_online_cpu(j) {
                per_cpu_ptr(mib, j)->mibs[mib_stats[i].entry] = 0;
            }
        }
    }
}

static void show(int start, int end, struct seq_file *m, int *len)
{
    int i = 0;
    while(1) {
        if (mib_stats[i].entry == start) break;
        i ++;
    }
    *len = 0;
    while (NULL != mib_stats[i].name) {
        *len += seq_printf(m + *len, "%-25s:", mib_stats[i].name);
        /* assume qps is 10M, counter will work 317 years until exceed width 17 */
        *len +=
            seq_printf(m + *len, "%17ld\n",
                    fold_field(dm_esmib, mib_stats[i].entry));
        i++;
        if (mib_stats[i].entry == end)
            break;
    }
}


int dm_estats_show(struct seq_file *m, void *v)
{
    int len;
    show(DM_CACHE_WITH_ANSWER_NUM, -1, m, &len);
    return len;
}

int dm_counters_show(struct seq_file *m, void *v)
{
    int len;
    show(DM_ACCEPT_LOCAL_IN_L3, DM_CACHE_WITH_ANSWER_NUM, m, &len);
    return len;
}

int dm_stats_init(void)
{
    int i;
    if ((dm_esmib = alloc_percpu(struct dm_estats_mib)) == NULL) {
        pr_err("cannot allocate percpu struct dm_estats_mib\n");
        return -1;
    }
    for (i = 0; i < __DM_STAT_MAX; i++) {
        per_cpu_ptr(dm_esmib, smp_processor_id())->mibs[i] = 0;
    }
    pr_info("DNS Mega stats initialization successful\n");
    return 0;
}

void dm_stats_exit(void)
{
    free_percpu(dm_esmib);
    pr_info("DNS Mega stats exit successful\n");
}

#endif                          /* CONFIG_PROC_FS */
