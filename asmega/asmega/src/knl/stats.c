/*
 * Copyright (C)
 * Filename: stats.c
 * Author:
 * mogu<mogu.lwp@alibaba-inc.com>
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

struct as_estats_mib *as_esmib;

static char *mib_stats_name[] = {
    [AS_ACCEPT_LOCAL_IN_L3] = "accept_local_in_l3",
    [AS_ACCEPT_LOCAL_IN_L4] = "accept_local_in_l4",
    [AS_ACCEPT_LOCAL_IN_L7] = "accept_local_in_l7",
    [AS_ACCEPT_LINEARIZE_IN] = "accept_linearize_in",
    [AS_ACCEPT_LOCAL_OUT_L3] = "accept_local_out_l3",
    [AS_ACCEPT_LOCAL_OUT_L4] = "accept_local_out_l4",
    [AS_ACCEPT_LOCAL_OUT_L7] = "accept_local_out_l7",
    [AS_ACCEPT_LINEARIZE_OUT] = "accept_linearize_out",
    [AS_ACCEPT_NOSUPPORT] = "accept_nosupport",
    [AS_ACCEPT_NOT_FIND_VIEW_ID] = "accept_not_find_view_id",
    [AS_STOLEN_NEW_SKB] = "stolen_new_skb",
    //[AS_NONSUP_MUL_ADD] = "nonsup_multi_addtions",
    [AS_NONSUP_OPCODE] = "nonsup_opcode",
    [AS_NONSUP_QUESTIONS] = "nonsup_qustions",
    [AS_NONSUP_CLASS] = "nonsup_class",
    //[AS_NONSUP_QR_WITH_AN_OR_AU] = "nonsup_qr_with_an_or_au",
    [AS_DROP_LOCAL_IN_L7] = "drop_local_in_l7",
    [AS_DROP_PAC_INCOMPLETE] = "drop_pac_incomplete",
    [AS_DROP_PARSE_ERROR] = "drop_parse_error",
    //[AS_DROP_EDNS_TO_WIRE] = "drop_edns_to_wire",
    [AS_DROP_PARSE_EDNS] = "drop_parse_edns_error",
    [AS_DROP_QR_WITH_PVT_EDNS] = "as_drop_qr_with_pvt_edns",
    [AS_REQUEST_IN] = "request_in",
    [AS_REQUEST_OUT] = "request_out",
    [AS_REQUEST_MEM_MOV] = "request_mem_mov",
    [AS_ANSWER_MEM_MOV] = "answer_mem_mov",
    [AS_ERROR_DATAGRAM_SMALL] = "error_datagram_small",
    [AS_ERROR_NOMEM_REQUEST] = "error_nomem_request",
    [AS_ERROR_ILLEGAL_DNAME_LEN] = "error_illegal_dname_len",
    //[AS_ERROR_ADDITION_NUM] = "error_addtion_num",
    [AS_ERROR_EDNS_TYPE] = "error_edns_type",
    [AS_ERROR_EDNS_VERSION] = "error_edns_version",
    [AS_ERROR_EDNS_LEN] = "error_edns_edns_len",
    [AS_ERROR_NOMEM_SKB] = "error_nomen_skb",
};

/*
 * add all online cpus' stats entry.
 */
long fold_field(const struct as_estats_mib *mib, int stats_idx)
{
    long res = 0;
    int i;
    for_each_online_cpu(i) {
        res += per_cpu_ptr(mib, i)->mibs[stats_idx];
    }
    return res;
}

void as_estats_clear(struct as_estats_mib *mib, int start, int end)
{
    int i, j;

    for (i = start; i < end; i++) {
        for_each_online_cpu(j) {
            per_cpu_ptr(mib, j)->mibs[i] = 0;
        }
    }
}

static void show(int start, int end, struct seq_file *m, int *len)
{
    int i;

    *len = 0;

    for (i = start; i < end; i++) {
        *len += seq_printf(m + *len, "%-25s:", mib_stats_name[i]);
        /* assume qps is 10M, counter will work 317 years until exceed width 17 */
        *len +=
            seq_printf(m + *len, "%17ld\n", fold_field(as_esmib, i));
    }
}

int as_counters_show(struct seq_file *m, void *v)
{
    int len;
    show(AS_COUNTERS_START, AS_COUNTERS_END, m, &len);
    return len;
}

int as_stats_init(void)
{
    int i;
    if ((as_esmib = alloc_percpu(struct as_estats_mib)) == NULL) {
        pr_err("cannot allocate percpu struct as_estats_mib\n");
        return -1;
    }
    for (i = AS_COUNTERS_START; i < AS_COUNTERS_END; i++) {
        per_cpu_ptr(as_esmib, smp_processor_id())->mibs[i] = 0;
    }
    pr_info("DNS asmega stats initialization successful\n");
    return 0;
}

void as_stats_exit(void)
{
    free_percpu(as_esmib);
    pr_info("DNS asmega stats exit successful\n");
}

#endif                          /* CONFIG_PROC_FS */
