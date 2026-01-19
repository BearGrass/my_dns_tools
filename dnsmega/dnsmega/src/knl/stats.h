/*
 * Copyright (C)
 * Filename: stats.h
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#ifndef __STATS_H__
#define __STATS_H__

#include <linux/percpu.h>
#include <linux/smp.h>

struct dm_mib {
    char *name;
    int entry;
};

#define DM_MIB_ITEM(_name, _entry) {	\
	.name = _name,			\
	.entry = _entry,		\
}

#define DM_MIB_LAST {	\
	.name = NULL,		\
	.entry = 0,		\
}

/* list of counters */
enum {
    DM_COUNTERS = 0,
    DM_ACCEPT_LOCAL_IN_L3,
    DM_ACCEPT_LOCAL_IN_L4,
    DM_ACCEPT_LOCAL_IN_L7,
    DM_ACCEPT_LINEARIZE_IN,
    //DM_ACCEPT_LOOPBACK_IN,

    DM_ACCEPT_LOCAL_OUT_L3,
    DM_ACCEPT_LOCAL_OUT_L4,
    DM_ACCEPT_LOCAL_OUT_L7,
    DM_ACCEPT_LINEARIZE_OUT,
    DM_ACCEPT_LOOPBACK_OUT,
    DM_ACCEPT_NOSUPPORT,

    DM_DROP_SINGLEIP_RATELIMIT,
    DM_DROP_REC_RATELIMIT,
    DM_DROP_PAC_INCOMPLETE,
    DM_DROP_PAC_OVERSIZE,
    DM_DROP_PARSE_ERROR,
    DM_DROP_WAITLIST_FULL,
    DM_DROP_FORWARD_RATELIMIT,
    DM_DROP_NOMEM_REQUEST,
    DM_DROP_GENPAC_ERROR,
    DM_DROP_HOLD_TIMEOUT,
    DM_DROP_SAME_REQUEST,

    DM_REQUEST_IN,
    DM_REQUEST_OUT,
    DM_REQUEST_HIT,
    DM_REQUEST_HOLD,
    DM_REQUEST_PREFETCH,
    DM_REQUEST_REC,

    DM_CACHE_EXPIRED,

    DM_ERROR_NOMEM_REQUEST,
    DM_ERROR_NOMEM_SKB,
    DM_ERROR_BIG_APPEND,
    DM_ERROR_WAITLIST,
    DM_ERROR_UPDATE_RT,
    DM_ERROR_RESPONSE_NO_CACHE,
    DM_ERROR_NOMEM_NODE,
    DM_ERROR_NOMEM_NODE_VAL,
    DM_ERROR_NOMEM_NODE_KEY,
    DM_ERROR_RECURSIVE_NOANS,

    DM_FWD_LOGIC_RESPONSE,
    DM_FWD_REAL_RESPONSE,
    DM_FWD_REAL_TIMEOUT,
    DM_FWD_QUERIES,
    /* above is counters,below is stats */

    DM_CACHE_WITH_ANSWER_NUM,
    DM_CACHE_WITHOUT_ANSWER_NUM,
    DM_WAIT_REQUEST_NUM,
    __DM_STAT_MAX,
};

/* counters like SNMP MIB */
struct dm_estats_mib {
    long mibs[__DM_STAT_MAX];
};

#define DM_INC_ESTATS(mib, field)		\
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)
#define DM_ADD_ESTATS(mib, field, val)	\
	((per_cpu_ptr(mib, smp_processor_id())->mibs[field]) += val)
#define DM_DEC_ESTATS(mib, field)		\
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]--)
#define DM_GET_ESTATS(mib, field)       \
    (per_cpu_ptr(mib, smp_processor_id())->mibs[field])

extern struct dm_estats_mib *dm_esmib;
/* count counters in all cpus
 * @mib struct of state counters
 * @stats_num number of state counters
 *
 * @return number of a counter
 * */
extern long fold_field(const struct dm_estats_mib *mib, int stats_num);
extern int dm_estats_show(struct seq_file *m, void *v);
extern int dm_counters_show(struct seq_file *m, void *v);

/* clear all counters */
extern void dm_estats_clear(struct dm_estats_mib *mib, int stats_entry);
extern int dm_stats_init(void);
extern void dm_stats_exit(void);

#endif                          /* __STATS_H__ */
