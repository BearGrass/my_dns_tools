/*
 * Copyright (C)
 * Filename: stats.h
 * Author:
 * mogu.lwp<mogu.lwp@alibaba-inc.com>
 * Description:
 */

#ifndef __STATS_H__
#define __STATS_H__

#include <linux/percpu.h>
#include <linux/smp.h>


/* list of counters */
enum {
    AS_COUNTERS_START = 0,

    AS_ACCEPT_LOCAL_IN_L3 = AS_COUNTERS_START,
    AS_ACCEPT_LOCAL_IN_L4,
    AS_ACCEPT_LOCAL_IN_L7,
    AS_ACCEPT_LINEARIZE_IN,
    AS_ACCEPT_LOCAL_OUT_L3,
    AS_ACCEPT_LOCAL_OUT_L4,
    AS_ACCEPT_LOCAL_OUT_L7,
    AS_ACCEPT_LINEARIZE_OUT,
    AS_ACCEPT_NOSUPPORT,
    AS_ACCEPT_NOT_FIND_VIEW_ID,
    AS_STOLEN_NEW_SKB,
    //AS_NONSUP_MUL_ADD,
    AS_NONSUP_OPCODE,
    AS_NONSUP_QUESTIONS,
    AS_NONSUP_CLASS,
    //AS_NONSUP_QR_WITH_AN_OR_AU,
    AS_DROP_LOCAL_IN_L7,
    AS_DROP_PAC_INCOMPLETE,
    AS_DROP_PARSE_ERROR,
    //AS_DROP_EDNS_TO_WIRE,
    AS_DROP_PARSE_EDNS,
    AS_DROP_QR_WITH_PVT_EDNS,
    AS_REQUEST_IN,
    AS_REQUEST_OUT,
    AS_REQUEST_MEM_MOV,
    AS_ANSWER_MEM_MOV,
    AS_ERROR_DATAGRAM_SMALL,
    AS_ERROR_NOMEM_REQUEST,
    AS_ERROR_ILLEGAL_DNAME_LEN,
    //AS_ERROR_ADDITION_NUM,
    AS_ERROR_EDNS_TYPE,
    AS_ERROR_EDNS_VERSION,
    AS_ERROR_EDNS_LEN,
    AS_ERROR_NOMEM_SKB,

    AS_COUNTERS_END,
    AS_COUNTERS_NUM = AS_COUNTERS_END - AS_COUNTERS_START,
};

/* counters like SNMP MIB */
struct as_estats_mib {
    long mibs[AS_COUNTERS_NUM];
};

#define AS_INC_ESTATS(mib, field)		\
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)
#define AS_ADD_ESTATS(mib, field, val)	\
	((per_cpu_ptr(mib, smp_processor_id())->mibs[field]) += val)
#define AS_DEC_ESTATS(mib, field)		\
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]--)
#define AS_GET_ESTATS(mib, field)       \
    (per_cpu_ptr(mib, smp_processor_id())->mibs[field])

extern struct as_estats_mib *as_esmib;
/* count counters in all cpus
 * @mib struct of state counters
 * @stats_num number of state counters
 *
 * @return number of a counter
 * */
extern long fold_field(const struct as_estats_mib *mib, int stats_num);
extern int as_counters_show(struct seq_file *m, void *v);

/* clear all counters */
extern void as_estats_clear(struct as_estats_mib *mib, int start, int end);
extern int as_stats_init(void);
extern void as_stats_exit(void);

#endif                          /* __STATS_H__ */
