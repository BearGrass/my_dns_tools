
#ifndef _LDNS_LOG_H_
#define _LDNS_LOG_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_common.h>

#include "log_def.h"

#ifndef _MAX_LCORE
#define _MAX_LCORE 80
#endif
#define LOG_RING_COUNT   (1<<12)
#define LOG_NUM   (LOG_RING_COUNT * 16)
#define LOG_SIZE  2048
#define QUERY_READ_SIZE 16

extern struct rte_mempool *g_log_mempool;
extern struct rte_ring *g_log_rings[_MAX_LCORE];
extern int g_level[LOG_FILE_NUM];
extern int glog_lcore_count;
extern int glog_lcore_id[_MAX_LCORE];
extern char gtime_str[40];

/* common log API */
static inline int __attribute__ ((always_inline))
would_log(int type, int level)
{
    if (level > g_level[type])
        return 0;
    return 1;
}


static inline struct log_msg * __attribute__ ((always_inline))
log_alloc(void)
{
    void *msg;

    if (rte_mempool_get(g_log_mempool, &msg) < 0) {
        /*fprintf(stderr, "Failed to alloc log msg\n"); */
        return NULL;
    }

    return (struct log_msg *)msg;
}

static inline struct log_msg * __attribute__ ((always_inline))
log_alloc_level(int type, int level)
{
    if (!would_log(type, level)) {// || (adns_log_switch == ADNS_LOG_SWITCH_DOWN)) {
        return NULL;
    }

    return log_alloc();
}

static inline void __attribute__ ((always_inline))
log_free(struct log_msg *msg)
{
    if (msg == NULL)
        return;

    rte_mempool_put(g_log_mempool, (void *)msg);
}

static inline void __attribute__ ((always_inline))
adns_log_write_custom(int lcore, int type, int level, log_fmt_fun_t fmt_fun,
        struct log_msg *log) {
    if (log == NULL) {
        return;
    }

    log->log_type = type;
    log->log_leve = level;
    log->fmt_fun = fmt_fun;
    log->lcore_id = lcore;

    if (rte_ring_enqueue(g_log_rings[lcore], (void *) log) == -ENOBUFS) {
        log_free(log);
    }
}

#define WOULD_LOG(type,level) would_log(LOG_##type,LOG_##level)
#define ALOG(type,level,fmt,args...) \
        if (WOULD_LOG(type, level)) { \
            adns_log_write(rte_lcore_id(), LOG_##type, LOG_##level, fmt, ##args); \
        }
#define DLOG(type,level, fmt_fun, log) \
        if (WOULD_LOG(type, level)) { \
            adns_log_write_custom(rte_lcore_id(), LOG_##type, LOG_##level, fmt_fun, log); \
        }
#define LOG_ALLOC_LEVEL(type,level) log_alloc_level(LOG_##type,LOG_##level)

	
void
adns_log_write(int lcore, int type, int level, const char *fmt, ...);

extern int logs_flush();
extern void charge_log_time();
extern int set_log_level(const char *type,char *level);
extern int set_log_level_id(int type,int level);
extern void set_log_path(char *path);

extern int log_init(void);
extern void log_cleanup(void);


#endif

