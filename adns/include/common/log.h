
#ifndef _LOG_H_
#define _LOG_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_common.h>

#include "descriptor.h"

#define LOG_RING_COUNT   (1<<12)
#define LOG_NUM   (LOG_RING_COUNT * 16)
#define LOG_SIZE  2048
#define READ_SIZE 32
#define QUERY_READ_SIZE 8

/* default rotate size: 512M bytes */
#define LOG_ROTATE_DISABLE 0

extern char *adns_log_path;
extern int adns_log_level;
extern int adns_log_switch;
extern int adns_log_file;
extern size_t log_rotate_max_size;
extern uint32_t  log_rotate_max_count;

#define LOG_FILE_NUM  4

#define LOG_SERVER 0
#define LOG_QUERY  1
#define LOG_ANSWER 2
#define LOG_QUERY_STATIS 3

#define DNS_LOG_ERROR  0
#define DNS_LOG_WARN   1
#define DNS_LOG_INFO   2
#define DNS_LOG_DEBUG  3

typedef char * (*log_fmt_fun_t)(uint32_t, uint8_t *, uint16_t *);
struct log_msg {
    uint32_t lcore_id;
    log_fmt_fun_t fmt_fun;
	uint8_t data[0];
}  __attribute__ ((packed));
typedef struct log_msg log_msg_t;
#define LOG_MSG_DATA_SIZE (LOG_SIZE - sizeof(log_msg_t))

extern struct rte_mempool *g_log_mempool;
extern struct rte_ring *g_log_rings[LOG_FILE_NUM];
extern struct rte_ring *g_log_query_rings[RTE_MAX_LCORE];

#ifdef __cplusplus
extern "C" {
#endif
/* common log API */
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
log_alloc_level(int level)
{
    if ((level > adns_log_level) || (adns_log_switch == ADNS_LOG_SWITCH_DOWN)) {
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
adns_log_write_custom(int lcore, struct rte_ring *ring_p, int level, log_fmt_fun_t fmt_fun,
		struct log_msg *log) {
	if (log == NULL) {
		return;
	}

	log->fmt_fun = fmt_fun;
	log->lcore_id = lcore;

	if (rte_ring_enqueue(ring_p, (void *) log) == -ENOBUFS) {
		log_free(log);
	}
}

extern void adns_log_write(int lcore, int type, int level, const char *file, int line, 
		const char *func, const char *fmt, ...);
#ifdef __cplusplus
}
#endif

#define adns_log_print(lcore, type, level, fmt, args...) \
	adns_log_write(lcore, type, level, __FILE__, __LINE__, __func__, fmt, ##args)

/* server log API */
#define log_server_error(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_SERVER, DNS_LOG_ERROR,fmt, ##args)
#define log_server_warn(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_SERVER, DNS_LOG_WARN,fmt, ##args)
#define log_server_info(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_SERVER, DNS_LOG_INFO,fmt, ##args)
#define log_server_debug(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_SERVER, DNS_LOG_DEBUG,fmt, ##args)

/* query log API */     
#define log_query_error(lcore, fmt, args...) \
    adns_log_print(lcore, LOG_QUERY, DNS_LOG_ERROR,fmt, ##args)
#define log_query_warn(lcore, fmt, args...) \
    adns_log_print(lcore, LOG_QUERY, DNS_LOG_WARN,fmt, ##args)
#define log_query_info(lcore, fmt, args...) \
    adns_log_print(lcore, LOG_QUERY, DNS_LOG_INFO,fmt, ##args)
#define log_query_debug(lcore, fmt, args...) \
    adns_log_print(lcore, LOG_QUERY, DNS_LOG_DEBUG,fmt, ##args)
#define log_query_custom(fmt_fun, log) \
    adns_log_write_custom(rte_lcore_id(), g_log_query_rings[rte_lcore_id()], DNS_LOG_INFO, fmt_fun, log)


/* answer log API */
#define log_answer_error(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_ANSWER, DNS_LOG_ERROR,fmt, ##args)
#define log_answer_warn(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_ANSWER, DNS_LOG_WARN,fmt, ##args)
#define log_answer_info(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_ANSWER, DNS_LOG_INFO,fmt, ##args)
#define log_answer_debug(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_ANSWER, DNS_LOG_DEBUG,fmt, ##args)
#define log_answer_custom(fmt_fun, log) \
    adns_log_write_custom(rte_lcore_id(), g_log_rings[LOG_ANSWER], DNS_LOG_INFO, fmt_fun, log)

/* query_statis log API */
#define log_query_statis_info(lcore, fmt, args...) \
	adns_log_print(lcore, LOG_QUERY_STATIS, DNS_LOG_INFO,fmt, ##args)

extern void adns_log_flush(void);
extern int  log_init(void);
extern void log_cleanup(void);

#endif

