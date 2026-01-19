
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>

#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_common.h>
#include "rte_core.h"

#include "log.h"
#define MSG_SIZE LOG_SIZE-4

static const char *log_file_name[LOG_FILE_NUM] = {
        "fwd_server.log",
        "fwd_query.log",
        "fwd_answer.log",
		"fwd_secure.log"
};

char gtime_str[40];
static void *msg_queue[QUERY_READ_SIZE];
static int log_fds[LOG_FILE_NUM] = { -1 };
struct rte_ring *g_log_rings[_MAX_LCORE];
int g_level[LOG_FILE_NUM];
struct rte_mempool *g_log_mempool = NULL;
static char *log_path = NULL;

struct default_log_data {
    uint16_t size;
    char msg[0];
};
typedef struct default_log_data default_log_data_t;
#define DEFAULT_LOG_DATA_MSG_SIZE (LOG_MSG_DATA_SIZE - sizeof(default_log_data_t))

static char *default_fmt_msg(uint32_t lcore_id, uint8_t *data, uint16_t *size) {
    *size = ((default_log_data_t *)data)->size;

    return ((default_log_data_t *)data)->msg;
}

int set_log_level_id(int type, int level)
{
    if (type > LOG_FILE_NUM || type < 0)
        return -1;
    if (level > LOG_LEVEL_NUM || level < 0)
        return -1;
    g_level[type] = level;
    return 0;
}

int set_log_level(const char *type, char *level)
{
    int type_id = -1, level_id = -1;
    int i;
    for (i = 0; i < LOG_FILE_NUM; i++) {
        if (strcasecmp(type, log_type_str[i]) == 0)
            type_id = i;
    }
    if (type_id == -1) {
        ALOG(SERVER, ERROR, "No such log type '%s'", type);
        return -1;
    }

    for (i = 0; i < LOG_LEVEL_NUM; i++) {
        if (strcasecmp(level, log_level_str[i]) == 0)
            level_id = i;
    }
    if (level_id == -1) {
        ALOG(SERVER, ERROR, "No such log level '%s'", level);
        return -1;

    }

    g_level[type_id] = level_id;
    printf("LDNS: Set log %s level to %s\n", type, level);
    return 0;
}

void set_log_path(char *path)
{
    log_path = path;
    printf("LDNS: Set log path to %s\n", path);
}

static char *make_logfile_name(const char *file)
{
    char name[300];
    char *filename;

    if (file == NULL)
        return NULL;

    snprintf(name, 300, "%s/%s", log_path, file);
    printf("LDNS: log file %s\n", name);
    filename = strdup(name);

    return filename;
}

static int
adns_fmt_msg(struct log_msg *log, int lcore, int type, int level,
             const char *fmt, va_list args)
{
    int size;
    char buf[LOG_SIZE];
    default_log_data_t *log_data;

    log->log_type = type;
    log->fmt_fun = default_fmt_msg;
    log_data = (default_log_data_t *)&log->data;

    vsnprintf(buf, LOG_SIZE, fmt, args);

    size =
        snprintf(log_data->msg, DEFAULT_LOG_DATA_MSG_SIZE, "%s [%s]:%s\n",
            gtime_str, log_level_str[level], buf);
    if(size > DEFAULT_LOG_DATA_MSG_SIZE) {
        log_data->msg[DEFAULT_LOG_DATA_MSG_SIZE - 1] = '\n';
        size = DEFAULT_LOG_DATA_MSG_SIZE;
    }
    log_data->size = (uint16_t)size;

    if (rte_ring_enqueue(g_log_rings[lcore], (void *)log) == -ENOBUFS) {
        /* plus counter here
        switch (type) {
            case LOG_SERVER:
                STATS(LOG_SERVER_FAIL);
                break;
            case LOG_QUERY:
                STATS(LOG_QUERY_FAIL);
                break;
            case LOG_ANSWER:
                STATS(LOG_ANSWER_FAIL);
                break;
            default:
                break;
        }
        */
        return -1;
    }

    return 0;
}

void
adns_log_write(int lcore, int type, int level, const char *fmt, ...)
{
    va_list args;
    struct log_msg *log;

/*    if ((level > g_level[type])) //|| (adns_log_switch == ADNS_LOG_SWITCH_DOWN))
        return;*/

    log = log_alloc();
    if (log == NULL)
        return;

    va_start(args, fmt);
    if(adns_fmt_msg(log, lcore, type, level, fmt, args) < 0) {
        log_free(log);
    }
    va_end(args);
}

static inline int
__adns_log_flush_fast(struct rte_ring *ring, unsigned maxnum)
{
    unsigned int i;
    ssize_t nwrite;
    uint16_t size;
    unsigned num = maxnum;
    struct log_msg *log;
    char *msg;

    while (num > 0
            && rte_ring_sc_dequeue_bulk(ring, msg_queue, num) != 0)
        num = RTE_MIN(rte_ring_count(ring), maxnum);

    for (i = 0; i < num; i++) {
        log = (log_msg_t *) msg_queue[i];
        if (log) {
            msg = log->fmt_fun(log->lcore_id, log->data, &size);

            while (size > 0) {
                nwrite = write(log_fds[log->log_type], msg, size);
                if (nwrite == -1) {
                    for (; i<num; i++)
                        if (msg_queue[i])
                            log_free(msg_queue[i]);
                    return num;
                }
                size -= nwrite;
                msg += nwrite;
            }
            log_free(log);
        }
    }

    return num;
}

int logs_flush() {
    int i, num = 0;

    for (i = 0; i < glog_lcore_count; i++) {
        num += __adns_log_flush_fast(g_log_rings[glog_lcore_id[i]],
                QUERY_READ_SIZE);
    }

    return num;
}

void charge_log_time()
{
    struct timeval tv;
    struct tm tm;

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&(tv.tv_sec), &tm);
    sprintf(gtime_str, "%04d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900,
            tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int __log_file_init(const char *file)
{
    char *log_file;
    FILE *fp;
    int fd;

    log_file = make_logfile_name(file);
    if (log_file == NULL)
        return -EINVAL;
    fp = fopen(log_file, "a");
    if (fp == NULL) {
        printf("LDNS: fopen log file %s fail\n", log_file);
        return -1;
    }
    setvbuf(fp, NULL, _IONBF, 0);
    fd = fileno(fp);

    return fd;
}

static int log_file_init(void)
{
    int i;

    for (i = 0; i < LOG_FILE_NUM; i++) {
        if ((log_fds[i] = __log_file_init(log_file_name[i])) < 0)
            return -1;
    }

    return 0;
}

static void log_file_cleanup(void)
{
    int i;
    for (i = 0; i < LOG_FILE_NUM; i++) {
        if (log_fds[i] > 0) {
            close(log_fds[i]);
            log_fds[i] = -1;
        }
    }
}

static int log_mps_init(void)
{
    g_log_mempool = rte_mempool_create("adns_log", LOG_NUM, LOG_SIZE, 32, 0,
                                     NULL, NULL, NULL, NULL, SOCKET_ID_ANY, 0);
    if (g_log_mempool == NULL) {
        fprintf(stderr, "Cannot init log mempool\n");
        return -ENOMEM;
    }

    return 0;
}

int log_init(void)
{
    int i, ret;
    char name[64];

    ret = log_file_init();
    if (ret < 0) {
        fprintf(stderr, "Cannot init log files\n");
        goto err_out;
    }

    ret = log_mps_init();
    if (ret < 0) {
        fprintf(stderr, "Cannot init log files\n");
        goto err_mps;
    }

    for (i = 0; i < glog_lcore_count; i++) {
        snprintf(name, 64, "log_ring_%d", glog_lcore_id[i]);
        g_log_rings[glog_lcore_id[i]] =
            rte_ring_create(name, LOG_RING_COUNT, SOCKET_ID_ANY,  RING_F_SC_DEQ | RING_F_SP_ENQ);
        if (g_log_rings[glog_lcore_id[i]] == NULL) {
            fprintf(stderr, "Failed to create ring for adns log, %s\n", name);
            goto err_rings;
        }
    }

    return 0;

err_rings:
err_mps:
    log_file_cleanup();
err_out:
    return -1;
}

void log_cleanup(void)
{
    log_file_cleanup();
}
