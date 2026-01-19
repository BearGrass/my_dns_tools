
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#include "rte_core.h"
#include "adns.h"
#include "log.h"
#include "adns_stats.h"


extern size_t g_log_rotate_max_size;
extern uint32_t g_log_rotate_max_count;

char log_level_str[4][10] = {
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG",
};

char log_file_name[LOG_FILE_NUM][30] = {
    "adns_server.log",
    "adns_query.log",
    "adns_answer.log",
	"adns_query_statis.log"
};

static void *msg_queue[READ_SIZE];

static int log_fds[LOG_FILE_NUM] = { -1 };
struct rte_ring *g_log_rings[LOG_FILE_NUM];
struct rte_ring *g_log_query_rings[RTE_MAX_LCORE];
struct rte_mempool *g_log_mempool = NULL;

static uint32_t file_count[LOG_FILE_NUM] = { 0 };

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

static char *make_logfile_name(int file)
{
    char name[64];
    char *filename;

    snprintf(name, 64, "%s/%s", adns_log_path, log_file_name[file]);
    filename = strdup(name);

    return filename;
}

static char *make_rotate_logfile_name(int file)
{
    char name[64];
    char *filename;

    ++file_count[file];
    if (file_count[file] > g_log_rotate_max_count) {
        file_count[file] = 1;
    }

    snprintf(name, 64, "%s/%s.%u", adns_log_path, log_file_name[file],
             file_count[file]);
    filename = strdup(name);

    return filename;
}

static int
adns_fmt_msg(struct log_msg *log, int lcore, int type, int level,
             const char *file, int line, const char *func,
             const char *fmt, va_list args)
{
	int size;
    struct timeval tv;
    struct tm tm;
    char buf[LOG_SIZE];
    default_log_data_t *log_data;

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&(tv.tv_sec), &tm);

    log->fmt_fun = default_fmt_msg;
    log_data = (default_log_data_t *)&log->data;

    vsnprintf(buf, LOG_SIZE, fmt, args);

    size =
        snprintf(log_data->msg, DEFAULT_LOG_DATA_MSG_SIZE,
                 "%02d-%02d-%04d %02d:%02d:%02d.%ld [%s]: %s", tm.tm_mday,
                 tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min,
                 tm.tm_sec, tv.tv_usec / 1000, log_level_str[level], buf);
    if(size > DEFAULT_LOG_DATA_MSG_SIZE) {
    	size = DEFAULT_LOG_DATA_MSG_SIZE;
    }
    log_data->size = (uint16_t)size;

    if (rte_ring_enqueue(g_log_rings[type], (void *)log) == -ENOBUFS) {
    	switch (type) {
            case LOG_SERVER:
                STATS_INC(log_server_fail);
                break;
            case LOG_QUERY:
                STATS_INC(log_query_fail);
                break;
            case LOG_ANSWER:
                STATS_INC(log_answer_fail);
                break;
            case LOG_QUERY_STATIS:
                STATS_INC(log_query_statis_fail);
                break;
    	    default:
                break;
        }
        
        return -1;
    }

    return 0;
}

void
adns_log_write(int lcore, int type, int level, const char *file, int line,
               const char *func, const char *fmt, ...)
{
    va_list args;
    struct log_msg *log;

    if ((level > adns_log_level) || (adns_log_switch == ADNS_LOG_SWITCH_DOWN))
        return;

    log = log_alloc();
    if (log == NULL)
        return;

    va_start(args, fmt);
    if(adns_fmt_msg(log, lcore, type, level, file, line, func, fmt, args) < 0) {
    	log_free(log);
    }
    va_end(args);
}

static void rotate_log(int file)
{
    char *now_file_name = make_logfile_name(file);
    if (now_file_name == NULL) {
        return;
    }

    char *old_file_name = make_rotate_logfile_name(file);
    if (old_file_name == NULL) {
        return;
    }
    rename(now_file_name, old_file_name);

    int now_fd = open(now_file_name, O_RDWR | O_CREAT | O_APPEND, 0644);
    if (now_fd < 0) {
        return;
    }

    if (dup2(now_fd, log_fds[file]) < 0) {
        return;
    }
    close(now_fd);
    free(now_file_name);
    free(old_file_name);
}

void __adns_log_flush_fast(int file, struct rte_ring *ring, unsigned maxnum)
{
    unsigned int i;
    ssize_t nwrite;
    uint16_t size;
    unsigned num = maxnum;
    struct log_msg *log;
    char *msg;
    int fd = log_fds[file];
    off_t offset;

    while (num > 0
            && rte_ring_sc_dequeue_bulk(ring, msg_queue, num) != 0)
        num = RTE_MIN(rte_ring_count(ring), maxnum);

    if (num == 0)
        return;

    offset = lseek(fd, 0, SEEK_END);
    if (offset < 0) {
        // does not handle error here, just try to write log file
        offset = 0;
    }

    for (i = 0; i < num; i++) {
        log = (log_msg_t *) msg_queue[i];
        if (log) {
        	msg = log->fmt_fun(log->lcore_id, log->data, &size);
            /* if file size larger than log rotate size will be rotated */
            if ((g_log_rotate_max_size != LOG_ROTATE_DISABLE)
                    && (g_log_rotate_max_count != LOG_ROTATE_DISABLE)) {
                if ((size_t) offset + size > g_log_rotate_max_size) {
                    rotate_log(file);
                    offset = size;
                } else {
                    offset += size;
                }
            }

            while (size > 0) {
                nwrite = write(fd, msg, size);
                if (nwrite == -1) {
                    for (; i<num; i++)
                        if (msg_queue[i])
                            log_free(msg_queue[i]);
                    return;
                }
                size -= nwrite;
                msg += nwrite;
            }
            log_free(log);
        }
    }
}

void __adns_log_flush(int file, struct rte_ring *ring)
{
    unsigned int i;
    ssize_t nwrite;
    uint16_t size;
    unsigned num = READ_SIZE;
    struct log_msg *log;
    int fd = log_fds[file];
    char *msg;

    while (num > 0 && rte_ring_sc_dequeue_bulk(ring, msg_queue, num) != 0)
        num = RTE_MIN(rte_ring_count(ring), READ_SIZE);

    if (num == 0)
        return;

    for (i = 0; i < num; i++) {
        log = (struct log_msg *)msg_queue[i];
        if (log) {
        	msg = log->fmt_fun(log->lcore_id, log->data, &size);

            while (size > 0) {
                /* if file size larger than log rotate size will be rotated */
                if ((g_log_rotate_max_size != LOG_ROTATE_DISABLE) &&
                    (g_log_rotate_max_count != LOG_ROTATE_DISABLE) &&
                    (size <= g_log_rotate_max_size)) {
                    off_t offset;

                    offset = lseek(fd, 0, SEEK_END);
                    if (offset < 0) {
                        return;
                    } else {
                        size_t log_size = (size_t) offset;
                        if (log_size + size > g_log_rotate_max_size)
                            rotate_log(file);
                    }
                }

                nwrite = write(fd, msg, size);
                if (nwrite == -1) {
                    log_free(log);
                    return;
                }
                size -= nwrite;
            }
            log_free(log);
        }
    }
}

void adns_log_flush(void)
{
    int i, lcore, max_io_lcore;

    for (i = 0; i < LOG_FILE_NUM; i++) {
		__adns_log_flush_fast(i, g_log_rings[i], READ_SIZE);
    }

    max_io_lcore = app.lcore_io_start_id + app.lcore_io_num;
    for (lcore = app.lcore_io_start_id ; lcore < max_io_lcore; lcore ++) {
        __adns_log_flush_fast(LOG_QUERY, g_log_query_rings[lcore], QUERY_READ_SIZE);
    }
}

static int __log_file_init(int file)
{
    char *log_file;
    FILE *fp;
    int fd;

    log_file = make_logfile_name(file);
    if (log_file == NULL)
        return -EINVAL;

    fp = fopen(log_file, "a");
    free(log_file);
    if (fp == NULL)
        return -1;
    setvbuf(fp, NULL, _IONBF, 0);
    fd = fileno(fp);

    return fd;
}

static int log_file_init(void)
{
    memset(file_count, 0, sizeof(file_count));
    if ((log_fds[LOG_SERVER] = __log_file_init(LOG_SERVER)) < 0)
        return -1;

    if ((log_fds[LOG_QUERY] = __log_file_init(LOG_QUERY)) < 0)
        return -1;

    if ((log_fds[LOG_ANSWER] = __log_file_init(LOG_ANSWER)) < 0)
        return -1;

    if ((log_fds[LOG_QUERY_STATIS] = __log_file_init(LOG_QUERY_STATIS)) < 0)
        return -1;

    return 0;
}

static void log_file_cleanup(void)
{
    if (log_fds[LOG_SERVER] > 0) {
        close(log_fds[LOG_SERVER]);
        log_fds[LOG_SERVER] = -1;
    }
    if (log_fds[LOG_QUERY] > 0) {
        close(log_fds[LOG_QUERY]);
        log_fds[LOG_QUERY] = -1;
    }
    if (log_fds[LOG_ANSWER] > 0) {
        close(log_fds[LOG_ANSWER]);
        log_fds[LOG_ANSWER] = -1;
    }
    if (log_fds[LOG_QUERY_STATIS] > 0) {
        close(log_fds[LOG_QUERY_STATIS]);
        log_fds[LOG_QUERY_STATIS] = -1;
    }
}

int log_init(void)
{
    int i, lcore, ret, max_io_lcore;
    char name[64];

    ret = log_file_init();
    if (ret < 0) {
        fprintf(stderr, "Cannot init log files\n");
        goto err_out;
    }

    g_log_mempool = rte_mempool_create("adns_log", LOG_NUM, LOG_SIZE, 0, 0,
                                     NULL, NULL, NULL, NULL, SOCKET_ID_ANY, 0);
    if (g_log_mempool == NULL) {
        fprintf(stderr, "Cannot init log mempool\n");
        goto err_mps;
    }

    for (i = 0; i < LOG_FILE_NUM; i++) {
        snprintf(name, 64, "%s", log_file_name[i]);
        g_log_rings[i] = rte_ring_create(name, LOG_RING_COUNT, SOCKET_ID_ANY, RING_F_SC_DEQ);
        if (g_log_rings[i] == NULL) {
            fprintf(stderr, "Failed to create ring for adns log, %s\n", name);
            goto err_rings;
        }
        printf("[%s]: Finish to new log ring %s\n", __FUNCTION__, name);
    }

    max_io_lcore = app.lcore_io_start_id + app.lcore_io_num;
    for (lcore = app.lcore_io_start_id ; lcore < max_io_lcore; lcore ++) {
        snprintf(name, 64, "%s_%d", log_file_name[LOG_QUERY], lcore);
        g_log_query_rings[lcore] =
            rte_ring_create(name, LOG_RING_COUNT, SOCKET_ID_ANY, RING_F_SC_DEQ | RING_F_SP_ENQ);
        if (g_log_query_rings[lcore] == NULL) {
            fprintf(stderr, "Failed to create ring for adns log, %s\n", name);
            goto err_rings;
        }
        printf("[%s]: Finish to new log ring %s\n", __FUNCTION__, name);
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
