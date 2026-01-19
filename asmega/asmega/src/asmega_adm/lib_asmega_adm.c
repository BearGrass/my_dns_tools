/*
 * Copyright (C)
 * Filename: lib_asmega_adm.c
 * Author:
 * yingze <mayong.my@alibaba-inc.com>
 * Description:
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "lib_asmega_adm.h"
#include "errcode.h"

#define LOG_BUFF_LEN                     2048

/* use the same log file with mega_adm, maybe it's better to separate them */
static char *g_lib_log_file = "/var/dns/asmega/var/log/asmega_adm.log";
static struct timeval g_op_start_tm;
static __thread int g_adm_sock_fd = -1;

int socket_init()
{
    if (g_adm_sock_fd != -1) {
        return ASMEGA_ADM_SOCKET_BUSY;
    }

    g_adm_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (g_adm_sock_fd < 0) {
        return ASMEGA_ADM_CREATE_SOCKET_ERROR;
    }

    return ASMEGA_ADM_OK;
}

void socket_cleanup()
{
    if (g_adm_sock_fd > -1) {
        close(g_adm_sock_fd);
    }
    g_adm_sock_fd = -1;
}

static int lib_asmega_adm_init()
{
    gettimeofday(&g_op_start_tm, NULL);

    return socket_init();
}

static void lib_asmega_adm_cleanup()
{
    return socket_cleanup();
}

static void lib_asmega_adm_log_write(int ret, const char *fmt, ...)
{
    size_t used_len = 0;
    struct timeval tv;
    struct tm tm;
    char log_buf[LOG_BUFF_LEN];
    int op_msec;
    va_list ap;

    int log_fd = open(g_lib_log_file, O_WRONLY | O_APPEND | O_CREAT | O_SYNC,
                      0644);
    if (log_fd < 0) {
        /* failed to write log, do nothing */
        return;
    }

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&(tv.tv_sec), &tm);

    used_len += snprintf(log_buf + used_len, LOG_BUFF_LEN - used_len,
                         "%02d-%02d-%04d %02d:%02d:%02d.%ld [RET=%d]:",
                         tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900,
                         tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec / 1000,
                         ret);

    va_start(ap, fmt);
    used_len += vsnprintf(log_buf + used_len, LOG_BUFF_LEN - used_len, fmt, ap);
    va_end(ap);

    op_msec = (tv.tv_sec - g_op_start_tm.tv_sec) * 1000
        + (tv.tv_usec - g_op_start_tm.tv_usec) / 1000;
    used_len += snprintf(log_buf + used_len, LOG_BUFF_LEN - used_len, ", %dms",
                         op_msec);
    log_buf[used_len++] = '\n';

    write(log_fd, log_buf, used_len);

    close(log_fd);
    log_fd = -1;

    return;
}

int __lib_asmega_adm_get(am_tnl_info_t * tnl_list, uint32_t *tnl_num) {
    int ret;
    socklen_t size;

    if (tnl_list == NULL) {
        lib_asmega_adm_log_write(ASMEGA_ADM_TNL_LIST_NULL_ERROR,
                "The tunnel info list is NULL");
        return ASMEGA_ADM_TNL_LIST_NULL_ERROR;
    }

    if (tnl_num == NULL) {
        lib_asmega_adm_log_write(ASMEGA_ADM_TNL_NUM_NULL_ERROR,
                "The tunnel info list num is NULL");
        return ASMEGA_ADM_TNL_NUM_NULL_ERROR;
    }

    size = (*tnl_num) * sizeof(am_tnl_info_t);
    ret = getsockopt(g_adm_sock_fd, IPPROTO_IP, SOCKET_OPS_GET_ALL,
            (void *) tnl_list, &size);

    if (ret != 0) {
        lib_asmega_adm_log_write(ASMEGA_ADM_GET_SOCKOPT_FAILED_ERROR,
                "[%s]: kernel not return the result with errno %d\n",
                __FUNCTION__, ret);
        return ASMEGA_ADM_GET_SOCKOPT_FAILED_ERROR;
    }

    if ((size % sizeof(am_tnl_info_t)) != 0) {
        lib_asmega_adm_log_write(ASMEGA_ADM_GET_SOCKOPT_BUFF_SIZE_ERROR,
                "[%s]: wrong buff size (%d) get from kernel\n",
                __FUNCTION__, size);
        return ASMEGA_ADM_GET_SOCKOPT_BUFF_SIZE_ERROR;
    }
    *tnl_num = size / sizeof(am_tnl_info_t);

    if (*tnl_num > MAX_VIEW_ID_NUM) {
        lib_asmega_adm_log_write(ASMEGA_ADM_GET_SOCKOPT_TNL_NUM_ERROR,
                "[%s]: wrong tunnel number (%d) get from kernel\n",
                __FUNCTION__, *tnl_num);
        return ASMEGA_ADM_GET_SOCKOPT_TNL_NUM_ERROR;
    }

    return ASMEGA_ADM_OK;
}

int lib_asmega_adm_get(am_tnl_info_t * tnl_list, uint32_t *tnl_num) {

    int ret;

    if ((ret = lib_asmega_adm_init()) < 0) {
        lib_asmega_adm_log_write(ret, "Failed to init lib_asmega_adm");
        lib_asmega_adm_cleanup();
        return ret;
    }

    ret = __lib_asmega_adm_get(tnl_list, tnl_num);

    lib_asmega_adm_cleanup();

    return ret;
}

int __lib_asmega_adm_set(am_tnl_info_t * tnl_list, uint32_t tnl_num) {
    int ret;
    socklen_t size;

    if (tnl_list == NULL) {
        lib_asmega_adm_log_write(ASMEGA_ADM_TNL_LIST_NULL_ERROR,
                "The tunnel info list is NULL");
        return ASMEGA_ADM_TNL_LIST_NULL_ERROR;
    }

    if (tnl_num > MAX_VIEW_ID_NUM) {
        lib_asmega_adm_log_write(ASMEGA_ADM_SET_SOCKOPT_TNL_NUM_ERROR,
                "[%s]: The tunnel info list number (%d) exceed the max number (%d)\n",
                __FUNCTION__, tnl_num, MAX_VIEW_ID_NUM);
        return ASMEGA_ADM_SET_SOCKOPT_TNL_NUM_ERROR;
    }

    size = tnl_num * sizeof(am_tnl_info_t);
    ret = setsockopt(g_adm_sock_fd, IPPROTO_IP, SOCKET_OPS_SET_BATCH,
            (void *) tnl_list, size);

    if (ret != 0) {
        lib_asmega_adm_log_write(ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR,
                "[%s]: failed to bind tunnel and view with errno %d\n",
                __FUNCTION__, ret);
        return ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR;
    }

    return ASMEGA_ADM_OK;
}

int lib_asmega_adm_set(am_tnl_info_t * tnl_list, uint32_t tnl_num) {
    int ret;

    if ((ret = lib_asmega_adm_init()) < 0) {
        lib_asmega_adm_log_write(ret, "Failed to init lib_asmega_adm");
        lib_asmega_adm_cleanup();
        return ret;
    }

    ret = __lib_asmega_adm_set(tnl_list, tnl_num);

    lib_asmega_adm_cleanup();

    return ret;
}
