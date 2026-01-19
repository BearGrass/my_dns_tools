/*
 * Copyright (C)
 * Filename: asmega_adm.c
 * Author:
 * yingze <mayong.my@alibaba-inc.com
 * Description:
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <fcntl.h>

#include "lib_asmega.h"
#include "config.h"
#include "errcode.h"

#define LOG_BUFF_LEN            2048
#define OPTEND -1

#define OPT_NONE                0x000000
#define OPT_TNL_ID              0x000001
#define OPT_VIEW_ID             0x000002
#define OPT_ALL                 0x000004

static const char *optnames[] = {
    "tunnel",
    "view",
    "all",
};

enum {
    AM_CMD_INIT = 1,
    AM_CMD_SHOW,
    AM_CMD_BIND,
    AM_CMD_UNBIND,

    AM_CMD_ERR,
};

static int g_log_fd;
static char *g_adm_log_file = "/var/dns/asmega/var/log/asmega_adm.log";

const char *const short_options = "hvSBUt:w:a";
const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
    {"version", 0, NULL, 'v'},
    {"show", 1, NULL, 'S'},
    {"bind", 1, NULL, 'B'},
    {"unbind", 1, NULL, 'U'},
    {"tunnel", 1, NULL, 't'},
    {"view", 1, NULL, 'w'},
    {"all", 0, NULL, 'a'},
};

static void usage_exit(const int exit_status)
{
    printf
        ("AS Mega administration tool.\n"
        "Usage: asmega_adm <command> [options]\n\n"
        "Commands:\n"
        "  -S --show         show the binding forward ID by tunnel ID or reverse\n"
        "  -B --bind         bind a tunnel ID to a forward ID\n"
        "  -U --unbind       unbind the forward ID with the tunnel ID\n"
        "  -v --version      display current version\n"
        "  -h --help         display this help message\n"
        "Options:\n"
        "  -t --tunnel       tunnel id (0-%d)\n"
        "  -w --view         view id (%d-%d)\n"
        "  -a --all          all\n"
        "Examples:\n"
        "  asmega_adm -S -a\n"
        "  asmega_adm -S -t 42677\n"
        "  asmega_adm -B -t 42677 -w 1012\n"
        "  asmega_adm -U -t 42677 -w 1012\n"
        "  asmega_adm -U -a\n"
        "  asmega_adm -v\n"
        "  asmega_adm -h\n",
        MAX_TNL_ID, MIN_VIEW_ID, MAX_VIEW_ID);

    exit(exit_status);
}

static void fail(int err, char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    vfprintf(stdout, msg, args);
    va_end(args);

    fprintf(stdout, "\n");
    exit(err);
}

static inline const char *opt2name(int option)
{
    const char **ptr;
    for (ptr = optnames; option > 1; option >>= 1, ptr++) ;

    return *ptr;
}

static void set_option(unsigned int *options, unsigned int option)
{
    if (*options & option)
        fail(ASMEGA_ADM_CMD_ERR, "multiple '%s' options specified",
                opt2name(option));
    *options |= option;
}

static int options_check(uint32_t options, int cmd)
{
    switch (cmd) {
        case AM_CMD_SHOW:
            if ((options & OPT_ALL) != 0) {
                if (((options & OPT_TNL_ID) != 0)
                        || ((options & OPT_VIEW_ID) != 0)) {
                    return -1;
                }
            } else if (((options & OPT_TNL_ID) == 0)
                    && ((options & OPT_VIEW_ID) == 0)) {
                return -1;
            } else if (((options & OPT_TNL_ID) != 0)
                    && ((options & OPT_VIEW_ID) != 0)) {
                return -1;
            }
            break;
        case AM_CMD_BIND:
            if (((options & OPT_TNL_ID) == 0) || ((options & OPT_VIEW_ID) == 0)) {
                return -1;
            }
            break;
        case AM_CMD_UNBIND:
            if ((options & OPT_ALL) != 0) {
                if (((options & OPT_TNL_ID) != 0)
                        || ((options & OPT_VIEW_ID) != 0)) {
                    return -1;
                }
            } else if (((options & OPT_TNL_ID) == 0)
                    || ((options & OPT_VIEW_ID) == 0)) {
                return -1;
            }
            break;
        case AM_CMD_INIT:
            usage_exit(ASMEGA_ADM_OK);
            break;
        default:
            break;
    }

    return 0;
}

int32_t parse_view_id(const char *id_str, uint16_t *id_val) {
    unsigned long val;

    /* check whether is default private zone first */
    val = strtoul(id_str, NULL, 10);

    if ((errno == ERANGE && val == ULONG_MAX) || (errno != 0 && val == 0)
            || val > MAX_VIEW_ID || val < MIN_VIEW_ID) {
        return -1;
    }
    *id_val = (uint16_t) val;

    return 0;
}

int32_t parse_tnl_id(const char *id_str, uint32_t *id_val) {
    unsigned long val;

    /* check whether is default private zone first */
    val = strtoul(id_str, NULL, 10);

    if ((errno == ERANGE && val == ULONG_MAX) || (errno != 0 && val == 0)
            || val > MAX_TNL_ID) {
        return -1;
    }
    *id_val = (uint32_t) val;

    return 0;
}

static int parse_opt(int argc, char **argv) {
    int ret, i, sockfd, tnl_num;
    int dm_cmd = AM_CMD_INIT;
    uint32_t tnl_id;
    uint16_t view_id;
    uint8_t buff[sizeof(am_tnl_info_t) * MAX_VIEW_ID_NUM];
    socklen_t size = sizeof(buff);
    am_tnl_info_t *tnl_list;
    unsigned int options = OPT_NONE;

    while ((ret =
            getopt_long(argc, argv, short_options, long_options,
                        NULL)) != OPTEND) {
        switch (ret) {
            case 'h':
                usage_exit(ASMEGA_ADM_OK);
                break;
            case 'v':
                printf("AS Mega Version is v%d.%d.%d\n", MAJOR_VERSION,
                    MINOR_VERSION, PATCH_VERSION);
                return ASMEGA_ADM_OK;
                break;
            case 'S':
                dm_cmd = AM_CMD_SHOW;
                break;
            case 'B':
                dm_cmd = AM_CMD_BIND;
                break;
            case 'U':
                dm_cmd = AM_CMD_UNBIND;
                break;
            case 'w':
                set_option(&options, OPT_VIEW_ID);
                if (parse_view_id(optarg, &view_id) < 0) {
                    fail(ASMEGA_ADM_PARSE_VIEW_ERROR,
                            "[%s]: view ID exceeds the max value %s\n",
                            __FUNCTION__, optarg);
                }
                break;
            case 't':
                set_option(&options, OPT_TNL_ID);
                if (parse_tnl_id(optarg, &tnl_id) < 0) {
                    fail(ASMEGA_ADM_PARSE_TUNNEL_ERROR,
                            "[%s]: tunnel ID exceeds the max value %s\n",
                            __FUNCTION__, optarg);
                }
                break;
            case 'a':
                set_option(&options, OPT_ALL);
                break;
            default:
                usage_exit(ASMEGA_ADM_CMD_ERR);
                break;
        }
    }

    if (options_check(options, dm_cmd) < 0) {
        fprintf(stdout, "[%s]: options not enough\n", __FUNCTION__);
        return ASMEGA_ADM_CMD_ERR;
    }
    /*
     * create socket between user space and kernel space.
     */
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        fprintf(stdout, "[%s]: can not create set socket\n", __FUNCTION__);
        return ASMEGA_ADM_CREATE_SOCKET_ERROR;
    }

    switch (dm_cmd) {
        case AM_CMD_SHOW:
            ret = getsockopt(sockfd, IPPROTO_IP, SOCKET_OPS_GET_ALL, buff,
                    &size);

            if(ret != 0) {
                fprintf(stdout, "[%s]: kernel not return the result\n",
                        __FUNCTION__);
                close(sockfd);
                return ASMEGA_ADM_GET_SOCKOPT_FAILED_ERROR;
            }

            if((size % sizeof(am_tnl_info_t)) != 0) {
                fprintf(stdout, "[%s]: wrong buff size (%d) get from kernel\n",
                        __FUNCTION__, size);
                close(sockfd);
                return ASMEGA_ADM_GET_SOCKOPT_BUFF_SIZE_ERROR;
            }
            tnl_num = size / sizeof(am_tnl_info_t);

            if(tnl_num > MAX_VIEW_ID_NUM) {
                fprintf(stdout, "[%s]: wrong tunnel number (%d) get from kernel\n",
                        __FUNCTION__, tnl_num);
                close(sockfd);
                return ASMEGA_ADM_GET_SOCKOPT_TNL_NUM_ERROR;
            }

            tnl_list = (am_tnl_info_t *) buff;

            /* print the result of command. */
            if ((options & OPT_ALL) != 0) {
                fprintf(stdout, "Total_Tunnel_Count: %d\n", tnl_num);
                fprintf(stdout, "----------------------------------------\n");
                for (i = 0; i < tnl_num; i++) {
                    fprintf(stdout, "Tunnel: %-10d    View: %d\n",
                            tnl_list[i].tnl_id, tnl_list[i].view_id);
                }
            } else if ((options & OPT_TNL_ID) != 0) {
                for (i = 0; i < tnl_num; i++) {
                    if(tnl_list[i].tnl_id == tnl_id) {
                        fprintf(stdout, "Tunnel: %-10d    View: %d\n",
                                tnl_list[i].tnl_id, tnl_list[i].view_id);
                        break;
                    }
                }
                if(i == tnl_num) {
                    fprintf(stdout, "Tunnel: %-10d    View: None\n", tnl_id);
                }
            } else {
                for (i = 0; i < tnl_num; i++) {
                    if (tnl_list[i].view_id == view_id) {
                        fprintf(stdout, "Tunnel: %-10d    View: %d\n",
                                tnl_list[i].tnl_id, tnl_list[i].view_id);
                        break;
                    }
                }
                if (i == tnl_num) {
                    fprintf(stdout, "Tunnel: None          View: %d\n", view_id);
                }
            }
            break;
        case AM_CMD_BIND:
            tnl_list = (am_tnl_info_t *) buff;
            tnl_list->tnl_id = tnl_id;
            tnl_list->view_id = view_id;
            ret = setsockopt(sockfd, IPPROTO_IP, SOCKET_OPS_SET_BIND, buff,
                    sizeof(am_tnl_info_t));
            if (ret != 0) {
                fprintf(stdout, "[%s]: failed to bind tunnel (%d) to view (%d)\n",
                        __FUNCTION__, tnl_id, view_id);
                close(sockfd);
                return ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR;
            }

            break;
        case AM_CMD_UNBIND:
            if((options & OPT_ALL) != 0) {
                ret = setsockopt(sockfd, IPPROTO_IP, SOCKET_OPS_SET_CLEAR, buff, 0);
                if (ret != 0) {
                    fprintf(stdout,
                            "[%s]: failed to clear all binding info between tunnel and view\n",
                            __FUNCTION__);
                    close(sockfd);
                    return ASMEGA_ADM_SET_SOCKOPT_CLEAR_ERROR;
                }
            } else {
                tnl_list = (am_tnl_info_t *) buff;
                tnl_list->tnl_id = tnl_id;
                tnl_list->view_id = view_id;
                ret = setsockopt(sockfd, IPPROTO_IP, SOCKET_OPS_SET_UNBIND, buff,
                        sizeof(am_tnl_info_t));
                if (ret != 0) {
                    fprintf(stdout, "[%s]: failed to unbind tunnel (%d) and view (%d)\n",
                            __FUNCTION__, tnl_id, view_id);
                    close(sockfd);
                    return ASMEGA_ADM_SET_SOCKOPT_UNBIND_ERROR;
                }
            }
            break;
        default:
            break;
    }
    close(sockfd);

    return ASMEGA_ADM_OK;
}

static void asmega_adm_log_write(int argc, char **argv, int ret, int op_msec)
{
    int i;
    size_t used_len = 0;
    struct timeval tv;
    struct tm tm;
    char log_buf[LOG_BUFF_LEN];

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&(tv.tv_sec), &tm);

    used_len +=
        snprintf(log_buf + used_len, LOG_BUFF_LEN - used_len,
                 "%02d-%02d-%04d %02d:%02d:%02d.%ld [RET=%d]:", tm.tm_mday,
                 tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min,
                 tm.tm_sec, tv.tv_usec / 1000, ret);
    for (i = 0; i < argc; ++i) {
        used_len +=
            snprintf(log_buf + used_len, LOG_BUFF_LEN - used_len, " %s",
                     argv[i]);
    }
    used_len +=
        snprintf(log_buf + used_len, LOG_BUFF_LEN - used_len, ", %dms",
                 op_msec);
    log_buf[used_len++] = '\n';

    write(g_log_fd, log_buf, used_len);

    return;
}

int main(int argc, char **argv)
{
    int ret, op_msec;
    struct timeval start, end;

    gettimeofday(&start, NULL);

    ret = parse_opt(argc, argv);

    gettimeofday(&end, NULL);
    op_msec = (end.tv_sec - start.tv_sec) * 1000
            + (end.tv_usec - start.tv_usec) / 1000;
    g_log_fd = open(g_adm_log_file, O_WRONLY | O_APPEND | O_CREAT | O_SYNC,
            0666);
    if (g_log_fd < 0) {
        fprintf(stdout, "ERROR : open %s to write faild : %s\n", g_adm_log_file,
                strerror(errno));
        return -1;
    }

    asmega_adm_log_write(argc, argv, ret, op_msec);

    close(g_log_fd);

    return ret;
}
