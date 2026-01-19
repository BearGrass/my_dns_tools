/*
 * Copyright (C)
 * Filename: dnsmega_adm.h
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 */

#ifndef __DNSMEGA_ADM_H__
#define __DNSMEGA_ADM_H__

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define DM_SUCCESS 0
#define DM_ERROR -1

#define ONE_DOMAIN 1
#define ALL_DOMAIN 2

#define DEFAULT_TYPE "A"

#define MAX_ANSWER_NUM 13

enum {
    DM_CMD_INIT = 1,
    DM_CMD_SHOW,
    DM_CMD_DELETE,
    DM_CMD_ACTIVE,
    DM_CMD_QPSLIMIT_SHOW,

    DM_CMD_ERR,
};

enum {
    SOCKET_OPS_SET_BASE = 128,
    SOCKET_OPS_SET_SEARCH,
    SOCKET_OPS_SET_CLEAR,
    SOCKET_OPS_SET_WHITE,
    SOCKET_OPS_SET_BLACK,
    SOCKET_OPS_SET_LIMITIP,

    SOCKET_OPS_SET_MAX,
};

enum {
    SOCKET_OPS_GET_BASE = 128,
    SOCKET_OPS_GET_SEARCH,
    SOCKET_OPS_GET_LIMITIP,

    SOCKET_OPS_GET_MAX,
};

struct dns_ans {
    char query[256];
    char answer[256];
    char type[10];
    int ttl;
};

struct cache_info {
    struct dns_ans ans[MAX_ANSWER_NUM];
    int ans_len;
    int ctime;
    int mtime;
    int protect;
};

#endif                          /* __DNSMEGA_ADM_H__ */
