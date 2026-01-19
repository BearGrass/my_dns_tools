/*
 * Copyright (C)
 * Filename: manage.h
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 */

#ifndef __MANAGE_H__
#define __MANAGE_H__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <asm/uaccess.h>

#include "dns.h"
#include "cache.h"

#define DOMAIN_LEN_MAX 256

/* 128 is to prevent conflict with kernel opt number */
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

struct resource_record {
    char query[256];
    char answer[256];
    char type[10];
    int ttl;
};

/* save a simple infomation of node_t,
 * util/dnsmega_adm.c will print the struct to console
 */
struct cache_info {
    struct resource_record rr[MAX_ANSWER_NUM];
    int rr_num;
    int ctime;
    int mtime;
    int protect;
};

extern void get_domain_name(struct dm_dnshdr *dnshdr, int maxlen, char **p, char *out, int *len);
extern int dm_manage_init(void);
extern void dm_manage_exit(void);

#endif                          /* __MANAGE_H__ */
