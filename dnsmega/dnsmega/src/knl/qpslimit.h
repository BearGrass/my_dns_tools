/*
 * Copyright (C)
 * Filename: qpslimit.h
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 * limit dns query for every IP
 */
#ifndef __QPSLIMIT_H__
#define __QPSLIMIT_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jhash.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>

/* must be power of 2 */
#define IPLIMIT_SIZE (1 << 24)
#define MAX_IP_LIMIT_NUM 128

#define DROPPED 1
#define NOTDROP 2

#define DM_IP_LIMIT_QPS 0
#define DM_IP_REC_LIMIT_QPS 1

struct ip_limit_st{
    uint64_t check_cycle;
    uint64_t tokens;
    uint32_t ip;
    uint8_t  drop;
};

struct ip_limit_list_t {
    uint32_t list[MAX_IP_LIMIT_NUM];
    int len;
};

extern struct ip_limit_list_t ip_limit_list;
extern struct ip_limit_list_t ip_rec_limit_list;
extern struct rb_root g_ip_limit_root;
extern struct rb_root g_ip_rec_limit_root;
extern rwlock_t g_ip_pool_l;
extern rwlock_t g_ip_rec_pool_l;
typedef struct limit_ip_pool {
    struct rb_node node;
    uint32_t ip;
}ip_pool;

int limit_ip_pool_insert(struct rb_root *root, ip_pool *new, rwlock_t *lock);
int __limit_ip_pool_insert(struct rb_root *root, ip_pool *new);
ip_pool* limit_ip_pool_search(struct rb_root *root, uint8_t ip);

extern struct ip_limit_st *g_ip_limit_list;
extern struct ip_limit_st *g_ip_rec_limit_list;
extern uint64_t g_ip_qps_limit_size;

extern int ip_traffic_control(uint32_t sip, int qps, int flag);
extern int dm_qpslimit_init(void);
extern void dm_qpslimit_exit(void);

#endif
