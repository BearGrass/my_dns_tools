/*
 * Copyright (C)
 * Filename: qpslimit.c
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 * limit dns query for every IP
 */

#include <linux/slab.h>

#include "util.h"
#include "stats.h"
#include "qpslimit.h"
#include "lock.h"

uint64_t g_ip_qps_limit_size = IPLIMIT_SIZE;
struct ip_limit_st *g_ip_limit_list;
struct ip_limit_st *g_ip_rec_limit_list;
struct rb_root g_ip_limit_root;
struct rb_root g_ip_rec_limit_root;
struct ip_limit_list_t ip_limit_list, ip_rec_limit_list;
rwlock_t g_ip_pool_l;
rwlock_t g_ip_rec_pool_l;

int limit_ip_pool_insert(struct rb_root *root, ip_pool *new, rwlock_t *lock) {
    int ret;
    write_trylock_bh(lock);
    ret = __limit_ip_pool_insert(root, new);
    write_unlock_bh(lock);
    return ret;
}

int __limit_ip_pool_insert(struct rb_root *root, ip_pool *new) {
    struct rb_node **now = &(root->rb_node), *parent = NULL;
    ip_pool *treenode;
    int temp;
    while ( *now != NULL ) {
        treenode = rb_entry(*now, ip_pool, node);
        temp = treenode->ip - new->ip;
        if (temp > 0) {
            now = &((*now)->rb_right);
        } else if (temp < 0) {
            now = &((*now)->rb_left);
        } else {
            return DM_ERROR;
        }
    }
    rb_link_node(&new->node, parent, now);
    rb_insert_color(&new->node, root);
    return DM_SUCCESS;
}

ip_pool* limit_ip_pool_search(struct rb_root *root, uint8_t ip) {
    struct rb_node *now = root->rb_node;
    ip_pool *treenode;
    uint8_t temp;
    while ( now != NULL ) {
        treenode = rb_entry(now, ip_pool, node);
        temp = treenode->ip - ip;
        if (temp >0) {
            now = now->rb_right;
        } else if (temp < 0) {
            now = now->rb_left;
        } else {
            return treenode;
        }
    }
    return NULL;
}

static int rate_proc(struct ip_limit_st *lim, int qps, struct rb_root *root, rwlock_t *lock) {
    uint64_t diff, now, check_cycle;
    int64_t toks;
    int ret;
    ip_pool *limit_node;
    now = jiffies;
    check_cycle = lim->check_cycle;
    diff = now - check_cycle;

    if (check_cycle == 0) {
        lim->check_cycle = jiffies;
        lim->tokens = qps;
        goto xmit;
    }

    if (diff < HZ) {
        goto xmit;
    }

    toks = (diff * qps) / HZ;
    lim->tokens += toks;
    if (toks != 0)
        lim->check_cycle = jiffies;

    if(lim->tokens > qps)
        lim->tokens = qps;
xmit:
    if(lim->tokens > 0){
        lim->tokens--;
        lim->drop = NOTDROP;
        return DM_SUCCESS;
    }
    if (lim->drop != DROPPED) {
        limit_node = (struct limit_ip_pool*)
            kmalloc(sizeof(struct limit_ip_pool),GFP_ATOMIC);
        if (limit_node == NULL) {
            return DM_ERROR;
        }
        limit_node->ip = lim->ip;
        ret = limit_ip_pool_insert(root, limit_node, lock);
    }
    lim->drop = DROPPED;
    return DM_ERROR;
}

int ip_traffic_control(uint32_t sip, int qps, int flag) {
    int index = (jhash_1word(sip, 0) & (g_ip_qps_limit_size - 1));
    if (flag == DM_IP_LIMIT_QPS) {
        g_ip_limit_list[index].ip = sip;
        return rate_proc(g_ip_limit_list + index, qps, &g_ip_limit_root, &g_ip_pool_l);
    } else if (flag == DM_IP_REC_LIMIT_QPS) {
        g_ip_rec_limit_list[index].ip = sip;
        return rate_proc(g_ip_rec_limit_list + index, qps, &g_ip_rec_limit_root, &g_ip_rec_pool_l);
    }
    return DM_SUCCESS;
}

int ip_limit_init(struct ip_limit_st **limit_list) {
    int i, ret = DM_SUCCESS;
    *limit_list =
        (struct ip_limit_st *)vmalloc(sizeof(struct ip_limit_st)
                *g_ip_qps_limit_size);
    if (!(*limit_list)) {
        pr_err("Allocation problem for qpslimit\n");
        ret = -ENOMEM;
        return ret;
    }
    for(i = 0; i < g_ip_qps_limit_size; i ++) {
        (*limit_list)[i].check_cycle = 0;
        (*limit_list)[i].tokens = 0;
        (*limit_list)[i].ip = 0;
        (*limit_list)[i].drop= NOTDROP;
    }
    return ret;
}

int dm_qpslimit_init(void) {
    int ret;
    g_ip_limit_root = RB_ROOT;
    rwlock_init(&g_ip_pool_l);
    ret = ip_limit_init(&g_ip_limit_list);
    ip_limit_list.len = 0;
    if (ret == -ENOMEM) {
        return ret;
    }

    g_ip_rec_limit_root = RB_ROOT;
    rwlock_init(&g_ip_rec_pool_l);
    ret = ip_limit_init(&g_ip_rec_limit_list);
    ip_rec_limit_list.len = 0;
    if (ret == -ENOMEM) {
        return ret;
    }
    pr_info("DNS Mega qpslimit initialization successful\n");
    return ret;
}

void dm_qpslimit_exit(void) {
    vfree(g_ip_limit_list);
    vfree(g_ip_rec_limit_list);
    pr_info("DNS Mega qpslimit exit successful\n");
}
