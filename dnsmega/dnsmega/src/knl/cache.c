/*
 * Copyright (C)
 * Filename: cache.c
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description: domain cache struct file
 */

#include <linux/udp.h>

#include "cache.h"
#include "util.h"
#include "stats.h"
#include "timer.h"
#include "lock.h"
#include "control.h"
#include "consts.h"

int g_domain_cache_hash_size = DM_DOMAIN_CACHE_HASH_SIZE;

extern struct dm_cache_timer g_cache_timer_list;

struct dm_cache_hash *g_domain_cache_hash;

static struct kmem_cache *g_node_cache __read_mostly;
static struct kmem_cache *g_request_cache __read_mostly;

int put_request_to_node(struct node_t *n, struct request_t *r)
{
    write_trylock_bh(&n->l);
    if (n->wait_size >= sysctl_dm_req_waitlist_num) {
        if (unlikely(DM_GET_ESTATS(dm_esmib, DM_ERROR_WAITLIST) % 100 == 1)) {
            DM_INC_ESTATS(dm_esmib, DM_ERROR_WAITLIST);
            printk("[DNS Mega] n->wait_size error in %s", __func__);
        }
        write_unlock_bh(&n->l);
        return DM_ERROR;
    }
    list_add_tail(&r->list, &n->wait_list); /*link request to node */
    n->wait_size++;
    write_unlock_bh(&n->l);
    return DM_SUCCESS;
}

struct request_t *get_request(struct sk_buff *skb)
{
    struct request_t *r = kmem_cache_alloc(g_request_cache, GFP_ATOMIC);
    if (r == NULL) {
        DM_INC_ESTATS(dm_esmib, DM_ERROR_NOMEM_REQUEST);
        return NULL;
    }

    r->skb = skb;
    INIT_LIST_HEAD(&r->list);
    DM_INC_ESTATS(dm_esmib, DM_WAIT_REQUEST_NUM);
    return r;
}

void put_request(struct request_t *r)
{
    kmem_cache_free(g_request_cache, r);
    DM_DEC_ESTATS(dm_esmib, DM_WAIT_REQUEST_NUM);
}

void flush_wait_list(struct node_t *n)
{
    struct request_t *r, *r_tmp;
    write_trylock_bh(&n->l);
    list_for_each_entry_safe(r, r_tmp, &n->wait_list, list) {
        list_del(&r->list);
        kfree_skb(r->skb);
        put_request(r);
        DM_INC_ESTATS(dm_esmib, DM_DROP_HOLD_TIMEOUT);
    }
    n->wait_size = 0;
    write_unlock_bh(&n->l);
}

void pop_req_from_wait_list(struct node_t *n, struct sk_buff **send_skbs, int *send_num)
{
    struct request_t *r;
    struct request_t *r_tmp;
    write_trylock_bh(&n->l);
    /* Copy skb, send them later.
     * Because answer_from_node()->dev_queue_xmit() will be warned if called
     * in irqs disabled environment
     */
    list_for_each_entry_safe(r, r_tmp, &n->wait_list, list) {
        send_skbs[(*send_num)++] = r->skb;
        r->skb = NULL;
        list_del(&r->list);
        put_request(r);
        DM_INC_ESTATS(dm_esmib, DM_FWD_LOGIC_RESPONSE);
    }
    n->wait_size = 0;
    write_unlock_bh(&n->l);
}

void stop_timer(struct node_t *n)
{
    forward_timer_control(n, TIMER_INIT);
    expire_timer_control(n, TIMER_INIT);
}

struct node_t *get_node(const uint8_t * qkey, int klen)
{
    struct node_t *n;
    struct value_t *key;

    n = kmem_cache_alloc(g_node_cache, GFP_ATOMIC);
    if (n == NULL) {
        DM_INC_ESTATS(dm_esmib, DM_ERROR_NOMEM_NODE);
        return NULL;
    }

    INIT_LIST_HEAD(&n->wait_list);
    INIT_LIST_HEAD(&n->node_list);
    INIT_LIST_HEAD(&n->expire_timer_list);
    INIT_LIST_HEAD(&n->forward_timer_list);

    key = kmalloc(sizeof(struct value_t) + klen, GFP_ATOMIC);
    if (key == NULL) {
        DM_INC_ESTATS(dm_esmib, DM_ERROR_NOMEM_NODE_KEY);
        kmem_cache_free(g_node_cache, n);
        return NULL;
    }
    key->len = klen;
    memcpy(key->buf, qkey, klen);
    n->key = key;
    n->val = NULL;
    n->wait_size = 0;
    n->cached_jiffies = jiffies;
    n->ctime = jiffies;
    n->prefetch = 0;
    n->protect = 0;
    rwlock_init(&n->l);

    return n;
}

void __put_node(struct node_t *n)
{
    if (!list_empty(&n->node_list)) {
        list_del_init(&n->node_list);
    }

    if (!list_empty(&n->wait_list)) {
        flush_wait_list(n);
    }

    stop_timer(n);

    write_trylock_bh(&n->l);
    if (n->key) {
        kfree(n->key);
    }
    n->key = NULL;

    if (n->val) {
        kfree(n->val);
    }
    n->val = NULL;
    write_unlock_bh(&n->l);

    kmem_cache_free(g_node_cache, n);
    n = NULL;
}

void put_node(struct node_t *n)
{
    int hash_index = 0;
    struct dm_cache_hash *hash_bucket = NULL;

    read_trylock_bh(&n->l);
    if (n->key) {
        hash_index = hash_val(n->key->buf, n->key->len);
        hash_bucket = &g_domain_cache_hash[hash_index];
    }
    read_unlock_bh(&n->l);

    write_trylock_bh(&hash_bucket->l);
    if (n) {
        __put_node(n);
    }
    write_unlock_bh(&hash_bucket->l);
}
static inline uint8_t adns_wire_get_rcode(const uint8_t *packet)
{
    return *(packet + ADNS_WIRE_OFFSET_FLAGS2) & ADNS_WIRE_RCODE_MASK;
}

void update_ip_list(struct node_t *n, struct dm_dnsans dnsans[], int ansnum) {
    int i, ip_num;
    ip_num = 0;
    n->ip_list.len = 0;
    for(i = 0; i < ansnum; i ++) {
        if (dnsans[i].type == RR_TYPE_ANAME) {
            n->ip_list.list[ip_num].offset = dnsans[i].offset;
            memcpy(n->ip_list.list[ip_num].value, dnsans[i].data.ip, 4);
            ip_num++;
        }
    }
    n->ip_list.len = ip_num;
}

int __update_node(struct node_t *n, const char *val, int vlen,
        struct dm_dnsans dnsans[], int ansnum) {
    int ret;
    struct value_t *buf, *tmp;
    ret = DM_UPDATE_NODE;
    if (n->val) {
        if (n->val->buf) {
            if ((((adns_wire_get_rcode(val) == ADNS_RCODE_NXDOMAIN) && !sysctl_dm_update_nxdomain_on) ||
                 ((adns_wire_get_rcode(val) == ADNS_RCODE_SERVFAIL) && !sysctl_dm_update_servfail_on))
                 &&
                 (adns_wire_get_rcode(n->val->buf) == ADNS_RCODE_NOERROR)
               )

            {
                DM_INC_ESTATS(dm_esmib, DM_ERROR_RECURSIVE_NOANS);
                n->cached_jiffies = jiffies;
                n->prefetch = 0;
                n->protect = 1;
                return DM_ERROR;
            }
            if (n->val->len == vlen) {
                /* New & old value len is the same, don't need to kmalloc a new memory. */
                n->cached_jiffies = jiffies;
                n->prefetch = 0;
                n->protect = 0;
                memcpy(n->val->buf, val, vlen);
                update_ip_list(n, dnsans, ansnum);
                return ret;
            }
        }
    } else {
        /* n->val=NULL means a new node insert in cache */
        ret = DM_NEW_NODE;
        DM_INC_ESTATS(dm_esmib, DM_CACHE_WITH_ANSWER_NUM);
    }

    buf = kmalloc(sizeof(struct value_t) + vlen, GFP_ATOMIC);
    if (buf == NULL) {
        DM_INC_ESTATS(dm_esmib, DM_ERROR_NOMEM_NODE_VAL);
        return DM_ERROR;
    }
    n->cached_jiffies = jiffies;
    n->prefetch = 0;
    n->protect = 0;
    tmp = n->val;
    buf->len = vlen;
    memcpy(buf->buf, val, vlen);
    n->val = buf;
    /* kfree can judge either tmp is NULL or not */
    kfree(tmp);
    update_ip_list(n, dnsans, ansnum);
    return ret;
}

int update_node(struct node_t *n, const char *val, int vlen,
        struct dm_dnsans dnsans[], int ansnum)
{
    int ret;
    write_trylock_bh(&n->l);
    ret = __update_node(n, val, vlen, dnsans, ansnum);
    write_unlock_bh(&n->l);
    return ret;
}

uint32_t hash_val(const char *qkey, int klen)
{
    u32 hash;
    hash = jhash(qkey, klen, JHASH_INITVAL) & (g_domain_cache_hash_size - 1);
    return hash;
}

int match_node(struct node_t *n, const uint8_t * key, uint16_t klen)
{
    int min_len = 0;
    read_trylock_bh(&n->l);
    min_len = min(n->key->len, klen);

    if (memcmp(n->key->buf, key, min_len) == 0) {
        read_unlock_bh(&n->l);
        return DM_SUCCESS;
    }
    read_unlock_bh(&n->l);
    return DM_ERROR;
}

void cache_clear(void)
{
    int i;
    struct node_t *n, *n_tmp;

    for (i = 0; i < g_domain_cache_hash_size; i++) {
        write_trylock_bh(&g_domain_cache_hash[i].l);
        list_for_each_entry_safe(n, n_tmp, &g_domain_cache_hash[i].list,
                                 node_list) {
            __put_node(n);
            n = NULL;
        }
        write_unlock_bh(&g_domain_cache_hash[i].l);
    }
}

int dm_cache_init(void)
{
    int i, ret;

    /* create domain table */
    g_domain_cache_hash =
        (struct dm_cache_hash *)vmalloc(sizeof(struct dm_cache_hash) *
                                        g_domain_cache_hash_size);
    if (!g_domain_cache_hash) {
        pr_err("Allocation problem for domain table\n");
        ret = -ENOMEM;
        goto domain_cache_hash;
    }

    /* init domain table and domain lock */
    for (i = 0; i < g_domain_cache_hash_size; i++) {
        INIT_LIST_HEAD(&g_domain_cache_hash[i].list);
        rwlock_init(&g_domain_cache_hash[i].l);
    }

    /* create domain cache */
    g_node_cache =
        kmem_cache_create("dnsmega_node", sizeof(struct node_t), 0,
                          SLAB_HWCACHE_ALIGN, NULL);
    if (!g_node_cache) {
        pr_err("Allocation problem for struct g_node_cache\n");
        ret = -ENOMEM;
        goto node_cache;
    }

    /* create domain cache */
    g_request_cache =
        kmem_cache_create("dnsmega_request", sizeof(struct request_t), 0,
                          SLAB_HWCACHE_ALIGN, NULL);
    if (!g_request_cache) {
        pr_err("Allocation problem for struct g_request_cache\n");
        ret = -ENOMEM;
        goto request_cache;
    }

    pr_info("DNS Mega cache initialization successful\n");
    return 0;

request_cache:
    kmem_cache_destroy(g_node_cache);
node_cache:
    vfree(g_domain_cache_hash);
domain_cache_hash:
    return ret;
}

void dm_cache_exit(void)
{
    sysctl_dm_on = 0;
    cache_clear();
    kmem_cache_destroy(g_request_cache);
    kmem_cache_destroy(g_node_cache);
    vfree(g_domain_cache_hash);
    pr_info("DNS Mega cache exit successful\n");
}
