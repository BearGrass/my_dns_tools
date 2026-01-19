/*
 * Copyright (C)
 * Filename: cache.h
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#ifndef __CACHE_H__
#define __CACHE_H__

#include <linux/list.h>
#include <linux/types.h>

#include "dns.h"
#include "util.h"

// the number of hash slot
#define DM_DOMAIN_CACHE_HASH_SIZE (128 * 1024 * 1024)
#define NAME_MAX_LEN 256

/*
 * cache_find's result
 * CACHE_FIND means found cache which in trusted time.
 * CACHE_UPDATE means found cache which alived time is over.
 * trusted time,and we will try to update cache.
 * CACHE_INSERT means mega could not find cache and would insert a new cache node.
 * CACHE_DROP drop the request.
 * CACHE_HOLD means mega has no cache,but already sent a request to backend,
 * we should hold it waiting for BIND's answer.
 * CACHE_ERR means something error.
 */
#define CACHE_FIND 1
#define CACHE_UPDATE 2
#define CACHE_INSERT 3
#define CACHE_DROP 4
#define CACHE_HOLD 5
#define CACHE_ERR -1

/* used in flush_wait_list */
#define SAVESKB 1
#define NOSAVESKB 0

//if the number of IP beyond 13,the package may over 512 bytes.
//#define MAX_RR_IP_NUM 13
//the max number of answers in cache
#define MAX_ANSWER_NUM 13

/* hash slot struct */
struct dm_cache_hash {
    struct list_head list; /* hash conflict list */
    rwlock_t l;
    int size;
};

/*
 * offset is calculate from dnshdr
 * value save ip
 */
struct ips {
    int offset;
    char value[4];
};

/*
 * list[0] is the IP offset
 * list[1] is the IP value
 * len is 0 means SERVERFAIL or NXDOMAIN
 */
struct ip_list {
    struct ips list[MAX_ANSWER_NUM];
    int len;
};

/* node in dns mega */
struct node_t {
    /* base variable */
    struct value_t *key;         /* node's hash key qname+qtype */
    struct value_t *val;         /* skb from BIND */
    struct list_head node_list;  /* conflict list */

    /* states variable */
    uint64_t ctime;              /* the create time of cache */
    uint32_t last_prefetch_time;
    unsigned long cached_jiffies;
    struct list_head wait_list;  /* requst's wait list */
    struct ip_list ip_list; /* request's ip list */

    /* control variable */
    uint8_t wait_size;               /* how many DNS query received from client */
    uint16_t forward_port;
    uint8_t prefetch;            /* mark of prefetch */
    uint8_t protect;             /* mark of protect*/
    struct list_head forward_timer_list; /* forward timer */
    struct list_head expire_timer_list;  /* cache expire time timer */
    rwlock_t l;                  /* update lock */
};

/* general string */
struct value_t {
    uint16_t len;
    uint8_t buf[0];
};

/*
 * node of request used in wait list
 * witch is waitting for Mega's answer
 */
struct request_t {
    struct sk_buff *skb;       /* request origin skb */
    /* DOIT: use some dns feature to mark the request for decrease wait list space
     * uint16_t id;
     * uint32_t real_ip;
     * uint8_t i_port;
     * uint8_t *key;
     * uint8_t flags2;
     * uint16_t klen;
     */
    struct list_head list;
} __attribute__ ((packed));

extern struct dm_cache_hash *g_domain_cache_hash;

/* judge the value of cache node is equal to k or not */
extern int match_node(struct node_t *n, const uint8_t * k, uint16_t klen);

/* clear all cache */
extern void cache_clear(void);

/* insert a node to cache */
extern int cache_insert(struct sk_buff *skb, const uint8_t * qkey,
        int klen, struct node_t **n, struct dm_cache_hash *hash_bucket);

/* try to find a node in cache.
 * could return 5 results
 * more detail could find at the above of file(cache_find's result)
 */
extern int cache_find(const uint8_t * qkey, int klen, struct sk_buff *skb,
        struct node_t **node_find, struct dm_cache_hash *hash_bucket);

extern int dm_cache_init(void);
extern void dm_cache_exit(void);
/* generate a mega node */
extern struct node_t *get_node(const uint8_t * key, int klen);
struct request_t *get_request(struct sk_buff *skb);
/* put request r in n's wait list */
int put_request_to_node(struct node_t *n, struct request_t *r);

/* get hash value by qkey */
uint32_t hash_val(const char *qkey, int klen);
/* delete a mega node */
void put_node(struct node_t *n);
void __put_node(struct node_t *n);
/* delete a node in waitlist */
void put_request(struct request_t *r);

/* update a node */
int update_node(struct node_t *n, const char *val, int vlen, struct dm_dnsans dnsans[], int ansnum);
/* clear all req in wait list */
void flush_wait_list(struct node_t *n);
/* get all req from wait list and clear them*/
void pop_req_from_wait_list(struct node_t *n, struct sk_buff **send_skbs, int *send_num);
/* update ip list */
void update_ip_list(struct node_t *n, struct dm_dnsans dnsans[], int ansnum);
#endif                          /* __CACHE_H__ */
