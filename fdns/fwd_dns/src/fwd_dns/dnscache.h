#ifndef _ADNS_DNSCACHE_H_
#define _ADNS_DNSCACHE_H_

#include <stdio.h>
#include <stdlib.h>

#include "list.h"
#include "iplib.h"
#include "log.h"
#include "user_config.h"
#include "view.h"
#include "stats.h"

#define MAX_SOURCE_IP_NUM 255
#define MAX_DOMAIN_LEN 256
#define MAX_SOURCE_IN_OPT 16
#define MAX_SOURCE_LEN_TYPE_NUM 5

typedef uint32_t zone_id_t;

extern uint32_t g_dnscache_max_num;
extern uint32_t g_src_len_max_num[];
extern uint16_t g_src_len_max_lens[];
extern uint32_t g_dnscache_queue_offset;

enum {
    DNSCACHE_SET = 0,
    DNSCACHE_UPDATE,
};

struct dnscache_source_node {
    uint32_t ip_addr;
    uint32_t port;
    uint16_t down;
    uint8_t state;
}; // __rte_cache_aligned;

struct dnscache_source_info {
	struct rte_mempool *mp;
	zone_id_t zone_id;
	uint32_t serials;
    uint32_t cache_ttl_max;
    uint32_t cache_ttl_min;
    uint8_t src_len;
    uint8_t src_ecs;
    uint8_t src_ptr;
    uint8_t src_state;
    struct dnscache_source_node source[0];
};

struct dnscache_node {
    struct list_head node_list;
    char domain_name[MAX_DOMAIN_LEN];
    uint8_t dlen;
    struct dnscache_source_info *src_info;
};

static inline struct dnscache_source_node * get_source_node(
		struct dnscache_source_info *src_info, uint32_t ip_addr, uint32_t port) {
    int i;
    struct dnscache_source_node *src_nodes = src_info->source;

    for (i = 0; i < src_info->src_len; i++) {
        if (src_nodes[i].ip_addr == ip_addr && src_nodes[i].port == port) {
            return &src_nodes[i];
        }
    }

    return NULL;
}

static inline void set_src_state_s(struct dnscache_source_node *src_node,
		struct dnscache_source_info *src_info, uint8_t x) {
    int i = 0;
    int up = 0;

    if (x == DOWN) {
        int max = 1000;
        src_node->down = src_node->down + 1;

        if (src_node->down > max)
            src_node->down = max;

        if (src_node->state == DOWN || src_node->down < g_forwarder_fail_down) {
            return;
        }

        //down
        src_node->state = DOWN;
        STATS(AUTH_SRC_DOWN);

        for (i = 0; i < src_info->src_len; i++) {
            if (src_info->source[i].state == UP) {
                up = 1;
                break;
            }
        }

        if (!up) {
            STATS(AUTH_NODE_DOWN);
            src_info->src_state = DOWN;
        }
        return;
    }
    // if x == UP
    if (src_node->down > 0) {
        src_node->down = 0;
    }

    //down to up
    if (src_node->state == DOWN) {
        src_node->state = UP;
    }

    if (src_info->src_state == DOWN) {
    	src_info->src_state = UP;
    }
}

static inline void set_src_state(uint32_t ip, uint16_t port,
		struct dnscache_source_info *src_info, uint8_t x) {
    struct dnscache_source_node *src_node = get_source_node(src_info, ip, port);
    if (src_node == NULL) {
        return;
    }

    set_src_state_s(src_node, src_info, x);
}

static inline void dnscache_queue_offset_set(uint32_t offset) {
    g_dnscache_queue_offset = offset;
}

static inline uint32_t dnscache_queue_offset_get() {
    return g_dnscache_queue_offset;
}

int dnscache_node_init();
void dnscache_node_free(struct dnscache_node *n);
struct dnscache_node *dnscache_node_new(uint8_t * qkey, uint16_t klen,
        zone_id_t zone_id, uint32_t max_ttl, uint32_t min_ttl,
        uint8_t sourceedns, uint8_t iplen, uint8_t **iplist);
struct dnscache_source_info* dnscache_source_info_new(zone_id_t zone_id,
		uint32_t max_ttl, uint32_t min_ttl, uint8_t sourceedns, uint8_t iplen,
		uint8_t **iplist);
void dump_dnscache_node(FILE *fp, struct dnscache_node *node);


#endif
