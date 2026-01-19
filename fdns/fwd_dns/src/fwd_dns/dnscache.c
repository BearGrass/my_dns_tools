#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_string_fns.h>

#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_core.h>
#include <rte_kni.h>
#include <rte_ethdev.h>
#include <rte_interrupts.h>
#include <rte_memory.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "snapshot.h"
#include "dnscache.h"
#include "dnscache_tbl.h"
#include "common.h"
#include "log.h"
#include "ldns.h"


#define DEFAULT_MAX_DNSCACHE_NUM 1000000

struct rte_mempool *g_dnscache_node_pools;
static struct rte_mempool *g_dnscache_src_pools[MAX_SOURCE_LEN_TYPE_NUM] = {NULL};
uint32_t g_dnscache_queue_offset;
uint32_t g_src_len_max_num[MAX_SOURCE_LEN_TYPE_NUM] =
             { DEFAULT_MAX_DNSCACHE_NUM * 0.5,
               DEFAULT_MAX_DNSCACHE_NUM * 0.4,
			   DEFAULT_MAX_DNSCACHE_NUM * 0.05,
			   DEFAULT_MAX_DNSCACHE_NUM * 0.04,
			   DEFAULT_MAX_DNSCACHE_NUM * 0.01 };
uint16_t g_src_len_max_lens[MAX_SOURCE_LEN_TYPE_NUM] =
             { 16, 32, 64, 128, 256 };
uint32_t g_dnscache_max_num = DEFAULT_MAX_DNSCACHE_NUM;

/*
 * mega_node_value_obj constructor, given as a callback function to
 * rte_mempool_create().
 * Set the len_idx field of a node_val to corresponding value.
 */
static void
dnscache_node_val_obj_init(
         struct rte_mempool *mp,
         __attribute__((unused)) void *opaque,
         void *obj,
         __attribute__((unused)) unsigned obj_idx)
{
    struct dnscache_source_info *node_val = obj;
    //uint32_t *len_idx = opaque;

    node_val->mp = mp;
    //node_val->len_idx = *len_idx;
}

int dnscache_node_init() {
	char name[64];
	uint32_t i;

    g_dnscache_queue_offset = 0;
	g_dnscache_node_pools = rte_mempool_create("g_dnscache_node_pools",
			g_dnscache_max_num, sizeof(struct dnscache_node), 32, 0,
			NULL,
			NULL,
			NULL,
			NULL, rte_lcore_to_socket_id(rte_lcore_id()),
			MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
	if (g_dnscache_node_pools == NULL) {
		RTE_LOG(ERR, LDNS, "[%s]: Failed to alloc g_dnscache_node_pools\n",
				__FUNCTION__);
		return -1;
	}
	RTE_LOG(INFO, LDNS, "[%s]: Finish to alloc g_dnscache_node_pools\n",
			__FUNCTION__);

	for (i = 0; i < MAX_SOURCE_LEN_TYPE_NUM; ++i) {
		snprintf(name, sizeof(name), "g_dnscache_src_%d_pools",
				g_src_len_max_lens[i]);
		g_dnscache_src_pools[i] = rte_mempool_create(name, g_src_len_max_num[i],
				sizeof(struct dnscache_source_info)
						+ g_src_len_max_lens[i]
								* sizeof(struct dnscache_source_node), 32, 0,
				NULL, NULL, dnscache_node_val_obj_init, &i, rte_lcore_to_socket_id(rte_lcore_id()),
				MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
		if (g_dnscache_src_pools[i] == NULL) {
			RTE_LOG(ERR, LDNS,
					"[%s]: Failed to alloc g_dnscache_src_pools %s\n",
					__FUNCTION__, name);
			return -1;
		}
		RTE_LOG(INFO, LDNS, "[%s]: Finish to alloc g_dnscache_src_pools %s\n",
				__FUNCTION__, name);
	}

    return 0;
}

void dnscache_node_free(struct dnscache_node *n) {
	if (n->src_info != NULL) {
		rte_mempool_put(n->src_info->mp, (void*)n->src_info);
	}

    rte_mempool_put(g_dnscache_node_pools, (void *)n);
}

struct dnscache_node *dnscache_node_new(uint8_t * qkey, uint16_t klen,
        zone_id_t zone_id, uint32_t max_ttl, uint32_t min_ttl,
        uint8_t sourceedns, uint8_t iplen, uint8_t **iplist)
{
    struct dnscache_node *node;
    void *data = NULL;

    if (unlikely(
                rte_mempool_get(g_dnscache_node_pools, &data) < 0 || data == NULL)) {
        RTE_LOG(ERR, LDNS,
                "[%s]: rte_mempool_get failed, pool name = g_dnscache_node_pools\n",
                __FUNCTION__);
        return NULL;
    }
    node = (struct dnscache_node*)data;
    INIT_LIST_HEAD(&(node->node_list));
    memcpy(node->domain_name , qkey, klen);
    node->dlen = klen;
	node->src_info = dnscache_source_info_new(zone_id, max_ttl, min_ttl,
			sourceedns, iplen, iplist);
	if (unlikely(node->src_info == NULL)) {
		rte_mempool_put(g_dnscache_node_pools, (void*) node);
		return NULL;
	}

    return node;
}

struct dnscache_source_info* dnscache_source_info_new(zone_id_t zone_id,
		uint32_t max_ttl, uint32_t min_ttl, uint8_t sourceedns, uint8_t iplen,
		uint8_t **iplist) {
    int i;
    int j;
    void *data = NULL;
    struct dnscache_source_info *src_info;

    if (unlikely(iplen > MAX_SOURCE_IP_NUM)) {
		ALOG(SERVER, WARN, "DNS cache source num (%u) must less than %d\n",
				iplen, MAX_SOURCE_IP_NUM);
        return NULL;
    }

	for (i = 0; i < MAX_SOURCE_LEN_TYPE_NUM; ++i) {
		if (g_src_len_max_lens[i] >= iplen) {
			if (unlikely(
					rte_mempool_get(g_dnscache_src_pools[i], &data) < 0 || data == NULL)) {
				ALOG(SERVER, ERROR,
						"[%s]: g_dnscache_src_pools failed, len: %d, len index: %d\n",
						__FUNCTION__, iplen, i);
				// try to get a cache buffer from next pool
				continue;
			}
			src_info = (struct dnscache_source_info*) data;
			src_info->cache_ttl_max = max_ttl;
			src_info->cache_ttl_min = min_ttl;
			src_info->src_ecs = sourceedns;
			src_info->src_ptr = 0;
			src_info->src_state = 0;
			src_info->zone_id = zone_id;
			src_info->serials = 0;
		    for (j = 0; j < iplen; j ++) {
		    	src_info->source[j].ip_addr = *(uint32_t*)(*iplist);
		        (*iplist) += 4;
		        src_info->source[j].port = *(uint32_t*)(*iplist);
		        (*iplist) += 4;
		        src_info->source[j].down = 0;
		        src_info->source[j].state = UP;
		    }
		    src_info->src_len = iplen;

			return src_info;
		}
	}

    return NULL;
}

void dump_dnscache_node(FILE *fp, struct dnscache_node *node) {
    int i;
    uint8_t *p;
    struct dnscache_snapshot snapshot;
    memcpy(snapshot.qname, node->domain_name, MAX_DOMAIN_LEN);
    snapshot.serials = node->src_info->serials;
    snapshot.zone_id = node->src_info->zone_id;
    snapshot.dlen = node->dlen;
    snapshot.maxttl = node->src_info->cache_ttl_max;
    snapshot.minttl = node->src_info->cache_ttl_min;
    snapshot.sourceedns = node->src_info->src_ecs;
    snapshot.ip_len = node->src_info->src_len;
    p = (uint8_t*)&snapshot;
    print_byte(fp, sizeof(struct dnscache_snapshot), p);

    struct dnscache_snapshot_iplist iplist[snapshot.ip_len];
    int size = sizeof(struct dnscache_snapshot_iplist) * snapshot.ip_len;
    p = (uint8_t*)iplist;
    for (i = 0; i < node->src_info->src_len; i ++) {
        // print dnscache_source_node
        iplist[i].ip_addr = node->src_info->source[i].ip_addr;
        iplist[i].port = node->src_info->source[i].port;
    }
    print_byte(fp, size, p);
}
