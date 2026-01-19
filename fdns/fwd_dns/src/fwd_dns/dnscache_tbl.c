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
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "dnscache_tbl.h"
#include "common.h"
#include "log.h"
#include "ldns.h"
#include "dname.h"
#include "snapshot.h"

struct dnscache_node_tbl *g_dnscache_node_tbl = NULL;

/* Init Function */
int dnscache_node_tbl_init(struct dnscache_node_tbl **dnscache_node_tbl)
{
    uint32_t i;
    char name[32];
    struct dnscache_node_tbl *tbl = NULL;

    snprintf(name, 32, "%s", "dnscache_node_tbl");

    tbl = rte_zmalloc_socket(name, sizeof(struct dnscache_node_tbl), 0, rte_socket_id());
    if (tbl == NULL) {
        RTE_LOG(ERR, LDNS, "[%s]: Failed to alloc dnscache_node_tbl %s\n",
                __FUNCTION__, name);
        return -1;
    }

    RTE_LOG(INFO, LDNS, "[%s]: Finish to new dnscache node table %s\n",
            __FUNCTION__, name);
    /* zmalloc has set all memory to zero, so need not to initialize zero value again */

    for (i = 0; i < DNSCACHE_NODE_HASH_SIZE; i++) {
        INIT_LIST_HEAD(&(tbl->dnscache_nodes[i].list));
    }

    *dnscache_node_tbl = tbl;

    return 0;
}

/* Init Function */
int dnscache_init(struct dnscache_node_tbl **dnscache_node_tbl)
{
    if (dnscache_node_tbl_init(dnscache_node_tbl) < 0) {
        return -1;
    }

    if (dnscache_node_init() < 0) {
        return -1;
    }

    return 0;
}


void dnscache_node_tbl_clear(struct dnscache_node_tbl *dnscache_node_tbl)
{
    uint32_t i;
    struct dnscache_hash_node *hash_node;
    struct dnscache_node *it, *it_nxt;

    dnscache_node_tbl->cnt = 0;
    dnscache_node_tbl->max_level = 0;

    for (i = 0; i < DNSCACHE_NODE_HASH_SIZE; i++) {
        hash_node = &dnscache_node_tbl->dnscache_nodes[i];
        list_for_each_entry_safe(it, it_nxt, &hash_node->list,
                node_list)
        {
            list_del(&(it->node_list));
            dnscache_node_free(it);
        }
    }
}


static struct dnscache_node * __dnscache_node_tbl_lookup(
        const struct dnscache_node_tbl *dnscache_node_tbl, const uint8_t * qkey,
        uint16_t klen) {
    struct dnscache_node *node;
    uint32_t hash;
    const struct list_head *h_list;
    const struct dnscache_hash_node *h_node;

    hash = mm3_hash_mod((const char *) qkey, klen, DNSCACHE_NODE_HASH_SIZE);
    h_node = &dnscache_node_tbl->dnscache_nodes[hash];
    h_list = &(h_node->list);

    list_for_each_entry(node, h_list, node_list)
    {
        if (node->dlen == klen && !memcmp(qkey, node->domain_name, klen)) {
            return node;
        }
    }
    return NULL;
}

struct dnscache_node *dnscache_zone_lookup(
        const struct dnscache_node_tbl *dnscache_node_tbl,
        struct dns_packet *pkt, const uint8_t *qname) {
    struct dnscache_node *dc_node = NULL;
    int labels = pkt->labels;
    const uint8_t *zone_name = qname;

    if(unlikely(dnscache_node_tbl->max_level == 0)) {
        return NULL;
    }

    if (pkt->labels > dnscache_node_tbl->max_level) {
        labels = dnscache_node_tbl->max_level;
        zone_name = qname + pkt->label_offset[pkt->labels - labels];
    }

    for (; labels >= 2; --labels) {
        dc_node = __dnscache_node_tbl_lookup(dnscache_node_tbl, zone_name,
                pkt->qname_size - pkt->label_offset[pkt->labels - labels]);
        if (dc_node != NULL) {
			if (dc_node->src_info->src_len != 0) {
				pkt->zname_offset = pkt->label_offset[pkt->labels - labels];
				break;
			} else {
				dc_node = NULL;
			}
        }
        zone_name += *zone_name + 1;
    }

    return dc_node;
}

int dnscache_node_tbl_add_node(struct dnscache_node_tbl *dnscache_node_tbl,
        uint8_t * qkey, uint16_t klen, zone_id_t zone_id, uint32_t max_ttl,
        uint32_t min_ttl, uint8_t sourceedns, uint8_t status, uint8_t iplen,
        uint8_t **iplist, struct dnscache_node **new_node)
{
    uint32_t hash;
    struct dnscache_node *node;
    struct list_head *h_list;
    struct dnscache_hash_node *h_node;
    struct dnscache_source_info *src_info, *tmp_src_info;
    int lbs;

    hash = mm3_hash_mod((const char *)qkey, klen, DNSCACHE_NODE_HASH_SIZE);
    h_node = &dnscache_node_tbl->dnscache_nodes[hash];
    h_list = &(h_node->list);

    list_for_each_entry(node, h_list, node_list) {
        if (node->dlen == klen && !memcmp(qkey, node->domain_name, klen)) {
        	/*
            RTE_LOG(WARNING, LDNS, "[%s] dnscache node is existed\n",
                            __FUNCTION__);
                            */
            if (status == 0) {
                return dnscache_node_tbl_del_node(dnscache_node_tbl, node);
            }

            if (unlikely(iplen == 0)) {
                ALOG(SERVER, WARN, "DNSCACHE: update zone [%s], but iplen is 0, keep the old source ips!\n", qkey);
                node->src_info->cache_ttl_max = max_ttl;
                node->src_info->cache_ttl_min = min_ttl;
                node->src_info->src_ecs = sourceedns;
                node->src_info->zone_id = zone_id;
                node->src_info->serials = node->src_info->serials + 1;
            } else {
				src_info = dnscache_source_info_new(zone_id, max_ttl, min_ttl,
						sourceedns, iplen, iplist);
				if (unlikely(src_info == NULL)) {
					return -1;
				}

				if (likely(node->src_info != NULL)) {
					src_info->serials = node->src_info->serials + 1;
					tmp_src_info = node->src_info;
					node->src_info = src_info;
					rte_mempool_put(tmp_src_info->mp, (void*) tmp_src_info);
				} else {
					node->src_info = src_info;
				}
			}
			*new_node = node;

            return 0;
        }
    }

    if (status == 0) {
        ALOG(SERVER, WARN, "DNSCACHE: delete zone [%s], but it is not existing",
                qkey);
        return 0;
    }

    if (iplen == 0) {
        ALOG(SERVER, WARN, "DNSCACHE: add zone [%s], but iplen is 0\n", qkey);
    }
	node = dnscache_node_new(qkey, klen, zone_id, max_ttl, min_ttl, sourceedns,
			iplen, iplist);
    if (unlikely(node == NULL)) {
        return -1;
    }

    list_add(&(node->node_list), h_list);
    dnscache_node_tbl->cnt++;
    *new_node = node;

    lbs = adns_dname_labels(qkey);
    if (lbs > dnscache_node_tbl->max_level) {
        dnscache_node_tbl->max_level = (uint8_t)lbs;
    }

    return 0;
}

/* This function only used when add node from command line */
int dnscache_node_tbl_del_node_by_key(struct dnscache_node_tbl *dnscache_node_tbl,
        const uint8_t * qkey, uint16_t klen)
{
    struct dnscache_node *node;
    uint32_t hash;
    struct list_head *h_list;
    struct dnscache_hash_node *h_node;

    hash = mm3_hash_mod((const char *) qkey, klen, DNSCACHE_NODE_HASH_SIZE);
    h_node = &dnscache_node_tbl->dnscache_nodes[hash];
    h_list = &(h_node->list);

    list_for_each_entry(node, h_list, node_list)
    {
        if (node->dlen == klen && !memcmp(qkey, node->domain_name, klen)) {
            list_del(&node->node_list);
            dnscache_node_free(node);

            if (unlikely(dnscache_node_tbl->cnt == 0)) {
                RTE_LOG(ERR, LDNS, "[%s]: The node table cnt is 0\n",
                        __FUNCTION__);
            } else {
                dnscache_node_tbl->cnt--;
            }

            return 0;
        }
    }

    /* need a set of dnscache error */
    //return MEGA_ADMIN_DEL_CACHE_NODE_LOOKUP_ERROR;
    return -1;
}

int dnscache_node_tbl_del_node(struct dnscache_node_tbl *dnscache_node_tbl, struct dnscache_node *node) {
    list_del(&node->node_list);
    dnscache_node_free(node);

    if (unlikely(dnscache_node_tbl->cnt == 0)) {
        RTE_LOG(ERR, LDNS, "[%s]: The node table cnt is 0\n",
                __FUNCTION__);
    } else {
        dnscache_node_tbl->cnt--;
        if (unlikely(dnscache_node_tbl->cnt == 0)) {
            dnscache_node_tbl->max_level = 0;
        }
    }

    return 0;
}

struct dnscache_node **dnscache_node_tbl_list(struct dnscache_node_tbl *dnscache_node_tbl)
{
    int i, z_count = 0;
    struct dnscache_node **z_list;
    struct dnscache_node *node;
    const struct list_head *h_list;
    const struct dnscache_hash_node *h_node;

    if (unlikely(dnscache_node_tbl == NULL || dnscache_node_tbl->cnt == 0)) {
        return NULL;
    }

    z_list = malloc(sizeof(struct dnscache_node *) * dnscache_node_tbl->cnt);
    if (z_list == NULL) {
        return NULL;
    }

    for (i = 0; i < DNSCACHE_NODE_HASH_SIZE; i++) {
        h_node = &dnscache_node_tbl->dnscache_nodes[i];
        h_list = &(h_node->list);

        list_for_each_entry(node, h_list, node_list)
        {
            z_list[z_count++] = node;
        }

        if (z_count > dnscache_node_tbl->cnt) {
            RTE_LOG(ERR, LDNS,
                    "[%s]: The actual cache node count is bigger than dnscache_node_tbl->cnt %d\n",
                    __FUNCTION__, dnscache_node_tbl->cnt);
            break;
        }
    }

    return z_list;
}

int dnscache_export_snapshot(struct dnscache_node_tbl *dnscache_node_tbl, FILE *fp) {
    uint32_t node_num = dnscache_node_tbl->cnt;
    uint32_t offset;
    int i;
    struct dnscache_node **list;
    uint8_t *p;
    snapshot_hdr_t hdr;

    hdr.snapshot_type = DNSCACHE_SNAPSHOT;
    hdr.payload_size = sizeof(node_num) + sizeof(offset);;
    list = dnscache_node_tbl_list(dnscache_node_tbl);
	for (i = 0; i < node_num; i++) {
		hdr.payload_size += sizeof(struct dnscache_snapshot);
		hdr.payload_size += sizeof(struct dnscache_snapshot_iplist)
				* list[i]->src_info->src_len;
	}

    p = (uint8_t*)&hdr;
    print_byte(fp, sizeof(snapshot_hdr_t), p);

    p = (uint8_t*)&node_num;
    print_byte(fp, sizeof(node_num), p);

    offset = dnscache_queue_offset_get();
    p = (uint8_t*)&offset;
    print_byte(fp, sizeof(offset), p);

    for (i = 0; i < node_num; i ++) {
        dump_dnscache_node(fp, list[i]);
    }
    return 0;
}

static int load_dnscache_node(FILE *fp,
		struct dnscache_node_tbl *dnscache_node_tbl, uint32_t *read_size) {
	struct dnscache_node *node = NULL;
	struct dnscache_snapshot snapshot;
	int ret, num;
	num = fread(&snapshot, sizeof(struct dnscache_snapshot), 1, fp);
	if (num != 1) {
		ALOG(SERVER, ERROR, "Reload snapshot error %u(%u)", num,
				sizeof(struct dnscache_snapshot));
		return -1;
	}
	*read_size += sizeof(struct dnscache_snapshot);
	struct dnscache_snapshot_iplist iplist[snapshot.ip_len];
	num = fread((void*) iplist, sizeof(struct dnscache_snapshot_iplist),
			snapshot.ip_len, fp);
	if (num != snapshot.ip_len) {
		ALOG(SERVER, ERROR, "Reload iplist buffer error %u(%u)", num,
				sizeof(iplist));
		return -1;
	}
	uint8_t *iplist_p = (uint8_t*) iplist;
	*read_size += sizeof(struct dnscache_snapshot_iplist) * snapshot.ip_len;
	ret = dnscache_node_tbl_add_node(dnscache_node_tbl, snapshot.qname,
			snapshot.dlen, snapshot.zone_id, snapshot.maxttl, snapshot.minttl,
			snapshot.sourceedns, 1, snapshot.ip_len, &iplist_p, &node);
	if (node != NULL) {
		node->src_info->serials = snapshot.serials;
	}

	return ret;
}

// TODO: opt point: calculate bytes of per struct of snapshot
// and read more buffer at once
int dnscache_import_snapshot(FILE *fp, uint32_t payload_size) {
    struct dnscache_node_tbl *new_dnscache_node_tbl = NULL;
    int i, ret, num;
    uint32_t node_num;
    uint32_t offset;
    uint32_t read_size = 0;
    struct dnscache_node_tbl *temp;

    num = fread(&node_num, 4, 1, fp);
    if (num != 1) {
        return 0;
    }
    read_size += sizeof(node_num);
    if (node_num <= 0) {
        return 0;
    }
    num = fread(&offset, 4, 1, fp);
    if (num != 1) {
        ALOG(SERVER, ERROR, "Reload queue offset error");
        return -1;
    }
    read_size += sizeof(offset);

    dnscache_node_tbl_init(&new_dnscache_node_tbl);
    if (new_dnscache_node_tbl == NULL) {
        ALOG(SERVER, ERROR, "Init new_dnscache_node_tbl error");
        return -1;
    }
    for (i = 0; i < node_num; i ++) {
        ret = load_dnscache_node(fp, new_dnscache_node_tbl, &read_size);
        if (ret < 0) {
            dnscache_node_tbl_clear(new_dnscache_node_tbl);
            ALOG(SERVER, ERROR, "Load dnscache node error");
            return -1;
        }
    }

	if (read_size != payload_size) {
		ALOG(SERVER, ERROR,
				"Actual read size (%u) is different with payload size(%u)!",
				read_size, payload_size);
		return -1;
	}
    temp = g_dnscache_node_tbl;
    g_dnscache_node_tbl = new_dnscache_node_tbl;
    dnscache_node_tbl_clear(temp);
    dnscache_queue_offset_set(offset);
    //TODO reset init status

    return 0;
}
