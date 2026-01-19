#ifndef _ADNS_DNSCACHE_TBL_H_
#define _ADNS_DNSCACHE_TBL_H_

#include <stdio.h>

#include "list.h"
#include "murmurhash3.h"
#include "iplib.h"
#include "log.h"
#include "dnscache.h"
#include "dns_pkt.h"

#define DNSCACHE_NODE_HASH_SIZE (1<<16)
#define SNAPSHOT_SIZE (16+sizeof(zone_id_t))

struct dnscache_hash_node {
    struct list_head list;
};

struct dnscache_snapshot {
    uint8_t qname[MAX_DOMAIN_LEN];
    uint32_t serials;
    zone_id_t zone_id;
    uint8_t dlen;
    uint32_t maxttl;
    uint32_t minttl;
    uint8_t sourceedns;
    uint8_t ip_len;
} __attribute__((packed));

struct dnscache_snapshot_iplist {
    uint32_t ip_addr;
    uint32_t port;
} __attribute__((packed));

struct dnscache_node_tbl {
    struct dnscache_hash_node dnscache_nodes[DNSCACHE_NODE_HASH_SIZE];
    uint32_t cnt;
    uint8_t max_level;
};

extern struct dnscache_node_tbl *g_dnscache_node_tbl;
extern char *g_data_snapshort_path;


static inline struct dnscache_hash_node * __attribute__ ((always_inline))
dnscache_get_hash_node(const uint8_t * qkey, uint16_t klen) {
    return &g_dnscache_node_tbl->dnscache_nodes[mm3_hash_mod(
            (const char *) qkey, klen,
            DNSCACHE_NODE_HASH_SIZE)];
}

inline void set_snapshot_path(char *path);
int dnscache_init(struct dnscache_node_tbl **dnscache_node_tbl);
int dnscache_node_tbl_init(struct dnscache_node_tbl **dnscache_node_tbl);
void dnscache_node_tbl_clear(struct dnscache_node_tbl *dnscache_node_tbl);

struct dnscache_node *dnscache_zone_lookup(
        const struct dnscache_node_tbl *dnscache_node_tbl,
        struct dns_packet *pkt, const uint8_t *qname);
/*
 * Add a new dnscache node.
 *
 * This function check whether the dnscache node exist, if it is not exist,
 * will create a new one.
 *
 * @param qkey
 *   The query key of the new node.
 * @param klen
 *   The length of the query key.
 * @param new_node
 *   A pointer to the pointer of the new node or existing node.
 * @return
 *   - 0: Success; the node with qkey is not existing, created a new one.
 *   - 1: Success; the node with qkey is existing, return it.
 *   - <0: Failure；error occurs when create the cache node.
 */
int dnscache_node_tbl_add_node(struct dnscache_node_tbl *dnscache_node_tbl,
        uint8_t * qkey, uint16_t klen, zone_id_t zone_id, uint32_t max_ttl,
        uint32_t min_ttl, uint8_t sourceedns, uint8_t status, uint8_t iplen,
        uint8_t **iplist, struct dnscache_node **new_node);
int dnscache_node_tbl_del_node_by_key(struct dnscache_node_tbl *dnscache_node_tbl,
        const uint8_t * qkey, uint16_t klen);
int dnscache_node_tbl_del_node(struct dnscache_node_tbl *dnscache_node_tbl, struct dnscache_node *node);
int dnscache_node_tbl_set_nodes(struct dnscache_node_tbl *dnscache_node_tbl);

struct dnscache_node **dnscache_node_tbl_list(struct dnscache_node_tbl *dnscache_node_tbl);
int dnscache_export_snapshot(struct dnscache_node_tbl *dnscache_node_tbl, FILE *fp);
int dnscache_import_snapshot(FILE *fp, uint32_t payload_size);

#endif                          /*  _MEGA_NODE_TBL_  */
