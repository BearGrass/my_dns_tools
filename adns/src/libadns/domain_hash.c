#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>


#include "log.h"
#include "domain_hash.h"
#include "murmurhash3.h"


struct adns_domaindb *g_domain_db = NULL;


static inline struct adns_node*
_adns_domain_hash_lookup_with_len(const struct adns_zone *zone, const adns_dname_t *dname, int name_len)
{
    uint32_t hash;
    struct adns_node *d_node = NULL;
    struct list_head *h_list;
    struct domain_hash *h_node;

    if ((zone == NULL) || (dname == NULL)) {
        return NULL;
    }

    hash = mm3_hash((const char *)dname, name_len);
    h_node = &(g_domain_db->domain_tbl[hash & ADNS_DOMAINDB_HASH_MASK]);
    h_list = &(h_node->node_list);

    list_for_each_entry(d_node, h_list, node_list){
        if((d_node->name_len == name_len)
                && (d_node->zone == zone)
                && !memcmp(d_node->name, dname, name_len)) {
            return d_node;
        }
    }

    return NULL;
}


struct adns_node* adns_domain_hash_lookup(const struct adns_zone *zone, const adns_dname_t *dname)
{
    int name_len;

    if ((zone == NULL) || (dname == NULL)) {
        return NULL;
    }

    name_len = adns_dname_size(dname);
    if (name_len < 1) {
        return NULL;
    }

    return _adns_domain_hash_lookup_with_len(zone, dname, name_len);
}

struct adns_node*
adns_domain_hash_lookup_with_len(const struct adns_zone *zone, const adns_dname_t *dname, int name_len)
{
    return _adns_domain_hash_lookup_with_len(zone, dname, name_len);
}

int adns_domain_add_hash(struct adns_node *adns_node, const adns_dname_t *dname)
{
    int name_len;
    uint32_t hash;
    struct domain_hash *h_node;
    struct list_head *h_list;

    if (adns_node == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: adns_domain_add_hash %s failed\n", __FUNCTION__, dname);
        return -1;
    }

    name_len = adns_dname_size(dname);   
    hash = mm3_hash((const char *)dname, name_len);
    h_node = &(g_domain_db->domain_tbl[hash & ADNS_DOMAINDB_HASH_MASK]);
    h_list = &(h_node->node_list);

    list_add(&(adns_node->node_list), h_list);
    g_domain_db->domain_count ++;

    return 0;
}


static int __adns_domain_delete_hash(struct adns_zone *zone, const adns_dname_t *dname)
{
    int name_len;
    uint32_t hash;
    struct adns_node *d_node = NULL, *d_node_next = NULL;
    struct list_head *h_list;
    struct domain_hash *h_node;
           
    name_len = adns_dname_size(dname);
    hash = mm3_hash((const char *)dname, name_len); 
    h_node = &(g_domain_db->domain_tbl[hash & ADNS_DOMAINDB_HASH_MASK]);
    h_list = &(h_node->node_list);

    list_for_each_entry_safe(d_node, d_node_next, h_list, node_list) {
        if ((d_node->name_len == name_len)
                && (d_node->zone == zone)
                && !memcmp(d_node->name, dname, name_len)) {                  
            list_del(&d_node->node_list);
            g_domain_db->domain_count --;
            return 0;
        }
    }

    log_server_warn(rte_lcore_id(), "[%s]: Can't find the node %s in zone %s\n", __FUNCTION__, dname, zone->name);
    return -1;
}

int adns_domain_replace_hash(struct adns_zone *zone, const adns_dname_t *dname, struct adns_node * new_node)
{
    int name_len;
    uint32_t hash;
    struct adns_node *d_node;
    struct list_head *h_list;
    struct domain_hash *h_node;

    name_len = adns_dname_size(dname);
    hash = mm3_hash((const char *)dname, name_len);
    h_node = &(g_domain_db->domain_tbl[hash & ADNS_DOMAINDB_HASH_MASK]);
    h_list = &(h_node->node_list);

    list_for_each_entry(d_node, h_list, node_list) {
        if ((d_node->name_len == name_len)
                && (d_node->zone == zone)
                && !memcmp(d_node->name, dname, name_len)) {
            list_replace(&(d_node->node_list), &(new_node->node_list));
            return 0;
        }
    }

    log_server_warn(rte_lcore_id(), "[%s]: Can't find the node %s in zone %s\n", __FUNCTION__, dname, zone->name);
    return -1;
}


int adns_domain_delete_hash(struct adns_node *node)
{

    if (node == NULL) {
        return 0;
    }
    if (node->zone != NULL) {
        return __adns_domain_delete_hash(node->zone, node->name);
    } else {
        log_server_warn(rte_lcore_id(), "[%s]: delete domain %s out of domaindb failed, node->zone is null.\n",
            __FUNCTION__, node->name);
        return -1;
    }
}


/* Init Function */
static struct adns_domaindb *adns_domaindb_new(const char *name, int socket_id)
{
    int i;
    struct adns_domaindb *db;
    const struct rte_memzone *mz = NULL;

    db = rte_zmalloc_socket(name, sizeof(struct adns_domaindb), 0, socket_id);
    if (db == NULL) {
        return NULL;
    }

    snprintf(db->name, ADNS_ZONEDB_NAMELEN, "%s", name);
    db->domain_count = 0;
    
    mz = rte_memzone_reserve(name, 
            sizeof(struct domain_hash) * ADNS_DOMAINDB_HASH_SIZE, socket_id, 0);
    if (mz == NULL) {
        goto err;
    }       
    memset(mz->addr, 0, sizeof(struct domain_hash) * ADNS_DOMAINDB_HASH_SIZE);
    db->domain_tbl = (struct domain_hash *)mz->addr;

    for (i = 0; i < ADNS_DOMAINDB_HASH_SIZE; i++) {
        INIT_LIST_HEAD(&(db->domain_tbl[i].node_list));
        db->domain_tbl[i].size = 0;
    }
    
    return db;

err:
    rte_free(db);
    return NULL;
}


int adns_domaindb_init()
{
    adns_socket_id_t socket_id;
    int admin_core;
    char name[64];
    struct adns_domaindb *db = NULL;
    
    admin_core = rte_lcore_id();
    socket_id = rte_lcore_to_socket_id(admin_core);

    snprintf(name, sizeof(name), "%s_%d", "g_domain_db", socket_id);
    db = adns_domaindb_new(name, socket_id);    
    if (db == NULL) {
        rte_exit(EXIT_FAILURE, "[%s]: Cannot init %s on socket %d\n", __FUNCTION__, name, socket_id);
        return -1;
    }

    g_domain_db = db;
    fprintf(stdout, "[%s]: Finish to alloc g_domain_db\n", __FUNCTION__);

    return 0;
}
