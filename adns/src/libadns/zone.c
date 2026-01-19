#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#include "adns.h"
#include "adns_conf.h"
#include "adns_share.h"
#include "descriptor.h"
#include "log.h"
#include "dname.h"
#include "zonedb.h"
#include "zone.h"
#include "node.h"
#include "domain_hash.h"
#include "adns_counter.h"
#include "murmurhash3.h"
#include "adns_counter.h"
#include "syslog.h"
#include "dnskey.h"


static struct rte_mempool *g_zone_pools[ADNS_MAX_SOCKETS][NAME_LEN_TYPE_NUM] = { {NULL} };
// zone zsk ctrl mempool
struct rte_mempool *g_zone_zsk_ctrl_pools[ADNS_MAX_SOCKETS] = {NULL};


extern uint32_t g_zone_name_max_num[];
extern uint32_t g_zone_name_used_num[];

extern int name_len_to_index[];

static unsigned tag_size;


static inline struct adns_zone *zone_alloc(adns_socket_id_t socket_id, int name_len)
{
    void *data;
    struct adns_zone *zone;
    int i;

    for (i = 0; i < NAME_LEN_TYPE_NUM; ++i) {
        if (name_len_to_index[i] >= name_len) {
            if (rte_mempool_get(g_zone_pools[socket_id][i], &data) < 0) {
                log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, pool name = %s, socket id = %d\n", __FUNCTION__, g_zone_pools[socket_id][i]->name, socket_id);
                continue;
            }
            zone = (struct adns_zone *)data;
            memset(zone, 0, g_zone_pools[socket_id][i]->elt_size);
            /* set zone node node index */
            zone->node_index = (uint8_t)i;
            /* set zone name pointer */
            zone->name = (adns_dname_t *)zone + sizeof(struct adns_zone) + tag_size;
            ++g_zone_name_used_num[i];
            break;
        }
    }

    if (i >= NAME_LEN_TYPE_NUM) {
        log_server_error(rte_lcore_id(), "[%s]: fail to allocate zone node\n", __FUNCTION__);
        return NULL;
    }

    INCREASE_ZONE_NUM(1);
    return zone;
}


static inline void zone_free(struct adns_zone *zone)
{
    if (zone == NULL) {
        return;
    }

    if (zone->socket_id >= ADNS_MAX_SOCKETS) {
        return;
    }

    if (zone->node_index >= NAME_LEN_TYPE_NUM) {
        log_server_error(rte_lcore_id(), "[%s]: fail to free zone node\n", __FUNCTION__);
        return; 
    }

    #if ZONE_CNT
    adns_counter_del(zone->counter_id);
    #endif
    rte_mempool_put(g_zone_pools[zone->socket_id][zone->node_index], (void *)zone);
    --g_zone_name_used_num[zone->node_index];
    // decrement dnssec enabled zone number when the zone is to be free
    if (zone->enable_dnssec == 1) {
        DECREASE_DNSSEC_ZONE_NUM(1);
    }

    // put back adns_zsk_ctr
    adns_put_zone_zsk_ctr(zone->adns_zsk_ctr);

    DECREASE_ZONE_NUM(1);
}


struct adns_zone *adns_zone_new(adns_socket_id_t socket_id, const adns_dname_t *name)
{
    int name_len, labels;
    struct adns_zone *zone;

    if (name == NULL) {
        return NULL;
    }

    name_len = adns_dname_size(name);
    /* zone is initialized to 0 in zone_alloc */
    zone = zone_alloc(socket_id, name_len);
    if (zone == NULL) {
        return NULL;
    }

    INIT_LIST_HEAD(&(zone->node_tbl.list));
    zone->node_tbl.size = 0;

    zone->socket_id = socket_id;
    
    memcpy(zone->name, name, name_len);
    zone->name_len = name_len;

    labels = adns_dname_labels(name);
    zone->domain_max_label = labels;
    zone->wildcard_max_label = labels;

    return zone;
}


static void adns_zone_free_nodes(struct node_hash *node_tbl)
{
    struct adns_node *node, *node_nxt;
    struct list_head *h_list;

    h_list = &(node_tbl->list);

    list_for_each_entry_safe(node, node_nxt, h_list, list) {
        list_del(&node->list);
        node_tbl->size--;
        adns_domain_delete_hash(node);
        adns_node_free(node);
    }
}


void adns_zone_free(struct adns_zone *zone)
{
    if (zone == NULL) {
        return;
    }

    adns_zone_free_nodes(&(zone->node_tbl));

    /* free the zone's ipset */
    if (zone->ipset) {
        adns_ipset_free(zone->ipset);
    }

    zone_free(zone);
    zone = NULL;
}


int adns_zone_check_node(const struct adns_zone *zone, const struct adns_node *node)
{
    adns_dname_t *dname;

    if (zone == NULL || node == NULL) {
        return -1;
    }

    dname = node->name;
    if (adns_dname_is_wildcard(dname)) {
        dname = adns_wire_next_label(dname);
    }

    if (adns_dname_is_equal(dname, zone->name)) {
        return 0;
    }

    if (!adns_dname_is_sub(dname, zone->name)) {
        return -2;
    }

    return 0;
}

static int __adns_zone_add_node(struct adns_zone *zone, struct adns_node *node)
{
    uint32_t hash;  
    int name_len, ret;
    adns_dname_t *dname;
    struct list_head *h_list;
    struct node_hash *h_node;
    int labels;
    int hashed_io_core_id = 0;

    if (zone == NULL || node == NULL) {
        return -1;
    }

    h_node = &(zone->node_tbl);
    if (h_node == NULL) {
        return -2;
    }

    dname = node->name;
    name_len = node->name_len;

    hash = mm3_hash((const char *)dname, name_len);
    h_list = &(h_node->list);

    list_add(&node->list, h_list);
    h_node->size++;
    node->zone = zone;

    labels = adns_dname_labels(dname);
    if(labels > zone->domain_max_label){
        zone->domain_max_label = labels;
    }
    if (adns_dname_is_wildcard(dname) && labels > zone->wildcard_max_label) {
        zone->wildcard_max_label = labels;
    }

    ret = adns_domain_add_hash(node, dname);
    if (ret != 0) {
        log_server_warn(rte_lcore_id(), "[%s]: adns_add_domain_hash failed, ret = %d\n", __FUNCTION__, ret);
        return -3;
    }

    if (g_syslog_ctl.domain_sta_on != 0 || g_syslog_ctl.domain_sta_log_on != 0) {
        hashed_io_core_id = hash % app.lcore_io_num;
        ret = rlist_add_tail(&(node->p_stub->rlist_entry), hashed_io_core_id);
        if (ret != 0) {
            log_server_error(rte_lcore_id(), "[%s]: rlist_add_tail fail\n", __FUNCTION__); 
            return -1;
        }
    }

    return 0;
}


int adns_zone_add_node(struct adns_zone *zone, struct adns_node *node, adns_viewid_t view_id)
{
    int ret;
    adns_dname_t *dname, *parent;
    struct adns_node *parent_node;

    if (zone == NULL || node == NULL || node->name == NULL || view_id >= (g_view_max_num + g_private_route_per_zone_max_num)) {
        return -1;
    }

    dname = node->name;

    /* check if node's name is subdomain of zone's name */
    ret = adns_zone_check_node(zone, node);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: The node %s is not the subdomain of zone %s\n", __FUNCTION__, dname, zone->name);
        return -2;
    }

    /* No parents for root domain. */
    if (node->name[0] == '\0') {
        goto add_node;
    }

    if (adns_dname_is_wildcard(node->name)) {
        parent = adns_wire_next_label(node->name);    
        parent_node = NULL;

        parent_node = adns_zone_lookup_node(zone, parent);
        if (parent_node) {
            if (parent_node->wildcard_child) {
                log_server_warn(rte_lcore_id(), "[%s]: parent_node->wildcard_child != NULL, node->name = %s\n", __FUNCTION__, node->name);
            }

            SET_TAG(parent_node->node_tag, view_id);
            parent_node->wildcard_child = node;
            node->parent = parent_node;
            goto add_node;
        } else {
            parent_node = adns_node_new(parent);
            if (parent_node == NULL) {
                log_server_warn(rte_lcore_id(), "[%s]: adns_node_new failed, Parent_node == NULL, node->name =%s\n", __FUNCTION__, node->name);
                return -3;
            }

            ret = __adns_zone_add_node(zone, parent_node);
            if (ret < 0) {
                log_server_warn(rte_lcore_id(), "[%s]: Add node to zone table failed, node->name =%s\n", __FUNCTION__, node->name);
                return -4;
            }

            SET_TAG(parent_node->node_tag, view_id);
            parent_node->wildcard_child = node;
            node->parent = parent_node;
            goto add_node;
        }
    }

add_node:
    ret = __adns_zone_add_node(zone, node);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: Add node to zone table failed, node->name = %s\n", __FUNCTION__, node->name);
        return -5;
    }

    return 0;
}


int adns_zone_del_node(struct adns_zone *zone, adns_dname_t *domain)
{
    int i, parent_is_empty = true;
    struct adns_node *node;
    int view_id, flag = 0;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;

    if (zone == NULL || domain == NULL) {
        return -1;
    }

    node = adns_domain_hash_lookup(zone, domain); 
    if (node == NULL) {
        return 0;
    }

    if((node->parent != NULL) && (node->parent->wildcard_child != NULL)){
        /* the current node is a child node */
        /* check each view of parent, if all is empty, delete the parent node */
        node->parent->wildcard_child = NULL;
        for (i = 0; i < g_view_max_num + g_private_route_per_zone_max_num; i++) {
            if (GET_TAG(node->parent->node_tag, i)) {
                parent_is_empty = false;
                break;
            }
        }
        
        if (parent_is_empty == true) {
            list_del(&node->parent->list);
            adns_domain_delete_hash(node->parent);
            adns_node_free(node->parent);
        }
    }

    if(node->wildcard_child == NULL){ 
        /* a normal node, not a parent or a child, just delete it */
        list_del(&node->list);
        adns_domain_delete_hash(node);
        adns_node_free(node);
    }else {
        /* current is a parent node. check whether the child node exists. */
        for(view_id = 0; view_id < g_view_max_num + g_private_route_per_zone_max_num; view_id ++) {
            if(GET_TAG(node->wildcard_child->node_tag, view_id)){
                flag = 1; 
                break;
            }
        }
                    
        if(flag == 0){
            /* child node doesn't exist, just delete the current node */
            list_del(&node->list);
            adns_domain_delete_hash(node);
            adns_node_free(node);
        }else{
            /* delete all the data in current(parent) node, but keep the node as parent */
            for (i = 0; i < ADNS_RRSET_NUM; i++) {
                rrset = node->rrsets[i];
                if (rrset == NULL) {
                    continue; 
                }

                for(view_id = 0; view_id < g_view_max_num + g_private_route_per_zone_max_num; view_id++){
                    rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
                    if (rdata_ctl == NULL) {
                        continue; 
                    }

                    adns_rrset_cleanup_rdatas_for_ctl(rdata_ctl, rrset->type);
                    rdata_ctl = NULL;
                }
            }
        }
    }

    return 0;
}


struct adns_node *adns_zone_lookup_node(const struct adns_zone *zone, const adns_dname_t *dname)
{
    int name_len;
    struct adns_node *node;

    if (zone == NULL || dname == NULL) {
        return NULL;
    }

    name_len = adns_dname_size(dname);
    if (name_len < 1) {
        return NULL;
    }

    node = adns_domain_hash_lookup_with_len(zone, dname, name_len);
    if (node == NULL) {
        return NULL;
    }
  
    return node;
}


struct adns_node *adns_zone_lookup_node_lsm(
        const struct adns_zone *zone, const adns_dname_t *domain, adns_labels_t label_jumped_to)
{
    int domain_lbs, name_len;
    struct adns_node *node;

    if (zone == NULL || domain == NULL) {
        return NULL;
    }

    domain_lbs = adns_dname_labels(domain);
    if (domain_lbs) {
        domain = adns_wire_next_label(domain);
        domain_lbs--;
    }
    while (domain_lbs > label_jumped_to){
        domain = adns_wire_next_label(domain);
        domain_lbs--;
    }

    name_len = adns_dname_size(domain);
    while (1) {
        node = adns_domain_hash_lookup_with_len(zone, domain, name_len);
        if (node != NULL) {
            return node;
        }

        name_len -= domain[0] + 1;
        if (name_len <= 0){
            return NULL;
        }

        domain = adns_wire_next_label(domain);
    }

    return NULL;
}


int adns_zone_init()
{
    adns_socket_id_t socket_id;
    char name[64];
    int j;

    for (socket_id = 0; socket_id < ADNS_MAX_SOCKETS; socket_id++) {
        for (j = 0; j < NAME_LEN_TYPE_NUM; j ++) {
            g_zone_pools[socket_id][j] = NULL;
        }
    }

    for (socket_id = 0; socket_id < ADNS_MAX_SOCKETS; socket_id++) {
        for (j = 0; j < NAME_LEN_TYPE_NUM; j ++ ) {
            /* private route wild tag goes after fix view tag */          
            tag_size = (g_view_max_num + g_private_route_per_zone_max_num)/ ADNS_UINT8_BIT;
            if (((g_view_max_num + g_private_route_per_zone_max_num) % ADNS_UINT8_BIT) > 0) {
                tag_size += 1;
            }
            snprintf(name, sizeof(name), "g_zone_%d_pools_%d", name_len_to_index[j], socket_id);
            g_zone_pools[socket_id][j] = rte_mempool_create(name, g_zone_name_max_num[j],
                    sizeof(struct adns_zone) + tag_size + name_len_to_index[j], 32, 0, NULL, NULL, NULL,
                    NULL, socket_id, 0);
            if (g_zone_pools[socket_id][j] == NULL) {
                return -1;
            }
            fprintf(stdout, "[%s]: Finish to alloc g_zone_pools %s\n", __FUNCTION__, name);
        }
    }

    return 0;
}

int adns_zone_zsk_ctr_init(void)
{
    adns_socket_id_t socket_id;
    char name[64];

    for (socket_id = 0; socket_id < ADNS_MAX_SOCKETS; socket_id++) {
        /* allocate memory pool for adns zone zsk ctrl */
        snprintf(name, sizeof(name), "g_zone_zone_zsk_ctr_%d", socket_id);
        /* zone's zsk_ctrl is replaced when add dnskey rrsig, g_zone_zsk_ctrl_pool's size is doubled */
        g_zone_zsk_ctrl_pools[socket_id] = rte_mempool_create(name, g_dnssec_zone_max_num << 1,
                sizeof(adns_zsk_ctr_t), 32, 0, NULL, NULL, NULL,
                NULL, socket_id, 0);
        if (g_zone_zsk_ctrl_pools[socket_id] == NULL) {
            fprintf(stdout, "[%s]: fail to alloc g_zone_zsk_ctrl_pools %s\n", __FUNCTION__, name);
            return -1;
        }
        fprintf(stdout, "[%s]: Finish to alloc g_zone_zsk_ctrl_pools %s\n", __FUNCTION__, name);
    }

    return 0;
}

adns_zsk_ctr_t *adns_get_zone_zsk_ctr(struct adns_rdata *dnskey_rrsig, uint8_t zsk_num, uint16_t active_zsk_tag, uint16_t alt_zsk_tag)
{
    void *data;
    adns_zsk_ctr_t *zsk_ctr = NULL;
    adns_socket_id_t socket_id;
    socket_id = rte_socket_id();

    if (dnskey_rrsig == NULL) {
        return NULL;
    }

    if (zsk_num < 1 || zsk_num > MAX_ZSK_NUM) {
        return NULL;
    }

    if (rte_mempool_get(g_zone_zsk_ctrl_pools[socket_id], &data) < 0) {
        log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, pool name = %s, socket id = %d\n", __FUNCTION__, g_zone_zsk_ctrl_pools[socket_id]->name, socket_id);
        return NULL;
    }
    zsk_ctr = (adns_zsk_ctr_t *)data;

    zsk_ctr->active_zsk = active_zsk_tag;
    zsk_ctr->dnskey_rrsig = dnskey_rrsig;
    zsk_ctr->size = zsk_num;

    if (zsk_num > 1) {
        zsk_ctr->alt_zsk = alt_zsk_tag;
    }

    return zsk_ctr;
}

void adns_put_zone_zsk_ctr(adns_zsk_ctr_t *adns_zsk_ctr) {
    adns_socket_id_t socket_id = rte_socket_id();
    if (adns_zsk_ctr != NULL) {
        if (adns_zsk_ctr->dnskey_rrsig != NULL) {
            rte_free(adns_zsk_ctr->dnskey_rrsig->data);
            adns_zsk_ctr->dnskey_rrsig->data = NULL;
            rdata_free(adns_zsk_ctr->dnskey_rrsig, ADNS_RRTYPE_RRSIG);
        }
        adns_dnssec_key *active_key = adns_get_zsk_by_key_tag(adns_zsk_ctr->active_zsk);
        // active key is certainly not NULL
        DNS_DNSSEC_KEY_ACTIVE_CNT_DEC(active_key);
        rte_mempool_put(g_zone_zsk_ctrl_pools[socket_id], (void *)adns_zsk_ctr);
    }
}
