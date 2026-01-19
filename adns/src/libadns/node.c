#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_cycles.h>

#include "common_value.h"

#include "adns_share.h"
#include "descriptor.h"
#include "node.h"
#include "log.h"
#include "adns_counter.h"
#include "domain_hash.h"
#include "ring_list.h"
#include "syslog.h"


static struct rte_mempool *g_node_pools[ADNS_MAX_SOCKETS][NAME_LEN_TYPE_NUM] = { {NULL} };
static struct rte_mempool *g_node_stub_pools[ADNS_MAX_SOCKETS] = {NULL};


extern uint32_t g_domain_name_max_num[];
extern uint32_t g_domain_name_used_num[];

extern int name_len_to_index[];

static unsigned tag_size;

// rrset that ADNS supoort descriptor
struct adnsTypeConvertIndex g_type2index_tbl[] = {
    { ADNS_RRTYPE_A, 0, "A"},
    { ADNS_RRTYPE_AAAA, 1, "AAAA"},
    { ADNS_RRTYPE_NS, 2, "NS"},
    { ADNS_RRTYPE_CNAME, 3, "CNAME"},
    { ADNS_RRTYPE_MX, 4, "MX"}, 
    { ADNS_RRTYPE_PTR, 5, "PTR"},    
    { ADNS_RRTYPE_TXT, 6, "TXT"},    
    { ADNS_RRTYPE_SRV, 7, "SRV"},
    { ADNS_RRTYPE_SOA, 8, "SOA"},
    { ADNS_RRTYPE_CAA, 9, "CAA"},
};
uint16_t g_type2index_size = ARRAY_SIZE(g_type2index_tbl);

static inline struct adns_node *node_alloc(int name_len)
{
    adns_socket_id_t socket_id;
    int i, cid_save;
    void *data;
    struct adns_node *node;

    socket_id = rte_socket_id();
    if (socket_id >= ADNS_MAX_SOCKETS){
        return NULL;
    }

    for (i = 0; i < NAME_LEN_TYPE_NUM; ++i) {
        if (name_len_to_index[i] >= name_len) {
            if (rte_mempool_get(g_node_pools[socket_id][i], &data) < 0) {
                log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, pool name = %s, socket id = %d\n", __FUNCTION__, g_node_pools[socket_id][i]->name, socket_id);
                continue;
            }
            node = (struct adns_node *)data;
            cid_save = node->counter_id;
            memset(node, 0, g_node_pools[socket_id][i]->elt_size);
            /* set domain node node index */
            node->node_index = (uint8_t)i;
            node->counter_id = cid_save; 
            /* set domain node name pointer */
            node->name = (adns_dname_t *)node + sizeof(struct adns_node) + tag_size;
            ++g_domain_name_used_num[i];
            break;
        }
    }

    if (i >= NAME_LEN_TYPE_NUM) {
        log_server_error(rte_lcore_id(), "[%s]: fail to allocate domain node\n", __FUNCTION__);
        return NULL;
    }

    INCREASE_DOMAIN_NUM(1);
    return node;
}

struct node_stub *node_stub_alloc()
{
    int socket_id;
    void *data;
    struct node_stub *node_stub;

    socket_id = rte_socket_id();
    if (socket_id >= ADNS_MAX_SOCKETS){
        return NULL;
    }

    if (rte_mempool_get(g_node_stub_pools[socket_id], &data) < 0) {
        log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, pool name = g_node_stub_pools, socket id = %d\n", __FUNCTION__, socket_id);
        return NULL;
    }
    node_stub = (struct node_stub *)data;
    memset(node_stub, 0, sizeof(struct node_stub));
    return node_stub;
}

static inline void node_free(struct adns_node *node)
{
    adns_socket_id_t socket_id;
    
    if (node == NULL) {
        return;
    }
    
    if (g_syslog_ctl.domain_sta_on != 0 || g_syslog_ctl.domain_sta_log_on != 0) {
        node->p_stub->is_deleted = true;
    }

    socket_id = rte_socket_id();
    if (socket_id >= ADNS_MAX_SOCKETS){
        return;
    }

    if (node->node_index >= NAME_LEN_TYPE_NUM) {
        log_server_error(rte_lcore_id(), "[%s]: fail to free domain node\n", __FUNCTION__);
        return;
    }

    adns_counter_init_value(node->counter_id);
    rte_mempool_put(g_node_pools[socket_id][node->node_index], (void *)node);
    --g_domain_name_used_num[node->node_index];
    DECREASE_DOMAIN_NUM(1);
}

void node_stub_free(struct node_stub *node_stub)
{
    if (node_stub == NULL) {
        return;
    }
    rte_mempool_put(g_node_stub_pools[0], (void *)node_stub);
}


struct adns_node *adns_node_new(const adns_dname_t *dname)
{
    int name_len;
    struct adns_node *node;
    struct node_stub *node_stub = NULL;

    if (dname == NULL) {
        return NULL;
    }

    name_len = adns_dname_size(dname);
    node = node_alloc(name_len);
    if (node == NULL) {
        return NULL;
    }

    if (g_syslog_ctl.domain_sta_on != 0 || g_syslog_ctl.domain_sta_log_on) {
        node_stub = node_stub_alloc();
        if (node_stub == NULL) {
            log_server_error(rte_lcore_id(), "[%s]: node_stub alloc error\n", __FUNCTION__); 
            return NULL;
        }
        node_stub->node_ptr = node;
        node_stub->is_deleted = false;
        node->p_stub = node_stub;
        node->pre_sta_timestamp = 0;
    }

    INIT_LIST_HEAD(&(node->list));
    INIT_LIST_HEAD(&(node->node_list));

    memcpy(node->name, dname, name_len);
    node->name_len = name_len;

    /* by default, A rrset is in ratio mode,
       AAAA rrset is in allrr mode,
       CNAME rrset is in ratio mode. */
    node->AAAA_schedule_mode = SCHEDULE_MODE_ALLRR;

    return node;
}


void adns_node_free(struct adns_node *node)
{
    int i;
    struct adns_rrset *rrset = NULL;

    if (node == NULL) {
        return;
    }

    for (i = 0; i < ADNS_RRSET_NUM; i++) {
        rrset = node->rrsets[i];
        if (rrset != NULL){
            adns_rrset_deep_free(rrset);
        }
    }

    node->wildcard_child = NULL;
    node->parent = NULL;

    node_free(node);
    node = NULL;
}


int adns_node_check_type(adns_type_t type)
{
    adns_type_t i;
    int index;
    
    for (i = 0; i < g_type2index_size; i++) {
        if (g_type2index_tbl[i].type == type) {
            index = g_type2index_tbl[i].index;
            if (index >= ADNS_RRSET_NUM) {
                return -1;
            }
            return index;  
        } 
    }

    return -2;
}


struct adns_rrset *adns_node_get_rrset(const struct adns_node *node, adns_type_t type)
{
    adns_type_t i;
    int index;

    if (node == NULL) {
        return NULL;
    }

    for (i = 0; i < g_type2index_size; i++) {
        if (g_type2index_tbl[i].type == type) {
            index = g_type2index_tbl[i].index;
            if (index >= ADNS_RRSET_NUM) {
                return NULL;
            }
            return node->rrsets[index];
        }
    }

    return NULL;
}


int adns_node_set_rrset(struct adns_node *node, adns_type_t type, struct adns_rrset *rrset)
{
    adns_type_t i;
    int index;

    if (node == NULL) {
        return -1;
    }

    for (i = 0; i < g_type2index_size; i++) {
        if (g_type2index_tbl[i].type == type) {
            index = g_type2index_tbl[i].index;
            if (index >= ADNS_RRSET_NUM) { 
                return -2;
            }    
            node->rrsets[index] = rrset;
            return 0;
        }
    }

    return -3;
}


struct adns_rrset *adns_node_get_rrset_a(struct adns_node *node)
{
    adns_type_t i;
    int index;

    if (node == NULL) {
        return NULL;
    }

    for (i = 0; i < g_type2index_size; i++) {
        if (g_type2index_tbl[i].type == ADNS_RRTYPE_A) {
            index = g_type2index_tbl[i].index;
            if (index >= ADNS_RRSET_NUM) { 
                return NULL;
            }
            return node->rrsets[index];
        }
    }

    return NULL;
}

static void
adns_node_obj_init(struct rte_mempool *mp, __attribute__((unused)) void *arg,
	    void *obj, unsigned i)
{
	struct adns_node * node = obj;
    int cid_start = *((int *)arg);
    node->counter_id = i + cid_start;
}

int adns_node_init()
{
    int i, j, cid_start;
    char name[64];

    cid_start = ADNS_RCODE_COUNTER_MAX + ADNS_PKT_DROP_COUNTER_MAX;
    for (i = 0; i < ADNS_MAX_SOCKETS; i++) {
        for (j = 0; j < NAME_LEN_TYPE_NUM; j++) {
            if (g_node_pools[i][j] == NULL) {
                /* private route tag goes after fix view tag */
                tag_size = g_view_max_num + g_private_route_per_zone_max_num;
#ifdef USE_BIT_NODE_TAG
                tag_size /= ADNS_UINT8_BIT;
                if (((g_view_max_num + g_private_route_per_zone_max_num) % ADNS_UINT8_BIT) > 0) {
                    tag_size += 1;
                }
#endif
                snprintf(name, sizeof(name), "g_node_%d_pools_%d", name_len_to_index[j], i);
                g_node_pools[i][j] = rte_mempool_create(name, g_domain_name_max_num[j],
                        sizeof(struct adns_node) + tag_size + name_len_to_index[j], 32, 0, NULL, NULL, 
                        adns_node_obj_init, &cid_start, 
                        i, 0);
                if (g_node_pools[i][j] == NULL) {
                    return -1;
                }
                fprintf(stdout, "[%s]: Finish to alloc g_node_pools %s\n", __FUNCTION__, name);
                cid_start += g_domain_name_max_num[j];  
            }
        }

        /* the delete of node_stub is delayed, so the maximum is doubled */
        if (g_syslog_ctl.domain_sta_on != 0 || g_syslog_ctl.domain_sta_log_on != 0) {
            if (g_node_stub_pools[i] == NULL) {
                snprintf(name, sizeof(name), "g_node_stub_pools_%d", i);
                // allocate more 20% node stub for the node just deleted
                g_node_stub_pools[i] = rte_mempool_create(name, g_domain_max_num * 1.2,
                        sizeof(struct node_stub), 32, 0, NULL, NULL, 
                        NULL, NULL, i, 0);
                if (g_node_stub_pools[i] == NULL) {
                    return -1;
                }
                fprintf(stdout, "[%s]: Finish to alloc g_node_stub_pools %s\n", __FUNCTION__, name);
            }
        }
        else {
            fprintf(stdout, "[%s]: g_node_stub_pools allocation canceled\n", __FUNCTION__);
        }
    }

    return 0;
}

