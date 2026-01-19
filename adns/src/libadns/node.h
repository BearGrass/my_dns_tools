#ifndef _ADNS_NODE_H_
#define _ADNS_NODE_H_

#include <stdint.h>
#include <stdlib.h>

#include "adns_conf.h"
#include "dname.h"
#include "rrset.h"
#include "list.h"
#include "view_maps.h"
#include "ring_list.h"


struct adns_zone;


struct adnsTypeConvertIndex {
    adns_type_t type;
    int index;
    char name[20];
};

/*
 * qps/bps is not calculated when a query comes (the former way), it is triggered by a timer.
 */
struct adns_node {
    /* list of domain node whithin the zone */
    struct list_head list;
    /* list of domain node within the domain hash table bucket */
    struct list_head node_list;

    adns_dname_t *name;
    uint16_t name_len;
    /* index of g_node_pools and g_domain_name_used_num */
    uint8_t node_index;

    uint8_t A_schedule_mode: 1,
            AAAA_schedule_mode: 1;

    struct adns_rrset *rrsets[ADNS_RRSET_NUM];
    struct adns_zone *zone;
    struct adns_node *parent;
    struct adns_node *wildcard_child;

    uint32_t counter_id;

    uint64_t pre_node_queries;
    uint64_t pre_node_bytes;
    uint64_t pre_timestamp;

    uint64_t pre_sta_queries;
    uint64_t pre_sta_bytes;
    uint64_t pre_sta_timestamp;
    struct node_stub * p_stub;
    /* The node_tag is a variable-length array, the value of every bit in the this array
     * indicates is there any rdata record for the view which has the same id with the index
     * of this bit in this node or its sub nodes
     *
     * !!!Note: Please never add another member after the node_tag for adns_node structure!
     *          The sizeof(struct ands_node) is not its really occupied size!
    */
    uint8_t node_tag[0];
};

struct node_stub {
    uint8_t is_deleted;
    struct adns_node * node_ptr;
    struct rlist_head rlist_entry;
}__attribute__((packed));

extern struct adnsTypeConvertIndex g_type2index_tbl[];
extern uint16_t g_type2index_size;

#ifdef __cplusplus
extern "C" {
#endif

int adns_node_check_type(adns_type_t type);
struct adns_node *adns_node_new(const adns_dname_t *dname);
void adns_node_free(struct adns_node *node);
struct adns_rrset *adns_node_get_rrset(const struct adns_node *node, adns_type_t type);
int adns_node_set_rrset(struct adns_node *node, adns_type_t type, struct adns_rrset *rrset);
struct adns_rrset *adns_node_get_rrset_a(struct adns_node *node);
int adns_node_init(void);
void node_stub_free(struct node_stub *node_stub);

#ifdef __cplusplus
}
#endif

#endif


