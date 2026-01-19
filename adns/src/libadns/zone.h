#ifndef _ADNS_ZONE_H_
#define _ADNS_ZONE_H_


#include <stdint.h>
#include <stdlib.h>
#include <rte_atomic.h>


#include "adns_types.h"
#include "adns_conf.h"
#include "list.h"
#include "dname.h"
#include "wire.h"
#include "node.h"
#include "private_route.h"
#include "adns.h"
#include "libadns.h"
#include "rrset.h"
#include "consts.h"


struct soa_rdata {
    adns_type_t type;
    adns_rclass_t rclass;
    adns_ttl_t ttl;
    uint16_t len;
    uint8_t data[ADNS_SOA_RRLEN];
    uint32_t sn;        // used as soa data verion, increment sn when edit zone
}__attribute__((packed));


struct node_hash {
    struct list_head list;
    uint32_t size;
}__attribute__((packed));

typedef struct adns_key_array_t {
    void *      keys[MAX_DNSKEY_NUM];       // dnssec key pointer array
    uint8_t     size;                       // dnsssec key pointer number
} adns_key_array_t;

#define KEY_ARRAY_SIZE(key_array) ((key_array).size)

#define KEY_ARRAY_PUSH(key_array, key) \
    if ((key_array).size < MAX_DNSKEY_NUM) \
        (key_array).keys[(key_array).size ++] = (void*)(key)

#define KEY_ARRAY_FOR_EACH(key_array, key)  \
    int idx = 0; \
    for ((key) = (key_array).keys[0]; \
            idx < (key_array).size && ( ((key) = (key_array).keys[idx]) || 1); \
            idx ++)

typedef struct adns_zsk_ctr {
    uint8_t     size;                   // number of zone's ZSK(1 or 2, including active zsk)
    uint16_t    alt_zsk;                // altanative key tag
    uint16_t    active_zsk;             // tag of zhe ZSK that is used for signing
    struct adns_rdata *dnskey_rrsig;    // rrsig signed for zone's dnskey rrset
} adns_zsk_ctr_t;

struct adns_zone {
    struct list_head list;
    adns_dname_t *name;
    uint16_t name_len;
    /* index of g_zone_pools and g_zone_name_used_num */
    uint8_t node_index;
    adns_labels_t domain_max_label;
    adns_labels_t wildcard_max_label;
    adns_socket_id_t socket_id;
    struct soa_rdata soa;
    struct node_hash node_tbl;

    uint32_t counter_id;
    struct adns_node *max_stat_node;
    uint8_t enable_cname_cascade:1,
            private_route_enable:1,
            wildcard_fallback_enable:1,
            enable_dnssec:1,            /* dnssec switch */
            dnssec_ok:1;                /* dnssec ready */
    uint64_t max_node_queries;
    uint64_t max_node_bytes;
    uint64_t pre_zone_queries;
    uint64_t pre_zone_bytes;
    uint64_t pre_timestamp;

    adns_ipset_t *ipset;            /* private route ipset to lookup */

    //adns_zone_dnskey_rrsig_state dnskey_rrsig_state;   /* state */
    //uint8_t active_dnskey_rrsig_index;                 /* current index to locate DNSKEY array and DNSKEY rrsig */
    //adns_key_array_t key_arrays[KEY_ROLLOVER_SIZE];                    /* DNSKEY arrays */
    //struct adns_rdata *dnskey_rrsigs[KEY_ROLLOVER_SIZE];               /* DNSKEY rrsig rdatas */

    adns_zsk_ctr_t *adns_zsk_ctr;       //zsk control structure
    
    /* The wild_tag is a variable-length array, the value of every bit in this array
     * indicates is there any wild domain or ns domain for the view which has the same id
     * with the index of this bit in this node or its sub nodes
     *
     * !!!Note: Please never add another member after the node_tag for adns_node structure!
     *          The sizeof(struct adns_zone) is not its really occupied size!
     */
    uint8_t wild_tag[0];
}__attribute__((packed));

#define ZONE_ENABLE_PRIVATE_ROUTE(zone) (zone->private_route_enable = 1)
#define ZONE_DISABLE_PRIVATE_ROUTE(zone) (zone->private_route_enable = 0)

#ifdef __cplusplus
extern "C" {
#endif

struct adns_zone *adns_zone_new(adns_socket_id_t socket_id, const adns_dname_t *name);
void adns_zone_free(struct adns_zone *zone);
int adns_zone_add_node(struct adns_zone *zone, struct adns_node *node, adns_viewid_t view_id);
int adns_zone_del_node(struct adns_zone *zone, adns_dname_t *domain);
struct adns_node *adns_zone_lookup_node(const struct adns_zone *zone, const adns_dname_t *dname);
struct adns_node *adns_zone_lookup_node_lsm(const struct adns_zone *zone, const adns_dname_t *domain, adns_labels_t label_jumped_to);
int adns_zone_check_node(const struct adns_zone *zone, const struct adns_node *node);
int adns_zone_init(void);

int adns_zone_zsk_ctr_init(void);
adns_zsk_ctr_t *adns_get_zone_zsk_ctr(struct adns_rdata *dnskey_rrsig, uint8_t zsk_num, uint16_t active_zsk_tag, uint16_t alt_zsk_tag);
void adns_put_zone_zsk_ctr(adns_zsk_ctr_t *adns_zsk_ctr);

#ifdef __cplusplus
}
#endif


#endif

