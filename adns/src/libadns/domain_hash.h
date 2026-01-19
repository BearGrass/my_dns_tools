#ifndef _ADNS_DOMAIN_HASH_H_
#define _ADNS_DOMAIN_HASH_H_


#include <stdio.h>
#include <stdlib.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>


#include "dname.h"
#include "list.h"
#include "zone.h"
#include "node.h"
#include "adns_conf.h"


struct adns_domain_hash_node{
    struct list_head list;
    struct adns_node *node_ptr;
};


struct domain_hash {
    struct list_head node_list;
    uint32_t size;
};


struct adns_domaindb{
    struct domain_hash *domain_tbl;
    char name[ADNS_DOMAIN_MAX_LEN];
    int domain_count;
};

struct adns_node* adns_domain_hash_lookup_with_len(const struct adns_zone *zone, const adns_dname_t *dname, int name_len);
struct adns_node* adns_domain_hash_lookup(const struct adns_zone *zone, const adns_dname_t *dname);
int adns_domain_add_hash(struct adns_node *adns_node, const adns_dname_t *dname);
int adns_domain_delete_hash(struct adns_node *node);
int adns_domaindb_init(void);
int adns_domain_init(void);
int adns_domain_replace_hash(struct adns_zone *zone, const adns_dname_t *dname, struct adns_node * new_node);


#endif


