#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "errcode.h"
#include "rrset.h"
#include "log.h"
#include "adns_share.h"
#include "adns_conf.h"
#include "murmurhash3.h"
#include "iplib.h"
#include "libadns.h"


struct rte_mempool *g_rrset_pools[ADNS_MAX_SOCKETS] = {NULL};
struct rte_mempool *g_rdata_ctl_pools[ADNS_MAX_SOCKETS] = {NULL};
struct rte_mempool *g_rdata_pools[ADNS_MAX_SOCKETS] = {NULL};
struct rte_mempool *g_private_rdata_ctl_pools[ADNS_MAX_SOCKETS] = {NULL};
extern adns_weight_t g_large_weight;
#define G_MAX_TOTAL_WEIGHT (TOTAL_WEIGHT_MAX * g_large_weight)

/* default NS list hash table */
struct adns_ns_list_hash *g_ns_tbl = NULL;
/* NS rrset table, each NS rrset represent a NS group */
struct adns_rrset** g_ns_rrsets = NULL;


static inline struct adns_rrset *rrset_alloc(void)
{
	int socket_id;
    void *data;
	struct adns_rrset *rrset;

	socket_id = rte_socket_id();
	if (socket_id >= ADNS_MAX_SOCKETS) {
		return NULL;
    }

    if (rte_mempool_get(g_rrset_pools[socket_id], &data) < 0) {
        log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, socket id = %d\n", __FUNCTION__, socket_id);
        return NULL;
	}
    memset(data, 0, sizeof(struct adns_rrset)); 
    rrset = (struct adns_rrset *)data;

    INCREASE_RRSET_MEMORY_NUM(1);
	return rrset;
}


static inline struct adns_rdata_ctl *rdata_ctl_alloc()
{
	int socket_id, i;
    void *data;
	struct adns_rdata_ctl *rdata_ctl, *tmp_ctl;

	socket_id = rte_socket_id();
	if (socket_id >= ADNS_MAX_SOCKETS) {
		return NULL;
    }

    if (rte_mempool_get(g_rdata_ctl_pools[socket_id], &data) < 0) {
        log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, socket id = %d\n", __FUNCTION__, socket_id);
        return NULL;
	}
    memset(data, 0, sizeof(struct adns_rdata_ctl) * g_view_max_num);
    rdata_ctl = (struct adns_rdata_ctl *)data;

    for(i = 0; i < g_view_max_num; i++) {
        tmp_ctl = (struct adns_rdata_ctl *)((char *)rdata_ctl + i * sizeof(struct adns_rdata_ctl));
        INIT_LIST_HEAD(&(tmp_ctl->list));
        /* init schedule mode for rdata_ctl to SCHEDULE_MODE_UNKNOWN */
        tmp_ctl->schedule_mode = SCHEDULE_MODE_UNKNOWN;
    }

    INCREASE_RDATA_CTL_NUM(1);
	return rdata_ctl;
}

static inline struct adns_rdata_ctl *private_rdata_ctl_alloc()
{
    int socket_id, i;
    void *data;
    struct adns_rdata_ctl *private_rdata_ctl, *tmp_ctl;

    socket_id = rte_socket_id();
    if (socket_id >= ADNS_MAX_SOCKETS) {
        return NULL;
    }

    if (rte_mempool_get(g_private_rdata_ctl_pools[socket_id], &data) < 0) {
        log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, socket id = %d\n", __FUNCTION__, socket_id);
        return NULL;
    }
    memset(data, 0, sizeof(struct adns_rdata_ctl) * g_private_route_per_zone_max_num);
    private_rdata_ctl = (struct adns_rdata_ctl *)data;

    for (i = 0; i < g_private_route_per_zone_max_num; i ++) {
        tmp_ctl = (struct adns_rdata_ctl *)((char *)private_rdata_ctl + i * sizeof(struct adns_rdata_ctl));
        INIT_LIST_HEAD(&(tmp_ctl->list));
        /* init schedule mode for rdata_ctl to SCHEDULE_MODE_UNKNOWN */
        tmp_ctl->schedule_mode = SCHEDULE_MODE_UNKNOWN;
    }

    INCREASE_PRIVATE_RDATA_CTL_NUM(1);
    return private_rdata_ctl;
}


static inline struct adns_rdata *__rdata_alloc(adns_type_t type)
{
	int socket_id;
    void *data;
	struct adns_rdata *rdata;

	socket_id = rte_socket_id();
	if (socket_id >= ADNS_MAX_SOCKETS) {
		return NULL;
    }

    if (rte_mempool_get(g_rdata_pools[socket_id], &data) < 0) {
        log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, socket id = %d\n", __FUNCTION__, socket_id);
        return NULL;
	}
    memset(data, 0, sizeof(struct adns_rdata));
    rdata = (struct adns_rdata *)data;
    INIT_LIST_HEAD(&(rdata->list));

	INCREASE_RR_NUM(1);
    INCREASE_RR_DETAIL_NUM(type, 1);
	return rdata;
}

struct adns_rdata *rdata_alloc(adns_type_t type)
{
    return __rdata_alloc(type);
}

static inline void rrset_free(struct adns_rrset *rrset)
{
    int socket_id = rte_socket_id();

	if (rrset == NULL) {
		return;
    }

	if (socket_id >= ADNS_MAX_SOCKETS) {
		return;
    }

    rte_mempool_put(g_rrset_pools[socket_id], (void *)rrset);

    DECREASE_RRSET_MEMORY_NUM(1);
    return;
}


static inline void rdata_ctl_free(struct adns_rdata_ctl *rdata_ctl)
{
    int socket_id = rte_socket_id();

	if (rdata_ctl == NULL) {
		return;
    }
    
	if (socket_id >= ADNS_MAX_SOCKETS) {
		return;
    }

    rte_mempool_put(g_rdata_ctl_pools[socket_id], (void *)rdata_ctl);

    DECREASE_RDATA_CTL_NUM(1);
    return;
}

static inline void private_rdata_ctl_free(struct adns_rdata_ctl *private_rdata_ctl)
{
    int socket_id = rte_socket_id();

    if (private_rdata_ctl == NULL) {
        return;
    }

    if (socket_id >= ADNS_MAX_SOCKETS) {
        return;
    }

    rte_mempool_put(g_private_rdata_ctl_pools[socket_id], (void *)private_rdata_ctl);

    DECREASE_PRIVATE_RDATA_CTL_NUM(1);
    return;
}


static inline void __rdata_free(struct adns_rdata *rdata, adns_type_t type)
{
    int socket_id = rte_socket_id();

	if (rdata == NULL) {
		return;
    }

	if (socket_id >= ADNS_MAX_SOCKETS) {
		return;
    }

    rte_mempool_put(g_rdata_pools[socket_id], (void *)rdata);

    DECREASE_RR_NUM(1);
	DECREASE_RR_DETAIL_NUM(type, 1);
    return;
}

void rdata_free(struct adns_rdata *rdata, adns_type_t type)
{
    __rdata_free(rdata, type);
}

struct adns_rrset *adns_rrset_new(adns_type_t type, 
                              adns_rclass_t rclass, adns_ttl_t ttl)
{
	struct adns_rrset *rrset;

	rrset = rrset_alloc();
	if (rrset == NULL) {
		return NULL;
    }
    INIT_LIST_HEAD(&(rrset->default_rdata.list));
    /* init schedule mode for default rdata ctl */
    rrset->default_rdata.schedule_mode = SCHEDULE_MODE_UNKNOWN;

	rrset->type = type;
	rrset->rclass = rclass;
    rrset->ttl = ttl;

	return rrset;
}


void adns_rrset_deep_free(struct adns_rrset *rrset)
{
	int i;
    struct adns_rdata *elem, *elem_next;
    struct list_head *h_list;
    struct adns_rdata_ctl *tmp_ctl;

	if (rrset == NULL) {
		return;
    }

    /* if default_ns flag is set, means that the rrset is default NS rrset, which only has
        default rdata_ctl and should not be free, only decrement the ref count is enough
    */
    if (rrset->default_ns == 1) {
        rrset->ref_count --;
        return;
    }

    rrset->default_rdata.rdata_count = 0; /*optimize for data core*/
    if (rrset->ctl_rdata != NULL) {
        rrset->ctl_rdata->rdata_count = 0;
    }

    h_list = &(rrset->default_rdata.list);
    list_for_each_entry_safe(elem, elem_next, h_list, list) {
        list_del(&(elem->list));
        rte_free(elem->data);
        __rdata_free(elem, rrset->type);
    }

    if (rrset->ctl_rdata != NULL) {
        for (i = 0; i < g_view_max_num; i++) {
            tmp_ctl = (struct adns_rdata_ctl *)((char *)(rrset->ctl_rdata) + i*sizeof(struct adns_rdata_ctl));
            h_list = &(tmp_ctl->list);
            list_for_each_entry_safe(elem, elem_next, h_list, list) {
                list_del(&(elem->list));
                rte_free(elem->data);
                __rdata_free(elem, rrset->type);
            }
        }
    }

    rdata_ctl_free(rrset->ctl_rdata);

    if (rrset->private_ctl_rdata != NULL) {
        for (i = 0; i < g_private_route_per_zone_max_num; i ++) {
            tmp_ctl = (struct adns_rdata_ctl *)((char *)(rrset->private_ctl_rdata) + i*sizeof(struct adns_rdata_ctl));
            h_list = &(tmp_ctl->list);
            list_for_each_entry_safe(elem, elem_next, h_list, list) {
                list_del(&(elem->list));
                rte_free(elem->data);
                __rdata_free(elem, rrset->type);
            }
        }
    }

    private_rdata_ctl_free(rrset->private_ctl_rdata);

	rrset_free(rrset);

	return;
}


uint8_t *adns_rrset_create_rdata(struct adns_rdata_ctl *rdata_ctl, 
                                 const uint16_t size, adns_weight_t weight, adns_type_t type)
{
	uint8_t *dst;
    struct adns_rdata *rdata;
    struct list_head *h_list;

	if (size == 0) {
		return NULL;
	}

    if (rdata_ctl->rdata_count >= USHRT_MAX) {
        log_server_warn(rte_lcore_id(), "[%s]: rdata count exceed limit %u\n", __FUNCTION__, USHRT_MAX);
        return NULL;
    }

    weight *= g_large_weight;
    if (rdata_ctl->tw + weight > G_MAX_TOTAL_WEIGHT) {
        log_server_warn(rte_lcore_id(), "[%s]: total weight exceed limit %u\n", __FUNCTION__, TOTAL_WEIGHT_MAX);
        return NULL;
    }

    rdata = __rdata_alloc(type);
    if (rdata == NULL) {
        return NULL;
    }

	dst = (uint8_t *)rte_zmalloc(NULL, size, 0);
	if (dst == NULL) {
        __rdata_free(rdata, type);
		return NULL;
	}

    h_list = &(rdata_ctl->list);
    list_add(&(rdata->list), h_list);
    rdata_ctl->rdata_count++;

	rdata->data = dst;
	rdata->len = size;
    rdata->cw = weight;
    rdata_ctl->tw += weight;

	return dst;
}


int adns_rrset_add_rdata(struct adns_rdata_ctl *rdata_ctl, 
                         const uint8_t *rdata, uint16_t size, adns_weight_t weight, const char *original_rdata, adns_type_t type)
{
    uint8_t *ptr;
    struct adns_rdata *elem, *elem_next;
    struct list_head *h_list;

    if (rdata_ctl == NULL || rdata == NULL || size == 0) {
    	return -1;
    }

    h_list = &(rdata_ctl->list);
    list_for_each_entry_safe(elem, elem_next, h_list, list) {
        if ((elem->len == size)
                && (!memcmp(elem->data, rdata, size))) {
            log_server_warn(rte_lcore_id(), "[%s]: Add rdata failed, rdata = \"%s\" (%d) exsit\n", __FUNCTION__, original_rdata, size);
            return 0;
        }
    }    

    ptr = adns_rrset_create_rdata(rdata_ctl, size, weight, type);
    if (ptr == NULL) {
    	return -2;
    }
    memcpy(ptr, rdata, size);

	return 0;
}


int adns_rrset_edit_rdata(struct adns_rdata_ctl *rdata_ctl,
                          const uint8_t *rdata, int rdata_len, adns_weight_t weight, const char *original_rdata)
{
    struct adns_rdata *elem, *elem_next;
    struct list_head *h_list;

    if ((rdata_ctl == NULL) || (rdata == NULL)) {
        return -1;
    }

    h_list = &(rdata_ctl->list);
    list_for_each_entry_safe(elem, elem_next, h_list, list) {
        if ((elem->len == rdata_len)
            && (!memcmp(elem->data, rdata, rdata_len))) {
            if (elem->cw != weight * g_large_weight) {
                rdata_ctl->tw = rdata_ctl->tw - elem->cw + weight * g_large_weight;
                elem->cw = weight * g_large_weight;
            }
            return 0;
        }
    }

    log_server_warn(rte_lcore_id(), "[%s]: Edit rdata failed, rdata = \"%s\" not exsit\n", __FUNCTION__, original_rdata);
    return -2;
}


struct adns_rdata_ctl* adns_rrset_get_rdata_ctl(struct adns_rrset *rrset, adns_viewid_t view_id)
{
    if (rrset == NULL) {
        return NULL;
    }

    if (view_id >= g_view_max_num) {
        return NULL;
    }

    if (view_id == 0) {
        return &(rrset->default_rdata);
    } else {
        if (rrset->ctl_rdata == NULL) {
            return NULL;
        }

        return (struct adns_rdata_ctl *)((char *)(rrset->ctl_rdata) 
                    + view_id * sizeof(struct adns_rdata_ctl));
    }
}

struct adns_rdata_ctl* adns_rrset_new_rdata_ctl(struct adns_rrset *rrset, adns_viewid_t view_id)
{
    struct adns_rdata_ctl *rdata_ctl;

    if (rrset == NULL) {
        return NULL;    
    } 

    if (view_id >= g_view_max_num) {
        return NULL;
    }

    if (rrset->ctl_rdata != NULL) {
        return (struct adns_rdata_ctl *)(((char *)(rrset->ctl_rdata)) 
                    + view_id * sizeof(struct adns_rdata_ctl));
    }

    rdata_ctl = rdata_ctl_alloc();
    if (rdata_ctl == NULL) {
        return NULL;
    }

    rrset->ctl_rdata = rdata_ctl;
    return (struct adns_rdata_ctl *)((char *)rdata_ctl 
                    + view_id * sizeof(struct adns_rdata_ctl));
}


struct adns_rdata_ctl* adns_rrset_get_private_rdata_ctl(struct adns_rrset *rrset, adns_private_route_id_t private_route_id)
{
    if (rrset == NULL) {
        return NULL;
    }

    if (rrset->private_ctl_rdata == NULL) {
        return NULL;
    }

    if (private_route_id >= g_private_route_per_zone_max_num) {
        return NULL;
    }

    return (struct adns_rdata_ctl *)((char *)(rrset->private_ctl_rdata) 
                + private_route_id * sizeof(struct adns_rdata_ctl));
}


struct adns_rdata_ctl* adns_rrset_new_private_rdata_ctl(struct adns_rrset *rrset, adns_private_route_id_t private_route_id)
{
    struct adns_rdata_ctl *private_rdata_ctl;

    if (rrset == NULL) {
        return NULL;
    }

    if (private_route_id >= g_private_route_per_zone_max_num) {
        return NULL;
    }

    if (rrset->private_ctl_rdata != NULL) {
        return (struct adns_rdata_ctl *)(((char *)(rrset->private_ctl_rdata)) 
                    + private_route_id * sizeof(struct adns_rdata_ctl));
    }

    private_rdata_ctl = private_rdata_ctl_alloc();
    if (private_rdata_ctl == NULL) {
        return NULL;
    }

    rrset->private_ctl_rdata = private_rdata_ctl;
    return (struct adns_rdata_ctl *)((char *)private_rdata_ctl 
                    + private_route_id * sizeof(struct adns_rdata_ctl));
}

void adns_rrset_del_rdata(struct adns_rdata_ctl *rdata_ctl, const char *rdata, int rdata_len, const char *original_rdata, adns_type_t type)
{
	struct adns_rdata *elem, *elem_next;
    struct list_head *h_list;

    if ((rdata_ctl == NULL) || (rdata == NULL)) {
        return;
    }

    h_list = &(rdata_ctl->list);
    list_for_each_entry_safe(elem, elem_next, h_list, list) {
        if ((elem->len == rdata_len)
            && (!memcmp(elem->data, rdata, rdata_len))) {
            rdata_ctl->tw -= elem->cw;
            rdata_ctl->rdata_count--;
            list_del(&(elem->list));
            rte_free(elem->data);   
            __rdata_free(elem, type);
            /* recover view's schedule mode */
            if (rdata_ctl->rdata_count == 0) {
                rdata_ctl->schedule_mode = SCHEDULE_MODE_UNKNOWN;
            }
            return;
        }
    }

    log_server_warn(rte_lcore_id(), "[%s]: Del rdata failed. rdata = \"%s\" not exsit\n", __FUNCTION__, original_rdata);
    return;
}


void adns_rrset_cleanup_rdatas_for_ctl(struct adns_rdata_ctl *rdata_ctl, adns_type_t type)
{
    struct list_head *h_list;
    struct adns_rdata *elem, *elem_next;

    if (rdata_ctl == NULL) {
        return;
    }

    rdata_ctl->rdata_count = 0;
    h_list = &(rdata_ctl->list);
    list_for_each_entry_safe(elem, elem_next, h_list, list) {
        list_del(&(elem->list));
        rte_free(elem->data);
        __rdata_free(elem, type);
    }
    /* recover view's schedule mode */
    rdata_ctl->schedule_mode = SCHEDULE_MODE_UNKNOWN;

    return;
}


int adns_rrset_check_rdata_exist(struct adns_rrset *rrset)
{
    int i;
    struct adns_rdata_ctl *tmp_ctl;

    if (rrset == NULL) {
        return 0;
    }

    if (rrset->default_rdata.rdata_count != 0) {
        return -1;
    } 

    if (rrset->ctl_rdata != NULL) {
        for (i = 0; i < g_view_max_num; i++) {
            tmp_ctl = (struct adns_rdata_ctl *)((char *)(rrset->ctl_rdata) + i * sizeof(struct adns_rdata_ctl));
            if (tmp_ctl->rdata_count != 0) {
                return -1;
            }
        }
    }

    return 0;
}


int adns_rrset_check_rdata_exist_in_view(struct adns_rrset *rrset, adns_viewid_t view_id)
{
    struct adns_rdata_ctl *tmp_ctl;

    if (rrset == NULL) {
        return 0;
    }
    
    if(view_id  == 0){
        if(rrset->default_rdata.rdata_count != 0) {
            return -1;
        }else{
            return 0;
        }
    }

    if (rrset->ctl_rdata != NULL) {
        tmp_ctl = (struct adns_rdata_ctl *)((char *)(rrset->ctl_rdata) + view_id * sizeof(struct adns_rdata_ctl));
        if (tmp_ctl->rdata_count != 0){
            return -1;
        }
    }

    return 0;
}

int adns_rrset_check_rdata_exist_in_private_route(struct adns_rrset *rrset, adns_private_route_id_t private_route_id)
{
    struct adns_rdata_ctl *tmp_ctl;

    if (rrset == NULL) {
        return 0;
    }

    if (private_route_id >= g_private_route_per_zone_max_num) {
        return 0;
    }

    if (rrset->private_ctl_rdata) {
        tmp_ctl = (struct adns_rdata_ctl *)((char *)(rrset->private_ctl_rdata) + private_route_id * sizeof(struct adns_rdata_ctl));
        if (tmp_ctl->rdata_count != 0){
            return -1;
        }
    }
    return 0;
}


int rrset_init(void)
{
    int socket_id, lcore_id = rte_lcore_id();
    char name[64];

    socket_id = 0;

    if (g_rrset_pools[socket_id] == NULL) {
        memset(name, 0, sizeof(name));
        snprintf(name, sizeof(name), "g_rrset_pools_%d", socket_id);
        g_rrset_pools[socket_id] = rte_mempool_create(name, g_rrset_memory_max_num,
                sizeof(struct adns_rrset), 32, 0, NULL, NULL, NULL,
                NULL, 0, 0);
        if (g_rrset_pools[socket_id] == NULL) {
            return -1;
        }
        printf("Finish to alloc g_rrset_pools %s, core id %d\n", name, lcore_id);
    }

    if (g_rdata_ctl_pools[socket_id] == NULL) {
        memset(name, 0, sizeof(name));
        snprintf(name, sizeof(name), "g_rdata_ctl_pools_%d", socket_id);
        g_rdata_ctl_pools[socket_id] = rte_mempool_create(name, g_rdata_ctl_max_num,
                sizeof(struct adns_rdata_ctl)*g_view_max_num, 32, 0, NULL, NULL, NULL,
                NULL, 0, 0); 
        
        if (g_rdata_ctl_pools[socket_id] == NULL) {
            return -1;
        }

        printf("Finish to alloc g_rdata_ctl_pools %s, core id %d\n", name, lcore_id);
    }

    if (g_rdata_pools[socket_id] == NULL) {
        memset(name, 0, sizeof(name));
        snprintf(name, sizeof(name), "g_rdata_large_ctl_pools_%d", socket_id);
        g_rdata_pools[socket_id] = rte_mempool_create(name, g_rr_max_num,
                sizeof(struct adns_rdata), 32, 0, NULL, NULL, NULL, 
                NULL, 0, 0); 

        if (g_rdata_pools[socket_id] == NULL) {
            return -1;
        }

        printf("Finish to alloc g_rdata_pools %s, core id %d\n", name, lcore_id);
    }

    if (g_private_rdata_ctl_pools[socket_id] == NULL) {
        memset(name, 0, sizeof(name));
        snprintf(name, sizeof(name), "g_pri_rdata_ctl_pools_%d", socket_id);
        g_private_rdata_ctl_pools[socket_id] =rte_mempool_create(name, g_private_rdata_ctl_max_num,
            sizeof(struct adns_rdata_ctl) * g_private_route_per_zone_max_num, 32, 0, NULL, NULL, NULL,
            NULL, 0, 0);
        if (g_private_rdata_ctl_pools[socket_id] == NULL) {
            fprintf(stdout, "[%s]: fail to alloc g_private_rdata_ctl_pools_%d %s\n", __FUNCTION__, socket_id, name);
            return -1;
        }

        printf("Finish to alloc g_private_rdata_ctl_pools %s, core id %d\n", name, lcore_id);
    }

    /* init ns list */
    if (ns_list_init() != 0) {
        fprintf(stdout, "[%s]: fail to init default NS list\n", __FUNCTION__);
        return -1;
    }

	return 0;
}


void rrset_cleanup(void)
{
}

int ns_list_init(void)
{
    struct adns_ns_list_hash *ns_tbl = NULL;
    
    ns_tbl = ns_list_load(0);
    if (ns_tbl == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: default NS list init error\n", __FUNCTION__);
        return -1;
    }

    g_ns_tbl = ns_tbl;

    return 0;
}

/* Add new NS to ns list */
static int _ns_list_add(struct adns_ns_list_hash *ns_tbl, struct adns_rrset** ns_rrsets, uint8_t *ns_name, uint8_t ns_name_len, uint32_t ns_group_id, uint32_t ttl, int reload)
{
    uint32_t hash;
    struct adns_ns_list_hash *h_node;
    struct list_head *hash_h_list, *h_list;
    struct adns_ns_list_elem *new_ns;
    struct adns_rrset *rrset = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rdata *elem, *elem_next, *rdata;
    struct adns_ns_list_elem *ns;

    if (ns_tbl == NULL || ns_name == NULL) {
        return -1;
    }

    hash = mm3_hash((const char *)ns_name, ns_name_len);
    h_node = &ns_tbl[hash & ADNS_NS_LIST_HASH_MASK];
    hash_h_list = &(h_node->list);

    list_for_each_entry(ns, hash_h_list, list) {
        if (ns->ns_rdata != NULL
            && ns->ns_rdata->len == ns_name_len
            && !memcmp(ns->ns_rdata->data, ns_name, ns_name_len)) {
            char *ns_str = adns_dname_to_str(ns_name);
            log_server_warn(rte_lcore_id(), "[%s]: NS %s is duplicated\n", __FUNCTION__, ns_str);
            free(ns_str);
            return -1;
        }
    }

    rdata = __rdata_alloc(ADNS_RRTYPE_NS);
    if (rdata == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: allocate new NS rdata error\n", __FUNCTION__);
        return -1;
    }
    rdata->data = (uint8_t *)rte_zmalloc(NULL, ns_name_len, 0);
    if (rdata->data == NULL) {
        __rdata_free(rdata, ADNS_RRTYPE_NS);
        log_server_warn(rte_lcore_id(), "[%s]: allocate new NS rdata value error\n", __FUNCTION__);
        return -1;
    }

    rdata->len = ns_name_len;
    memcpy(rdata->data, ns_name, ns_name_len);
    rdata->cw = 0;

    if (ns_rrsets != NULL) {
        rrset = ns_rrsets[ns_group_id];
        /* add new NS rrset */
        if (rrset == NULL) {
            rrset = adns_rrset_new(ADNS_RRTYPE_NS, ADNS_CLASS_IN, ttl);
            if (rrset == NULL) {
                rte_free(rdata->data);
                __rdata_free(rdata, ADNS_RRTYPE_NS);
                log_server_warn(rte_lcore_id(), "[%s]: allocate new NS rrset error\n", __FUNCTION__);
                return -1;
            }
            /* the rrset is default NS rrset */
            rrset->default_ns = 1;
            rdata_ctl = &(rrset->default_rdata);
            h_list = &(rdata_ctl->list);
            list_add(&(rdata->list), h_list);
            rdata_ctl->rdata_count++;
            g_ns_rrsets[ns_group_id] = rrset;
        }
        else { /* add new NS rdata to existing NS rrset */
            rdata_ctl = &(rrset->default_rdata);
            h_list = &(rdata_ctl->list);
            list_for_each_entry_safe(elem, elem_next, h_list, list) {
                if ((elem->len == rdata->len)
                        && (!memcmp(elem->data, rdata->data, rdata->len))) {
                    rte_free(rdata->data);
                    __rdata_free(rdata, ADNS_RRTYPE_NS);
                    log_server_warn(rte_lcore_id(), "[%s]: NS duplicated in group %d\n", __FUNCTION__, ns_group_id);
                    return -1;
                }
            }
            if (rdata_ctl->rdata_count >= ADNS_MAX_NS_NUM_PER_GROUP) {
                rte_free(rdata->data);
                __rdata_free(rdata, ADNS_RRTYPE_NS);
                log_server_warn(rte_lcore_id(), "[%s]: Too many NS in group %d\n", __FUNCTION__, ns_group_id);
                return -1;
            }

            list_add(&(rdata->list), h_list);
            rdata_ctl->rdata_count++;
            rrset->ttl = ttl;
        }
    }

    new_ns = (struct adns_ns_list_elem *)rte_zmalloc(NULL, sizeof(struct adns_ns_list_elem), 0);
    if (new_ns == NULL) {
        rte_free(rdata->data);
        __rdata_free(rdata, ADNS_RRTYPE_NS);
        log_server_warn(rte_lcore_id(), "[%s]: alocate new NS error\n", __FUNCTION__);
        return -1;
    }
    INIT_LIST_HEAD(&(new_ns->list));
    if (reload == 1) {
        new_ns->fresh = 1;
    }
    new_ns->ns_group_id = ns_group_id;
    new_ns->ns_rdata = rdata;
    new_ns->ttl = ttl;

    list_add(&(new_ns->list), hash_h_list);
    h_node->size ++;

    return 0;
}

static int _ns_list_load(struct adns_ns_list_hash *ns_tbl, struct adns_rrset** ns_rrsets, char *ns_list_file, int reload)
{
    int line_idx = 0, i;
    char line[1024] = {0};
    FILE *fp = NULL;
    int line_length = 0;
    char *str, *line_trim = NULL, *saveptr = NULL, *token, *buf[10], *c;
    uint32_t ns_group_id, ttl;

    if (ns_list_file == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: default NS list file is NULL\n", __FUNCTION__);
        return -1;
    }

    if (ns_tbl == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: default NS list is NULL\n", __FUNCTION__);
        return -1;
    }

    fp = fopen(ns_list_file, "r");
    if (fp == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: Cannot open file: %s\n", __FUNCTION__, ns_list_file);
        return -1;
    }

    while (!feof(fp) && fgets(line, sizeof(line) - 1, fp) != NULL ) {
        /* process one line */
        line_idx ++;
        line_length = strlen(line);

        if (line_length > 0) {
            if (line[line_length - 1] == '\n') {
                line[line_length - 1] = '\0';
            }

            if (line_length > 0 && line[line_length - 1] == '\r') {
                line[line_length - 1] = '\0';
            }
        }

        line_trim = rm_whitespace(line);
        for (i = 0, str = line_trim; ; i++, str = NULL) {
            token = strtok_r(str, " ", &saveptr);
            if (token == NULL) {
                break;
            }
            
            if (i >= 5) {
                break;  
            }
            buf[i] = token;
        }
        /* check NS group list syntax */
        /* NS list file syntax: NS NS_GROUP_ID TTL */
        if (i != 3) {
            log_server_warn(rte_lcore_id(), "[%s]: NS list file line %d syntax error\n", __FUNCTION__, line_idx);
            goto err;
        }

        /* check NS group ID */
        c = buf[1];
        while (*c) {
            if (!isdigit((int)*c)) {
                log_server_warn(rte_lcore_id(), "[%s]: NS group ID syntax error %s, line %d\n", __FUNCTION__, buf[1], line_idx);
                goto err;
            }
            c ++;
        }
        ns_group_id = (uint32_t)atoi(buf[1]);
        if (ns_group_id >= g_ns_group_max_num) {
            log_server_warn(rte_lcore_id(), "[%s]: NS group ID exceed limit %d, line %d\n", __FUNCTION__, g_ns_group_max_num, line_idx);
            goto err;
        }

        /* get TTL */
        c = buf[2];
        while (*c) {
            if (!isdigit((int)*c)) {
                log_server_warn(rte_lcore_id(), "[%s]: NS TTL syntax error %s, line %d\n", __FUNCTION__, buf[2], line_idx);
                goto err;
            }
            c ++;
        }
        ttl = (uint32_t)atoi(buf[2]);

        /* get NS in wire format */
        adns_dname_t *ns_name = adns_dname_from_str(buf[0], strlen(buf[0]));
        if (ns_name == NULL) {
            log_server_warn(rte_lcore_id(), "[%s]: NS list file line %d syntax error\n", __FUNCTION__, line_idx);
            goto err;
        }

        int ns_name_len = adns_dname_size(ns_name);

        if (_ns_list_add(ns_tbl, ns_rrsets, ns_name, (uint8_t)ns_name_len, ns_group_id, ttl, reload) < 0) {
            free(ns_name);
            goto err;
        }
        free(ns_name);

        memset(line, 0, 1024);
    }

    fclose(fp);
    return 0;
err:
    fclose(fp);
    return -1;
}

struct adns_ns_list_hash* ns_list_load(int reload)
{
    struct adns_ns_list_hash *ns_tbl = NULL;
    struct adns_rrset** ns_rrsets = NULL;
    int i;


    // allocate NS list hash table
    ns_tbl = (struct adns_ns_list_hash *)rte_zmalloc(NULL, sizeof(struct adns_ns_list_hash) * ADNS_NS_LIST_HASH_SIZE, 0);
    if (ns_tbl == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: Allocate memory for default NS list error\n", __FUNCTION__);
        return NULL;
    }

    for (i = 0; i < ADNS_NS_LIST_HASH_SIZE; i ++) {
        INIT_LIST_HEAD(&(ns_tbl[i].list));
        ns_tbl[i].size = 0;
    }

    /* if reload the ns group list, no need to handle NS rrset table */
    if (reload == 0) {
        // allocate NS group
        ns_rrsets = (struct adns_rrset **)rte_zmalloc(NULL, sizeof(struct adns_rrset *) * g_ns_group_max_num, 0);
        if (ns_rrsets == NULL) {
            rte_free(ns_tbl);
            log_server_warn(rte_lcore_id(), "[%s]: Allocate memory for default NS group error\n", __FUNCTION__);
            return NULL;
        }
        g_ns_rrsets = ns_rrsets;
    }

    if (_ns_list_load(ns_tbl, ns_rrsets, g_ns_list_file, reload) != 0) {
        log_server_warn(rte_lcore_id(), "[%s]: load default NS list error\n", __FUNCTION__);
        if (ns_rrsets != NULL) {
            ns_rrsets_free(ns_rrsets);
        }
        ns_list_deep_free(ns_tbl);
        return NULL;
    }

    return ns_tbl;
}

struct adns_ns_list_elem* ns_list_lookup(struct adns_ns_list_hash *ns_tbl, uint8_t *ns_name, uint8_t ns_name_len, uint32_t ttl)
{
    uint32_t hash;
    struct adns_ns_list_hash *h_node;
    struct list_head *h_list;
    struct adns_ns_list_elem *ns;

    if (ns_tbl == NULL) {
        return NULL;
    }

    if (ns_name == NULL) {
        return NULL;
    }

    hash = mm3_hash((const char *)ns_name, ns_name_len);
    h_node = &ns_tbl[hash & ADNS_NS_LIST_HASH_MASK];
    h_list = &(h_node->list);

    list_for_each_entry(ns, h_list, list) {
        if (ns->ns_rdata != NULL
            && ns->ns_rdata->len == ns_name_len
            && !memcmp(ns->ns_rdata->data, ns_name, ns_name_len)
            && ns->ttl == ttl) {
            return ns;
        }
    }

    return NULL;
}

/* Merge new NS list to the old NS list
    For memory organization reason, 
    Deleting existing NS is not allowed
    Only append new NS is allowed 
    
    return:
    -1: pre merge new NS table to old NS table fails, only need free the new NS table
    -2: failure occurs during merge progress, need recover the partially merged ns_list_hash */
int ns_list_tbl_merge(struct adns_ns_list_hash *old_ns_tbl, struct adns_ns_list_hash *new_ns_tbl)
{
    struct adns_ns_list_hash *h_node;
    struct list_head *h_list;
    struct adns_ns_list_elem *ns, *ns_next;
    struct adns_ns_list_elem *new_ns;
    int i;

    if (old_ns_tbl == NULL || new_ns_tbl == NULL) {
        return -1;
    }

    /* Check if old NS exists in the new NS list */
    for (i = 0; i < ADNS_NS_LIST_HASH_SIZE; i ++) {
        h_node = &old_ns_tbl[i];
        h_list = &(h_node->list);

        list_for_each_entry_safe(ns, ns_next, h_list, list) {               
            if (ns->ns_rdata) {
                new_ns = ns_list_lookup(new_ns_tbl, ns->ns_rdata->data, ns->ns_rdata->len, ns->ttl);
                if (new_ns == NULL) {
                    log_server_warn(rte_lcore_id(), "[%s]: Old NS not exist in new NS list, error\n", __FUNCTION__);
                    return -1;
                }
                if (new_ns->ns_group_id != ns->ns_group_id) {
                    log_server_warn(rte_lcore_id(), "[%s]: Not allow to modify NS group ID\n", __FUNCTION__);
                    return -1;
                }
                /* set unchanged flag for further merge */
                new_ns->unchanged = 1;
            }
            /* clear fresh flag */
            ns->fresh = 0;
        }
    }

    /* append new NS */
    for (i = 0; i < ADNS_NS_LIST_HASH_SIZE; i ++) {
        h_node = &new_ns_tbl[i];
        h_list = &(h_node->list);

        list_for_each_entry_safe(ns, ns_next, h_list, list) {
            if (ns->unchanged != 1) {
                if (_ns_list_add(old_ns_tbl, g_ns_rrsets, ns->ns_rdata->data, ns->ns_rdata->len, ns->ns_group_id, ns->ttl, 1)) {
                    log_server_warn(rte_lcore_id(), "[%s]: Append new NS error\n", __FUNCTION__);
                    return -2;
                }
            }
        }
    }

    return 0;
}

void ns_list_recover(struct adns_ns_list_hash *old_ns_tbl)
{
    struct adns_ns_list_hash *h_node;
    struct list_head *h_list;
    struct adns_ns_list_elem *ns, *ns_next;
    int i;

    if (old_ns_tbl == NULL) {
        return;
    }

    for (i = 0; i < ADNS_NS_LIST_HASH_SIZE; i ++) {
        h_node = &old_ns_tbl[i];
        h_list = &(h_node->list);

        list_for_each_entry_safe(ns, ns_next, h_list, list) {
            /* the freshly added ns list elem from merge should be free in recovery*/
            if (ns->fresh) {
                list_del(&ns->list);
                if (ns->ns_rdata) {
                    if (ns->ns_rdata->data) {
                        rte_free(ns->ns_rdata->data);
                    }
                    __rdata_free(ns->ns_rdata, ADNS_RRTYPE_NS);
                }
                rte_free(ns);
                h_node->size --;
            }
        }
    }
}

void ns_list_deep_free(struct adns_ns_list_hash *ns_tbl)
{
    struct adns_ns_list_hash *h_node;
    struct list_head *h_list;
    struct adns_ns_list_elem *ns, *ns_next;
    int i;

    if (ns_tbl == NULL) {
        return;
    }

    for (i = 0; i < ADNS_NS_LIST_HASH_SIZE; i ++) {
        h_node = &ns_tbl[i];
        h_list = &(h_node->list);

        list_for_each_entry_safe(ns, ns_next, h_list, list) {               
            list_del(&ns->list);
            if (ns->ns_rdata) {
                if (ns->ns_rdata->data) {
                    rte_free(ns->ns_rdata->data);
                }
                __rdata_free(ns->ns_rdata, ADNS_RRTYPE_NS);
            }
            rte_free(ns);
            h_node->size --;
        }
    }

    rte_free(ns_tbl);
}

void ns_rrsets_free(struct adns_rrset** ns_rrsets)
{
    int i;
    struct adns_rrset *rrset;
    struct list_head *h_list;
    struct adns_rdata *elem, *elem_next;

    if (ns_rrsets == NULL) {
        return;
    }

    for (i = 0; i < g_ns_group_max_num; i ++) {
        rrset = ns_rrsets[i];
        if (rrset != NULL) {
            h_list = &(rrset->default_rdata.list);
            list_for_each_entry_safe(elem, elem_next, h_list, list) {
                list_del(&(elem->list));
            }
            rrset_free(rrset);
        }
    }

    rte_free(ns_rrsets);
}
