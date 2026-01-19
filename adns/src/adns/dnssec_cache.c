#include <unistd.h>

#include "rte_lcore.h"
#include "rte_string_fns.h"
#include "rte_memzone.h"
#include "rte_mempool.h"
#include "rte_malloc.h"


#include "log.h"
#include "dnssec_cache.h"
#include "adns_share.h"
#include "view_maps.h"
#include "iplib.h"
#include "base64.h"
#include "dns_pkt.h"
#include "adns_stats.h"
#include "rcu.h"


// global dnssec cache db
adns_dnssec_cache_db *g_dnssec_cache_db = NULL;
// adns_dnssec_cache_node mempool
static struct rte_mempool *g_dnssec_cache_node_pool = NULL;
// declare here other than in admin.c since this global counter only changed in query process
// DNSSEC cache node allocated 
uint32_t g_dnssec_cache_num = 0;

// DNSSEC cache clean list
static adns_dnssec_cache_hash g_dnssec_cache_clean_hash;
uint32_t g_dnssec_cache_clean_thresh = 0;

static adns_dnssec_cache_db * adns_dnssec_cache_db_new(int socket_id, const char *cache_db_name)
{
    int i;
    adns_dnssec_cache_db *db;

    db = rte_zmalloc_socket(cache_db_name, sizeof(adns_dnssec_cache_db), 0, socket_id);
    if (db == NULL) {
        return NULL;
    }
    db->dnssec_cache_count = 0;

    for (i = 0; i < ADNS_DNSSEC_CACHE_HASH_SIZE; i++) {
        INIT_LIST_HEAD(&(db->dnssec_cache_tbl[i].list));
        db->dnssec_cache_tbl[i].size = 0;
    }

    return db;
}

int adns_dnssec_cache_db_init(void)
{
    adns_socket_id_t socket_id;
    socket_id = rte_socket_id();

    // Create g_dnssec_cache_node_pool
    g_dnssec_cache_node_pool = rte_mempool_create("g_dnssec_cache_pool", g_dnssec_cache_max_num, 
                                            sizeof(adns_dnssec_cache_node), 32, 0, NULL, NULL, NULL, NULL, socket_id, 0);
    if (g_dnssec_cache_node_pool == NULL) {
        fprintf(stdout, "[%s]: Fail to init DNSSEC cache mempool\n", __FUNCTION__);
        return -1;
    }
    fprintf(stdout, "[%s]: Finish to new g_dnssec_cache_node_pool\n", __FUNCTION__);

    // Create g_dnssec_cache_db
    g_dnssec_cache_db = adns_dnssec_cache_db_new(socket_id, "g_dnssec_cache_db");
    if (g_dnssec_cache_db == NULL) {
        rte_mempool_free(g_dnssec_cache_node_pool);
        fprintf(stdout, "[%s]: Fail to init DNSSEC cache db\n", __FUNCTION__);
        return -1;
    }
    fprintf(stdout, "[%s]: Finish to new g_dnssec_cache_db\n", __FUNCTION__);

    // init g_dnssec_cache_clean_hash
    INIT_LIST_HEAD(&(g_dnssec_cache_clean_hash.list));
    g_dnssec_cache_clean_hash.size = 0;

    return 0;
}

uint32_t adns_dnssec_cache_db_count(adns_dnssec_cache_db *dnssec_cache_db)
{
    if (dnssec_cache_db == NULL) {
        return 0;
    }

    return dnssec_cache_db->dnssec_cache_count;
}

adns_dnssec_cache_node * adns_new_dnssec_cache_node(uint8_t *owner,
                                                    uint8_t owner_len,
                                                    uint16_t type,
                                                    adns_viewid_t view_id,
                                                    uint8_t *rdata,
                                                    uint16_t rdlen,
                                                    adns_rrsig_rdata *rrsig_rdata,
                                                    uint8_t *signer,
                                                    uint8_t signer_len,
                                                    uint8_t *signature)
{
    void *data = NULL;
    adns_dnssec_cache_node * cache_node = NULL;
    uint32_t hash;

    if (unlikely(owner == NULL || owner_len == 0 || rdata == NULL || rdlen == 0)) {
        return NULL;
    }

    if (rrsig_rdata == NULL || signer == NULL || signer_len == 0 || signature == NULL) {
        return NULL;
    }

    rte_mempool_get(g_dnssec_cache_node_pool, &data);
    if (data == NULL) {
        // increment DNSSEC allocation error count
        STATS_INC(dnssec_cache_new_err);
        return NULL;
    }
    memset(data, 0, sizeof(adns_dnssec_cache_node));

    cache_node = (adns_dnssec_cache_node*)data;
    INCREASE_DNSSEC_CACHE_NUM(1);
    INIT_LIST_HEAD(&(cache_node->list));
    INIT_LIST_HEAD(&(cache_node->clean_list));

    // set node key
    rte_memcpy(cache_node->owner, owner, owner_len);
    cache_node->owner_len = owner_len;
    cache_node->type = type;
    cache_node->view_id = view_id;

    // set value
    rte_memcpy(&(cache_node->value.rrsig_rdata), rrsig_rdata, sizeof(adns_rrsig_rdata));
    rte_memcpy(cache_node->value.signer, signer, signer_len);
    cache_node->value.signer_len = signer_len;
    rte_memcpy(cache_node->value.signature, signature, DNS_SIG_ECDSA256SIZE);
    hash = gen_hash_key(owner, owner_len, type, view_id, rdata, rdlen);
    cache_node->hash = hash & ADNS_DNSSEC_CACHE_HASH_MASK;

    cache_node->rdata = (uint8_t *)rte_zmalloc(NULL, rdlen, 0);
    if (cache_node->rdata == NULL) {
        adns_free_dnssec_cache_node(cache_node);
        return NULL;
    }
    rte_memcpy(cache_node->rdata, rdata, rdlen);
    cache_node->rdlen = rdlen;

    return cache_node;
}

void adns_free_dnssec_cache_node(adns_dnssec_cache_node *node)
{
    if (node != NULL) {
        if (node->rdata) {
            rte_free(node->rdata);
        }
        rte_mempool_put(g_dnssec_cache_node_pool, (void *)node);
        if (node->free_not_count == 0) {
            DECREASE_DNSSEC_CACHE_NUM(1);
        }
    }
    return;
}

adns_dnssec_cache_node *adns_dnssec_cache_hash_lookup(uint8_t *owner, uint8_t owner_len, uint16_t type, adns_viewid_t view_id, uint8_t *rdata, uint16_t rdlen, adns_ttl_t ttl_n)
{
    adns_dnssec_cache_hash *hash_node = NULL;
    adns_dnssec_cache_node *node = NULL;
    struct list_head *h_list;
    uint32_t hash;

    if (unlikely(owner == NULL || owner_len == 0 || rdata == NULL || rdlen == 0)) {
        return NULL;
    }

    if (unlikely(g_dnssec_cache_db->dnssec_cache_count == 0)) {
        return NULL;
    }

    hash = gen_hash_key(owner, owner_len, type, view_id, rdata, rdlen);
    hash_node = &(g_dnssec_cache_db->dnssec_cache_tbl[hash & ADNS_DNSSEC_CACHE_HASH_MASK]);
    if (unlikely(hash_node->size == 0)) {
        return NULL;
    }

    h_list = &(hash_node->list);

    list_for_each_entry(node, h_list, list) {
        if (node->type == type &&
            node->view_id == view_id &&
            node->value.rrsig_rdata.original_ttl == ttl_n &&
            node->owner_len == owner_len &&
            node->rdlen == rdlen &&
            !memcmp(node->owner, owner, owner_len) &&
            !memcmp(node->rdata, rdata, rdlen)) {
            return node;
        }
    }

    return NULL;
}

int adns_dnssec_cache_add_hash(adns_dnssec_cache_node *node)
{
    adns_dnssec_cache_hash *hash_node = NULL;
    struct list_head *h_list;

    if (node == NULL) {
        return -1;
    }

    hash_node = &(g_dnssec_cache_db->dnssec_cache_tbl[node->hash]);
    h_list = &(hash_node->list);
    list_add(&(node->list), h_list);
    // increment dnssec cache hash table entry size
    hash_node->size ++;

    h_list = &(g_dnssec_cache_clean_hash.list);
    list_add(&(node->clean_list), h_list);
    g_dnssec_cache_clean_hash.size ++;

    // increment dnssec cache total number
    g_dnssec_cache_db->dnssec_cache_count ++;

    return 0;
}

int adns_dnssec_cache_del_hash(adns_dnssec_cache_node *node)
{
    adns_dnssec_cache_hash *hash_node = NULL;

    if (node == NULL) {
        return -1;
    }

    hash_node = &(g_dnssec_cache_db->dnssec_cache_tbl[node->hash]);
    list_del(&(node->list));
    hash_node->size --;

    list_del(&(node->clean_list));
    g_dnssec_cache_clean_hash.size --;

    g_dnssec_cache_db->dnssec_cache_count --;
    return 0;
}

int adns_dnssec_cache_dump_hash(int fd, adns_dnssec_cache_node *node)
{
    char buf[ADNS_LINE_MAX_LEN];
    int w_len = 0;
    unsigned char b64_ec_buf[DNS_SIG_ECDSA256SIZE << 1];
    size_t b64_ec_len = DNS_SIG_ECDSA256SIZE << 1;
    char *dname_str = NULL, *view_name = NULL, *signer_str = NULL;
    const char *cover_type_str;
    int ret = 0, len = 0;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (node == NULL || fd < 0) {
        return -1;
    }

    // convert owner
    dname_str = adns_dname_to_str((const adns_dname_t*)node->owner);

    // convert cover type
    cover_type_str = adns_rrtype_to_string(node->type);

    // convert signer
    signer_str = adns_dname_to_str((const adns_dname_t*)node->value.signer);

    // convert view name
    if (node->view_id == 0) {
        view_name = "default";
    } else {
        if (node->view_id > g_view_max_num) {
            snprintf(custom_view_name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, node->view_id - g_view_max_num);
            view_name = custom_view_name;
        } else {
            view_name = (char *)view_id_to_name(node->view_id);
        }
    }

    // base64 encoding signature
    ret = base64_encode(b64_ec_buf, &b64_ec_len, node->value.signature, DNS_SIG_ECDSA256SIZE);
    b64_ec_buf[b64_ec_len] = '\0';
    // name TTL IN RRSIG (cover_type 13 lable_count orig_ttl expire inception signer key_tag signature) view_name
    w_len = snprintf(buf, ADNS_LINE_MAX_LEN, "%s\t%u\tIN\tRRSIG\t%s 13 %u %u %u %u %s %u %s\t%s\n", 
                                      dname_str == NULL? "invalid-name" : dname_str,
                                      adns_ntohl(node->value.rrsig_rdata.original_ttl),
                                      cover_type_str == NULL? "unsupported-type" : cover_type_str,
                                      node->value.rrsig_rdata.labels,
                                      adns_ntohl(node->value.rrsig_rdata.original_ttl),
                                      adns_ntohl(node->value.rrsig_rdata.time_expire),
                                      adns_ntohl(node->value.rrsig_rdata.time_signed),
                                      signer_str,
                                      adns_ntohs(node->value.rrsig_rdata.key_id),
                                      b64_ec_buf,
                                      view_name == NULL? "unknown-view" : view_name);
    len += w_len;
    write(fd, buf, len);

    if (dname_str != NULL) {
        free(dname_str);
    }

    if (signer_str != NULL) {
        free(signer_str);
    }
    return 0;
}

int adns_dnssec_cache_replace_hash(adns_dnssec_cache_node *new_node, adns_dnssec_cache_node *old_node)
{
    if (new_node == NULL || old_node == NULL) {
        return -1;
    }

    list_replace(&(old_node->list), &(new_node->list));
    list_replace(&(old_node->clean_list), &(new_node->clean_list));
    return 0;
}

int adns_dnssec_cache_clean(uint32_t bulk_num)
{
    int ret, clean_num = 0;
    adns_dnssec_cache_hash *hash_node = NULL;
    adns_dnssec_cache_node *node, *node_prev;
    struct list_head *h_list, *clean_h_list;
    typedef void (*pfn) (void *);

    if (g_dnssec_cache_clean_thresh == 0 && g_dnssec_cache_num < g_dnssec_cache_max_num) {
        return 0;
    }

    // if dnssec cache node ran out, free a quarter
    if (g_dnssec_cache_clean_thresh == 0 ) {
        g_dnssec_cache_clean_thresh = g_dnssec_cache_num >> 2;
    }

    clean_h_list = &(g_dnssec_cache_clean_hash.list);
    int num = RTE_MIN(g_dnssec_cache_clean_thresh, bulk_num);

    list_for_each_entry_prev_safe(node, node_prev, clean_h_list, clean_list) {
        hash_node = &(g_dnssec_cache_db->dnssec_cache_tbl[node->hash]);
        list_del(&(node->list));
        hash_node->size --;

        list_del(&(node->clean_list));
        g_dnssec_cache_clean_hash.size --;

        // g_dnssec_cache_num decrease here
        // cache node free operation is add to rcu event list, will be executed in misc core
        node->free_not_count = 1;
        ret = call_rcu((pfn)adns_free_dnssec_cache_node, node);
        if (ret < 0) {
            log_server_error(rte_lcore_id(), "DNSSEC_CACHE_CLEAN_BULK: call rcu error\n");
            h_list = &(hash_node->list);
            list_add(&(node->list), h_list);
            hash_node->size ++;

            list_add(&(node->clean_list), clean_h_list);
            g_dnssec_cache_clean_hash.size ++;
        } else {
            clean_num ++;
        }

        if (clean_num >= num) {
            break;
        }
    }
    g_dnssec_cache_clean_thresh -= clean_num;
    g_dnssec_cache_num -= clean_num;

    return clean_num;
}

int adns_dnssec_cache_clean_all()
{
    int ret, clean_num = 0;
    adns_dnssec_cache_hash *hash_node = NULL;
    adns_dnssec_cache_node *node, *node_prev;
    struct list_head *h_list, *clean_h_list;

    clean_h_list = &(g_dnssec_cache_clean_hash.list);
    typedef void (*pfn) (void *);

    list_for_each_entry_prev_safe(node, node_prev, clean_h_list, clean_list) {
        hash_node = &(g_dnssec_cache_db->dnssec_cache_tbl[node->hash]);
        list_del(&(node->list));
        hash_node->size --;

        list_del(&(node->clean_list));
        g_dnssec_cache_clean_hash.size --;
        ret = call_rcu( (pfn)adns_free_dnssec_cache_node, node);
        if (ret < 0) {
            log_server_error(rte_lcore_id(), "DNSSEC_CACHE_CLEAN_ALL: call rcu error\n");
            h_list = &(hash_node->list);
            list_add(&(node->list), h_list);
            hash_node->size ++;

            list_add(&(node->clean_list), clean_h_list);
            g_dnssec_cache_clean_hash.size ++;
        } else {
            clean_num ++;
        }
    }

    return clean_num;
}