#ifndef _ADNS_DNSSEC_CACHE_H
#define _ADNS_DNSSEC_CACHE_H

#include "dname.h"
#include "list.h"
#include "rrset.h"
#include "adns_conf.h"
#include "consts.h"
#include "dnssec.h"
#include "murmurhash3.h"

/*
 * Structure of DNSSEC cache hash table header element
 */
typedef struct adns_dnssec_cache_hash {
    struct list_head list;
    uint32_t size;
} adns_dnssec_cache_hash;

/*
 * Structure of DNSSEC cache value
 */
typedef struct adns_dnssec_cache_value {
    adns_rrsig_rdata rrsig_rdata;               // rrsig_rdata exclude signer and signature
    char signer[ADNS_DOMAIN_MAX_LEN];           // signer(zone itself)
    uint8_t signer_len;                         // siger length
    uint8_t signature[DNS_SIG_ECDSA256SIZE];    // rrsig signature
} adns_dnssec_cache_value;

/*
 * Structure of DNSSEC cache node
 * cache node key: (rrset_owner, rrset_type, view_id)
 */
typedef struct adns_dnssec_cache_node {
    struct list_head list;
    struct list_head clean_list;
    uint8_t free_not_count;                  // if set, will not decrease counter when free node

    // hash key
    uint32_t hash;                           // DNSSEC cache hash
    uint8_t owner[ADNS_DOMAIN_MAX_LEN];      // owner of the rrset signed
    uint8_t owner_len;                       // owner length of the rrset signed
    uint16_t type;                           // rrset type
    adns_viewid_t view_id;                   // answer view id
    uint8_t *rdata;                          // rrdata
    uint16_t rdlen;                          // rrdata len

    // rrsig rdata
    adns_dnssec_cache_value value;           // cache value
} adns_dnssec_cache_node;

/*
 * Structure of DNSSEC cache db
 */
typedef struct adns_dnssec_cache_db {
    adns_dnssec_cache_hash dnssec_cache_tbl[ADNS_DNSSEC_CACHE_HASH_SIZE];   // DNSSEC cache hash table
    uint32_t dnssec_cache_count;                                            // DNSSEC cache count
} adns_dnssec_cache_db;


extern adns_dnssec_cache_db *g_dnssec_cache_db;
extern adns_dnssec_cache_db *g_dnssec_neg_cache_db;
#define MAX_CACHE_KEY_SIZE 4096


static inline uint32_t __attribute((always_inline))
gen_hash_key(uint8_t *owner, uint8_t owner_len, uint16_t type, adns_viewid_t view_id, uint8_t *rdata, uint16_t rdlen)
{
    uint32_t hash;
    uint8_t key_buf[MAX_CACHE_KEY_SIZE];
    uint8_t *p = key_buf;
    int key_len = owner_len - 1 + 4 + rdlen;

    // prepare key buf
    rte_memcpy(p, owner, owner_len - 1);
    p += (owner_len - 1);

    *((uint16_t *)p) = type;
    p += 2;

    *((uint16_t *)p) = view_id;
    p += 2;

    rte_memcpy(p, rdata, rdlen);
    p += rdlen;

    // hash
    hash = mm3_hash((const char *)key_buf, key_len);
    return hash;
}

/*
 * Init the dnssec cache db
 */
int adns_dnssec_cache_db_init(void);

/*
 * Get DNSSEC cache db count
 */
uint32_t adns_dnssec_cache_db_count(adns_dnssec_cache_db *dnssec_cache_db);


/*
 * DNSSEC positive Cache
 */

/*
 * Create a new adns_dnssec_cache_node
 */
adns_dnssec_cache_node * adns_new_dnssec_cache_node(uint8_t *owner,
                                                    uint8_t owner_len,
                                                    uint16_t type,
                                                    adns_viewid_t view_id,
                                                    uint8_t *rdata,
                                                    uint16_t rdlen,
                                                    adns_rrsig_rdata *rrsig_rdata,
                                                    uint8_t *signer,
                                                    uint8_t signer_len,
                                                    uint8_t *signature);

/*
 * Destroy a adns_dnssec_cache_node
 */
void adns_free_dnssec_cache_node(adns_dnssec_cache_node *node);

/*
 * Lookup DNSSEC cache
 */
adns_dnssec_cache_node *adns_dnssec_cache_hash_lookup(uint8_t *owner, uint8_t owner_len, uint16_t type, adns_viewid_t view_id, uint8_t *rdata, uint16_t rdlen, adns_ttl_t ttl_n);

/*
 * Add a adns_dnssec_cache_node
 */
int adns_dnssec_cache_add_hash(adns_dnssec_cache_node *node);

/*
 * Delete a adns_dnssec_cache_node
 */
int adns_dnssec_cache_del_hash(adns_dnssec_cache_node *node);

/*
 * Dump a adns_dnssec_cache_node
 */
int adns_dnssec_cache_dump_hash(int fd, adns_dnssec_cache_node *node);

/*
 * Replace a adns_dnssec_cache_node
 */
int adns_dnssec_cache_replace_hash(adns_dnssec_cache_node *new_node, adns_dnssec_cache_node *old_node);

/*
 * Clean DNSSEC cache bulk
 */
int adns_dnssec_cache_clean(uint32_t bulk_num);

/*
 * Clean DNSSEC cache all
 */
int adns_dnssec_cache_clean_all();

#endif
