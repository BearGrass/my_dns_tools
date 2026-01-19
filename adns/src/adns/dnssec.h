#ifndef _ADNS_DNSSEC_H_
#define _ADNS_DNSSEC_H_

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "dname.h"
#include "list.h"
#include "node.h"
#include "rrset.h"
#include "consts.h"
#include "dns_pkt.h"
#include "dnskey.h"

#define DNSSEC_PUBKEY_B64_DECODE_MAX_LEN  512  /* DNSSEC BASE64 encoding content max length */

#define MAX_DNSKEY_NUM          3        /* max number of DNSKEY RR existing in DNS response: 1 KSK, 2 ZSK in ZSK rollover */

#define NSEC_NEXT_OWNER_NULL_LABEL  0x0100   /*  The next owner name is the QNAME with a leading label with a single null octet added 
                                                EX. the next owner of "a.example.com" is "\000.a.example.com"*/
#define DNS_NSEC_BITMAP_BUFFERSIZE (8192 + 512)  /* max bufsize for NSEC RR type bitmap  */

#define DNS_RRSIG_RDATA_MAX_LEN (sizeof(adns_rrsig_rdata) + ADNS_DNAME_MAXLEN)   /* RRSIG rdata max len */


// adns nsec type bitmap type
typedef enum adns_nsec_bitmap_type {
    ZONE_APEX   =  0,            // nsec bitmap for zone apex(must have: SOA, NS, NSEC, RRSIG)
    DELEGATION_POINT,            // nsec bitmap for delegation point(must have: NS, NSEC, RRSIG)
    NORMAL_DOMAIN,               // nsec bitmap for normal domain(must have: NSEC, RRSIG)
    NSEC_BITMAP_TYPE_NUM         // nsec bitmap must not have CNAME
} adns_nsec_bitmap_type;

static const struct id_name_map adns_nsec_bitmap_type_map[] = {
	{ZONE_APEX, "ZONE_APEX"},
	{DELEGATION_POINT, "DELEGATION_POINT"},
	{NORMAL_DOMAIN, "NORMAL_DOMAIN"},
};

static inline __attribute__((always_inline)) const char* adns_nsec_bitmap_type_2str(adns_nsec_bitmap_type bitmap_type)
{
    return adns_nsec_bitmap_type_map[bitmap_type].name;
}

// adns nsec type bitmap structure
typedef struct adns_nsec_bitmap {
    uint8_t       *data;         // compressed bit map data
    uint16_t       len;          // compressed bit map length
    uint16_t       type;         // missing type of compressed type bit map
                                 // if missing type is not supported by ADNS, then missing type is set to 0
}__attribute__((packed)) adns_nsec_bitmap;

// adns nsec type bitmap list structure
typedef struct adns_nsec_bitmap_list {
    adns_nsec_bitmap maps[NSEC_BITMAP_TYPE_NUM]; //bitmaps(apex, delegation, normal domain)
} adns_nsec_bitmap_list;

/*
 * NSEC cache info
 */
typedef struct adns_nsec_cache_info {
    adns_nsec_bitmap        *bitmap;      // bitmap pointer, never change
    uint16_t                qtype;        // query type
    adns_nsec_bitmap_type   bitmap_type;  // bitmap type
} adns_nsec_cache_info;

// structure used for sign update data
typedef struct adns_rr_index {
    uint8_t *pos;                // point to the start position of rdata
    uint16_t len;                // rdata length
} __attribute__((packed)) adns_rr_index;


extern adns_dnssec_key **g_dnssec_ksk;

/* register rte mem allocation functions for openssl, so that openssl can use the huge page memory */
int adns_register_openssl_mem_functions(void);

// DNSSEC key
/* Init the dnssec key for master process */
int adns_init_dnssec_key(void);

EVP_PKEY *adns_openssl_new_key(uint8_t *pub_key_data, uint16_t pub_key_len, uint8_t *priv_key_data, uint16_t priv_key_len);

/* Get a dnssec key */
adns_dnssec_key *adns_get_dnssec_key(int ksk, uint8_t *pub_key_data, uint16_t pub_key_len, uint8_t *priv_key_data, uint16_t priv_key_len);

/* Put a dnssec key */
void adns_put_dnssec_key(adns_dnssec_key *key);

// NSEC bitmap
/* init the nsec bitmap */
int adns_init_nsec_bit_map(void);

/* destroy the nsec bitmap table */
void adns_destroy_nsec_bitmap(adns_nsec_bitmap_list *bm_table);

/* Get corresponding nsec bitmap */
adns_nsec_bitmap* get_nsec_bitmap(adns_type_t type, adns_nsec_bitmap_type bitmap_type);

/* sign the rrset 
   ret < 0: failure 
   ret > 0: dnssec content length
   */
int adns_dnssec_sign_rrset(struct adns_packet *query,
                            uint8_t *pos,
                            adns_rr_index *index_list,
                            uint16_t index_num,
                            const struct adns_zone *zone,
                            uint8_t *rrset_owner,
                            uint8_t rrset_owner_len,
                            adns_type_t type,
                            adns_viewid_t id, // view_id or bitmap_type
                            adns_ttl_t ttl,
                            const adns_dname_t *query_name_cursor);
#endif
