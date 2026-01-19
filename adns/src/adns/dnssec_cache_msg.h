#ifndef _DNSSEC_CACHE_MSG_H_
#define _DNSSEC_CACHE_MSG_H_

#include "dnssec_cache.h"


typedef enum dnssec_cache_operation_type {
    DNSSEC_CACHE_INSERT = 1,  /* CACHE INSERT */
    DNSSEC_CACHE_DELETE,      /* CACHE DELETE */
    DNSSEC_CACHE_UPDATE,      /* CACHE UPDATE */
} dnssec_cache_operation_type;

typedef struct dnssec_cache_msg_ctx {
    // cache key
    uint8_t owner[ADNS_DOMAIN_MAX_LEN];    // rrset owner
    uint8_t owner_len;                     // rrset owner len 
    uint16_t type;                         // rrset type
    adns_viewid_t view_id;                 // DNSSEC positive cache: view id
    uint8_t rdata[MAX_CACHE_KEY_SIZE];     // rdata signed
    uint16_t rdlen;                        // rdata len

    // cache value
    adns_rrsig_rdata rrsig_rdata;              // rrsig rdata
    uint8_t signer[ADNS_DOMAIN_MAX_LEN];       // signer name(zone name)
    uint8_t signer_len;                        // signer len
    uint8_t signature[DNS_SIG_ECDSA256SIZE];   // signature
} dnssec_cache_msg_ctx;

typedef struct dnssec_cache_msg {
    dnssec_cache_operation_type op;         // cache operation type
    dnssec_cache_msg_ctx ctx;               // cache context
} dnssec_cache_msg;


int send_dnssec_cache_msg(uint32_t lcore,
                          dnssec_cache_operation_type op,
                          uint8_t *owner,
                          uint8_t owner_len,
                          uint16_t type,
                          adns_viewid_t id,
                          adns_rrsig_rdata *rrsig_rdata,
                          uint8_t *signer,
                          uint8_t signer_len,
                          uint8_t *signature,
                          uint8_t *rdata,
                          uint16_t rdlen);

uint32_t handle_dnssec_cache_msg();


int dnssec_cache_msg_init();
void dnssec_cache_msg_destroy();

#endif
