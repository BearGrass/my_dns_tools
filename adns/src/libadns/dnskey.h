#ifndef _ADNS_DNSKEY_H_
#define _ADNS_DNSKEY_H_

#include <openssl/evp.h>
#include "consts.h"

#define DNS_DNSKEY_RDATA_LEN  (sizeof(adns_dnskey_rdata) + DNS_KEY_ECDSA256SIZE) /* ECDSAP256 dnskey rdata len */
#define DNS_DNSKEY_RR_LEN  (2 + ADNS_RR_HEADER_SIZE + DNS_DNSKEY_RDATA_LEN)      /* name pointer(2 bytes) + rr_header + rdata  ECDSAP256 dnskey rr wire len */
#define DNS_DNSSEC_KEY_ACTIVE_CNT_DEC(key) ((key)->active_ref_cnt --)
#define DNS_DNSSEC_KEY_ACTIVE_CNT_INC(key) ((key)->active_ref_cnt ++)

#define DNS_DNSKEY_TTL 3600      // default DNSKEY TTL is 3600, same as the DNSKEY rrsig from ADMS

// adns dnskey rdata structure
typedef struct adns_dnskey_rdata {
    uint16_t      flags;         // ZSK 256, KSK 257
    uint8_t       protocol;      // fix to 3
    uint8_t       algorithm;     // only support ECDSA-P256(13)
    uint8_t       pubkey[0];     // public key data
} __attribute__((packed)) adns_dnskey_rdata;

// adns dnssec key structure
typedef struct adns_dnssec_key {
    EVP_PKEY            *key;
    uint8_t             is_ksk;        // flag indicates if the key is ksk
    uint8_t             pubkey_data[DNS_KEY_ECDSA256SIZE]; // publib key data
    uint32_t            pubkey_data_len;                    // public key data length
    uint8_t             privkey_data[DNS_KEY_ECDSA256SIZE]; // private key data
    uint32_t            privkey_data_len;                   // private key data length
    uint16_t            key_tag;        // key tag (or key id), it is calculated by pubkey data
    EVP_MD_CTX          *evp_md_ctx[RTE_MAX_LCORE]; // should allocate EVP_MD_CTX per core
    uint32_t            active_ref_cnt; // reference count of the key as zone's active zsk 
} adns_dnssec_key;

/* Init zsk_p_table */
int adns_init_zsk_p_table(void);

/* Free zsk_p_table */
void adns_free_zsk_p_table(void);

/* Set ZSK in ZSK table, return the old dnssec key pointer at the key tag position */
adns_dnssec_key *adns_set_zsk(adns_dnssec_key *key);

/* Get ZSK by key tag */
adns_dnssec_key *adns_get_zsk_by_key_tag(uint16_t key_tag);

/* Clear ZSK by key tag */
void adns_clear_zsk_by_key_tag(uint16_t key_tag);

#endif
