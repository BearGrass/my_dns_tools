#include <strings.h>
#include <stdlib.h>
#include <time.h>

#include "rte_malloc.h"
#include "rte_log.h"
#include "rte_lcore.h"

#include "dnssec.h"
#include "dnssec_cache_msg.h"
#include "adns.h"
#include "adns_log.h"
#include "descriptor.h"
#include "adns_stats.h"
#include "qps_limit.h"
#include "common_value.h"


#include "zone.h"

#define SIGNATURE_TIME_BIAS 3600 * 25   // RRSIG signature time bias, 25 hours in seconds
#define DNSSEC_CACHE_EXPIRE_BIAS 10     // If dnssec cache will expire in 10 secs, delete it

// global DNSSEC KSK
adns_dnssec_key **g_dnssec_ksk;

// globle NSEC bitmap list table
adns_nsec_bitmap_list *g_nsec_bm_table;

// DNSSEC key mempool
struct rte_mempool *g_dnssec_key_pools[ADNS_MAX_SOCKETS] = { NULL };

extern uint16_t g_io_lcore_id_start;
extern int * g_adns_pkt_drop_counter;


static int opensslecdsa_createctx(EVP_MD_CTX **p_evp_md_ctx)
{
    if (p_evp_md_ctx == NULL) {
        return -1;
    }

    *p_evp_md_ctx = NULL;

    EVP_MD_CTX *evp_md_ctx;
	const EVP_MD *type = NULL;

    evp_md_ctx = EVP_MD_CTX_create();
	if (evp_md_ctx == NULL) {
        return -1;
    }

    /* Only support ECDSA-P256 */
    type = EVP_sha256();

    if (!EVP_DigestInit_ex(evp_md_ctx, type, NULL)) {
		EVP_MD_CTX_destroy(evp_md_ctx);
        return -1;
    }

    *p_evp_md_ctx = evp_md_ctx;
    return 0;
}

static void opensslecdsa_destroyctx(EVP_MD_CTX **p_evp_md_ctx)
{
    if (p_evp_md_ctx == NULL) {
        return;
    }

    EVP_MD_CTX *evp_md_ctx = *p_evp_md_ctx;
    if (evp_md_ctx == NULL) {
        return;
    }

    EVP_MD_CTX_destroy(evp_md_ctx);
    *p_evp_md_ctx = NULL;
}

static int opensslecdsa_adddata(EVP_MD_CTX *evp_md_ctx, unsigned char *data, uint32_t len)
{
    if (evp_md_ctx == NULL) {
        return -1;
    }

    if (!EVP_DigestUpdate(evp_md_ctx, data, len)) {
        return -1;
    }

    return 0;
}

static int
BN_bn2bin_fixed(const BIGNUM *bn, unsigned char *buf, int size) {
    int bytes = size - BN_num_bytes(bn);

    while (bytes-- > 0)
        *buf++ = 0;
    BN_bn2bin(bn, buf);
    return (size);
}


static int opensslecdsa_sign(EVP_MD_CTX *evp_md_ctx, EVP_PKEY *pkey, uint8_t *pos)
{
    ECDSA_SIG *ecdsasig;
    EC_KEY *eckey = NULL;
    unsigned int dgstlen;
	unsigned char digest[EVP_MAX_MD_SIZE];
	const BIGNUM *r, *s;

    if (evp_md_ctx == NULL || pkey == NULL) {
        goto err;
    }

    eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (eckey == NULL) {
        goto err;
    }

    if (!EVP_DigestFinal(evp_md_ctx, digest, &dgstlen)) {
        goto err;
    }

    ecdsasig = ECDSA_do_sign(digest, dgstlen, eckey);
    if (ecdsasig == NULL) {
        goto err;
    }


    ECDSA_SIG_get0(ecdsasig, &r, &s);
    BN_bn2bin_fixed(r, pos, DNS_SIG_ECDSA256SIZE / 2);
    pos += DNS_SIG_ECDSA256SIZE / 2;
    BN_bn2bin_fixed(s, pos, DNS_SIG_ECDSA256SIZE / 2);

    ECDSA_SIG_free(ecdsasig);


    return 0;

err:
    if (eckey != NULL) {
        EC_KEY_free(eckey);
    }
    return -1;
}

static int opensslecdsa_generate_key(EVP_PKEY **p_pkey, uint8_t *key_data, uint16_t key_len)
{
    EVP_PKEY *pkey;
    EC_KEY *eckey = NULL;
    int group_nid = NID_X9_62_prime256v1;
    

    if (p_pkey == NULL) {
        return -1;
    }

    eckey = EC_KEY_new_by_curve_name(group_nid);
    if (eckey == NULL) {
        return -1;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        goto err;
    }

    /* pass no key data, generate the key */
    if (key_data == NULL && key_len == 0) {
        if (EC_KEY_generate_key(eckey) != 1) {
            EVP_PKEY_free(pkey);
            goto err;
        }
    } else { /* if key data is passed, use it */
        uint8_t buf[DNS_KEY_ECDSA256SIZE + 1];
        uint16_t len = DNS_KEY_ECDSA256SIZE;
        const unsigned char *cp;

        buf[0] = POINT_CONVERSION_UNCOMPRESSED;
        memcpy(buf + 1, key_data, key_len);
        cp = buf;

        if (o2i_ECPublicKey(&eckey, (const unsigned char **) &cp, (long) len + 1) == NULL) {
            EVP_PKEY_free(pkey);
            goto err;
        }

        if (EC_KEY_check_key(eckey) != 1) {
            EVP_PKEY_free(pkey);
            goto err;
        }
    }

    if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
        EVP_PKEY_free(pkey);
        goto err;
    }

    *p_pkey = pkey;
    return 0;

err:
    if (eckey != NULL) {
        EC_KEY_free(eckey);
    }
    return -1;
}

static void opensslecdsa_destroy_key(EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        return;
    }

    EVP_PKEY_free(pkey);
}

static int opensslecdsa_todns(EVP_PKEY *pkey, uint8_t *pos)
{
    EC_KEY *eckey = NULL;
    int len;
    unsigned char *c;
    unsigned char buf[DNS_KEY_ECDSA256SIZE + 1];

    c = buf;

    if (pkey == NULL) {
        return -1;
    }

    eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (eckey == NULL) {
        return -1;
    }

    len = i2o_ECPublicKey(eckey, NULL);
    len --;


    if (!i2o_ECPublicKey(eckey, &c)) {
        goto err;
    }

    memcpy(pos, buf + 1, len);
    return len;


err:
    if (eckey != NULL) {
        EC_KEY_free(eckey);
    }
    return -1;
}

static uint16_t compute_key_id(adns_dnssec_key *key)
{
    uint32_t ac;
    int size;
    const unsigned char *p;
    uint8_t buf[DNS_DNSKEY_RDATA_LEN];
    adns_dnskey_rdata *dnskey_rdata = (adns_dnskey_rdata *)buf;

    if (key->is_ksk) {
        dnskey_rdata->flags = adns_htons(DNS_KEY_SIGNING_KEY_FLAGS);
    } else {
        dnskey_rdata->flags = adns_htons(DNS_ZONE_SIGNING_KEY_FLAGS);
    }
    dnskey_rdata->protocol = DNS_DNSKEY_PROTOCOL;
    dnskey_rdata->algorithm = ECDSA_P256_ALGO;
    memcpy(dnskey_rdata->pubkey, key->pubkey_data, key->pubkey_data_len);

    size = key->pubkey_data_len + sizeof(adns_dnskey_rdata);
    p = buf;

    for (ac = 0; size > 1; size -= 2, p += 2) {
        ac += ((*p) << 8) + *(p + 1);
    }

    if (size > 0) {
        ac += ((*p) << 8);
    }
    ac += (ac >> 16) & 0xffff;

	return ((uint16_t)(ac & 0xffff));
}

static uint16_t
nsec_compressbitmap(uint8_t *map, uint8_t *raw, adns_type_t max_type)
{
	uint8_t *start = map;
	uint16_t window;
	int octet;

	if (raw == NULL)
		return (0);

	for (window = 0; window < 256; window++) {
		if (window * 256 > max_type)
			break;
		for (octet = 31; octet >= 0; octet--)
			if (*(raw + octet) != 0)
				break;
		if (octet < 0) {
			raw += 32;
			continue;
		}
		*map++ = window;
		*map++ = octet + 1;
		
		rte_memcpy(map, raw, octet + 1);
		map += octet + 1;
		raw += 32;
	}
	return (uint16_t)(map - start);
}

static void
nsec_setbit(uint8_t *array, adns_type_t type, uint8_t bit) 
{
    uint16_t shift, mask;

    shift = 7 - (type % 8);
    mask = 1 << shift;

    if (bit != 0) {
        array[type / 8] |= mask;
    } else {
        array[type / 8] &= (~mask & 0xFF);
    }
}

static adns_type_t
build_nsec_bitmap(uint8_t *buf, adns_type_t missing_type, adns_nsec_bitmap_type bitmap_type)
{
    int i;
    uint8_t *bm;
    adns_type_t max_type = ADNS_RRTYPE_NSEC;

    bm = buf + 512;
    for (i = 0; i < ARRAY_SIZE(type_maps); i++) {
        adns_type_t type = (adns_type_t)type_maps[i].id;
        // always set NSEC and RRSIG
        if (type == ADNS_RRTYPE_NSEC || type == ADNS_RRTYPE_RRSIG) {
            nsec_setbit(bm, type, 1);
            if (type > max_type) {
                max_type = type;
            }
            continue;
        }
        // must not set CNAME
        if (type == ADNS_RRTYPE_CNAME) {
            continue;
        }
        
        if (bitmap_type == ZONE_APEX) { //always set SOA, NS, DNSKEY for apex
            if (type == ADNS_RRTYPE_SOA || type == ADNS_RRTYPE_NS || type == ADNS_RRTYPE_DNSKEY) {
                nsec_setbit(bm, type, 1);
                if (type > max_type) {
                    max_type = type;
                }
                continue;
            }
        } else if (bitmap_type == DELEGATION_POINT) { // always set NS for delegation point, only set NS, NSEC, RRSIG for delegation
            if (type == ADNS_RRTYPE_NS) {
                nsec_setbit(bm, type, 1);
                if (type > max_type) {
                    max_type = type;
                }
                continue;
            } else {
                continue;
            }
        } else { // NS, SOA, DNSKEY must not set for normal domain
            if (type == ADNS_RRTYPE_NS || type == ADNS_RRTYPE_SOA || type == ADNS_RRTYPE_DNSKEY) {
                continue;
            }
        }
        if (missing_type == type) {
            continue;
        } else {
            nsec_setbit(bm, type, 1);
            if (type > max_type) {
                max_type = type;
            }
        }
    }
    return max_type;
}

int adns_init_nsec_bit_map(void)
{
    uint16_t bm_cnt;
    int i, j;
    adns_nsec_bitmap_list *p_bm_list;
    adns_nsec_bitmap *p_bm;
    uint8_t bit_map[DNS_NSEC_BITMAP_BUFFERSIZE];
    adns_type_t max_type;
    uint16_t bit_map_len;

    bm_cnt = ARRAY_SIZE(type_maps);
    // the NSEC type bit map for ADNS non-support type is saved in the additional last element of bm_table
    // so the size of g_nsec_bm_table is bm_cnt + 1
    g_nsec_bm_table = (adns_nsec_bitmap_list *)rte_zmalloc(NULL, (bm_cnt + 1) * sizeof(adns_nsec_bitmap_list), 0);
    if (g_nsec_bm_table == NULL) {
        return -1;
    }

    // build missing type bit map for all supporting type
    for (i = 0; i < bm_cnt; i ++ ) {
        adns_type_t missing_type = (adns_type_t)type_maps[i].id;
        p_bm_list = &(g_nsec_bm_table[i]);
        for (j = 0; j < NSEC_BITMAP_TYPE_NUM; j ++) {
            memset(bit_map, 0, DNS_NSEC_BITMAP_BUFFERSIZE);
            p_bm = &(p_bm_list->maps[j]);
            max_type = build_nsec_bitmap(bit_map, missing_type, j);
            bit_map_len = nsec_compressbitmap(bit_map, bit_map + 512, max_type);
            p_bm->type = missing_type;
            p_bm->len = bit_map_len;
            p_bm->data = (uint8_t *)rte_zmalloc(NULL, bit_map_len, 0);
            if (p_bm->data == NULL) {
                goto err;
            }
            rte_memcpy(p_bm->data, bit_map, bit_map_len);
        }
    }
    // build type bit map for non-support type
    p_bm_list = &(g_nsec_bm_table[bm_cnt]);
    for (j = 0; j < NSEC_BITMAP_TYPE_NUM; j ++) {
        memset(bit_map, 0, DNS_NSEC_BITMAP_BUFFERSIZE);
        p_bm = &(p_bm_list->maps[j]);
        max_type = build_nsec_bitmap(bit_map, 0, j);
        bit_map_len = nsec_compressbitmap(bit_map, bit_map + 512, max_type);
        p_bm->type = 0;
        p_bm->len = bit_map_len;
        p_bm->data = (uint8_t *)rte_zmalloc(NULL, bit_map_len, 0);
        if (p_bm->data == NULL) {
            goto err;
        }
        rte_memcpy(p_bm->data, bit_map, bit_map_len);
    }

    fprintf(stdout, "[%s]: Finish to init nsec_bitmap_table\n", __FUNCTION__);
    return 0;

err:
    adns_destroy_nsec_bitmap(g_nsec_bm_table);
    g_nsec_bm_table = NULL;
    return -1;
}

void adns_destroy_nsec_bitmap(adns_nsec_bitmap_list *bm_table) {
    uint16_t bm_cnt;
    int i, j;
    adns_nsec_bitmap *p_bm;
    adns_nsec_bitmap_list *p_bm_list;

    if (bm_table == NULL) {
        return;
    }

    bm_cnt = ARRAY_SIZE(type_maps);

    for (i = 0; i < bm_cnt; i ++) {
        for (j = 0; j < NSEC_BITMAP_TYPE_NUM; j ++) {
            p_bm_list = &(bm_table[i]);
            p_bm = &(p_bm_list->maps[j]);
            if (p_bm->data != NULL) {
                rte_free(p_bm->data);
            }
            p_bm->len = 0;
        }
    }
    rte_free(bm_table);
}

adns_nsec_bitmap* get_nsec_bitmap(adns_type_t type, adns_nsec_bitmap_type bitmap_type)
{
    uint16_t bm_cnt;
    int i;
    adns_nsec_bitmap *p_bm;
    adns_nsec_bitmap_list *p_bm_list;

    bm_cnt = ARRAY_SIZE(type_maps);

    for (i = 0; i < bm_cnt + 1; i ++) {
        p_bm_list = &(g_nsec_bm_table[i]);
        p_bm = &(p_bm_list->maps[bitmap_type]);
        if (p_bm->type == type) {
            return p_bm;
        }
    }
    p_bm_list = &(g_nsec_bm_table[bm_cnt]);
    p_bm = &(p_bm_list->maps[bitmap_type]);
    return p_bm;
}

static int _adns_new_dnssec_key(adns_dnssec_key *key, int ksk, uint8_t *key_data, uint16_t key_len)
{
    int len, i;

    if (key == NULL) {
        return -1;
    }
    key->is_ksk = ksk;

    for (i = 0; i < app.lcore_io_num; i ++) {
        if (opensslecdsa_createctx(&(key->evp_md_ctx[i])) < 0) {
            goto err;
        }
    }

    if (opensslecdsa_generate_key(&(key->key), key_data, key_len) < 0) {
        goto err;
    }

    /* prepare pub key data */
    len = opensslecdsa_todns(key->key, key->pubkey_data);
    if (len < 0) {
        goto err;
    }
    key->pubkey_data_len = (uint32_t) len;
    /* calculate key tag */
    key->key_tag = compute_key_id(key);

    return 0;

err:
    return -1;
}

static int ecdsa_check(EC_KEY *eckey, adns_dnssec_key *pubkey)
{
    int ret = -1;
    EVP_PKEY *pkey;
    EC_KEY *pubeckey = NULL;
    const EC_POINT *_pubkey;

    if (pubkey == NULL) {
        return 0;
    }

    pkey = pubkey->key;
    if (pkey == NULL) {
        return 0;
    }

    pubeckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (pubeckey == NULL) {
        return 0;
    }

    _pubkey = EC_KEY_get0_public_key(pubeckey);
    if (pubkey == NULL) {
        ret = 0;
        goto err;
    }

    if (EC_KEY_set_public_key(eckey, _pubkey) != 1) {
        ret = 0;
        goto err;
    }

    if (EC_KEY_check_key(eckey) == 1) {
        ret = 0;
        goto err;
    }

err:
    if (pubeckey != NULL)
        EC_KEY_free(pubeckey);
    return (ret);
}

static int _adns_add_privkey(uint8_t *key_data, uint16_t key_len, adns_dnssec_key *pubkey)
{
    int ret, group_nid;
    EVP_PKEY *pkey, *old_pkey;
    EC_KEY *eckey = NULL;
    BIGNUM *privkey = NULL;

    group_nid = NID_X9_62_prime256v1;

    eckey = EC_KEY_new_by_curve_name(group_nid);
    if (eckey == NULL) {
        ret = -1;
        goto err;
    }

    privkey = BN_bin2bn(key_data, key_len, NULL);
    if (privkey == NULL) {
        ret = -1;
        goto err;
    }

    if (!EC_KEY_set_private_key(eckey, privkey)) {
        ret = -1;
        goto err;
    }

    if (ecdsa_check(eckey, pubkey) != 0) {
        ret = -1;
        goto err;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        ret = -1;
        goto err;
    }

    if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
        EVP_PKEY_free(pkey);
        ret = -1;
        goto err;
    }

    old_pkey = pubkey->key;
    pubkey->key = pkey;

    opensslecdsa_destroy_key(old_pkey);

    // save private key data
    memcpy(pubkey->privkey_data, key_data, key_len);
    pubkey->privkey_data_len = key_len;

    ret = 0;
err:
    if (privkey != NULL) {
        BN_clear_free(privkey);
    }
    if (eckey != NULL) {
        EC_KEY_free(eckey);
    }
    return ret;
}

static void *m_adns_calloc(size_t size, const char *file, int line)
{
    (void)(file); (void)(line);
    return rte_zmalloc(NULL, size, 0);
}

static void *m_adns_realloc(void *p, size_t size, const char *file, int line)
{
    (void)(file); (void)(line);
    return rte_realloc(p, size, 0);
}

void m_adns_free(void *p, const char *file, int line)
{
    (void)(file); (void)(line);
    rte_free(p);
}

int adns_register_openssl_mem_functions(void)
{
    if (CRYPTO_set_mem_functions(m_adns_calloc, m_adns_realloc, m_adns_free) == 0) {
        fprintf(stdout, "[%s]: Fail to register new mem functions for openssl\n", __FUNCTION__);
        return -1;
    }

    return 0;
}

int adns_init_dnssec_key(void)
{
    adns_socket_id_t socket_id;
    char name[64];

    // init zsk pointer table
    if (adns_init_zsk_p_table() < 0) {
        fprintf(stdout, "[%s]: Fail to init ZSK pointer table\n", __FUNCTION__);
        return -1;
    }

    // create dnssec key mempool
    for (socket_id = 0; socket_id < ADNS_MAX_SOCKETS; socket_id ++) {
        snprintf(name, sizeof(name), "g_dnssec_key_pools_%d", socket_id);
        // each dnssec enabled zone could have 2 ZSKs in maximum, plus the global KSK, so the mempool size is 2*g_dnssec_zone_max_num + 1
        g_dnssec_key_pools[socket_id] = rte_mempool_create(name, (g_dnssec_zone_max_num << 1) + 1, 
                                                        sizeof(adns_dnssec_key), 32, 0, NULL, NULL, NULL, NULL, socket_id, 0);
        if (g_dnssec_key_pools[socket_id] == NULL) {
            adns_free_zsk_p_table();
            fprintf(stdout, "[%s]: Fail to alloc g_dnssec_key_pools %s\n", __FUNCTION__, name);
            return -1;
        }

        fprintf(stdout, "[%s]: Finish to alloc g_dnssec_key_pools %s\n", __FUNCTION__, name);
    }

    return 0;
}

adns_dnssec_key *adns_get_dnssec_key(int ksk, uint8_t *pub_key_data, uint16_t pub_key_len, uint8_t *priv_key_data, uint16_t priv_key_len)
{
    void *data;
    adns_dnssec_key *key = NULL;
    adns_socket_id_t socket_id;
    
    socket_id = rte_socket_id();
    if (socket_id >= ADNS_MAX_SOCKETS){
        return NULL;
    }

    // must have pub key data
    if (pub_key_data == NULL || pub_key_len == 0) {
        return NULL;
    }

    // KSK must not have private key data
    if (ksk == 1 && (priv_key_data != NULL || priv_key_len != 0)) {
        return NULL;
    }

    // Get a dnssec key from mempool
    if (rte_mempool_get(g_dnssec_key_pools[socket_id], &data) < 0) {
        log_server_error(rte_lcore_id(), "[%s]: rte_mempool_get failed, pool name = %s, socket id = %d\n", __FUNCTION__, g_dnssec_key_pools[socket_id]->name, socket_id);
        return NULL;
    }
    key = (adns_dnssec_key *)data;
    memset(key, 0, sizeof(adns_dnssec_key));

    // new public key
    if (_adns_new_dnssec_key(key, ksk, pub_key_data, pub_key_len) < 0) {
        adns_put_dnssec_key(key);
        return NULL;
    }

    // add private key if key is ZSK
    if (ksk == 0) {
        if (_adns_add_privkey(priv_key_data, priv_key_len, key) < 0) {
            log_server_error(rte_lcore_id(), "[%s]: pub/priv key pair mismatch\n", __FUNCTION__);
            adns_put_dnssec_key(key);
            return NULL;
        }
    }

    return key;
}

void adns_put_dnssec_key(adns_dnssec_key *key)
{
    int i;
    adns_socket_id_t socket_id;
    socket_id = rte_socket_id();
    if (socket_id >= ADNS_MAX_SOCKETS){
        return;
    }
    if (key != NULL) {
        opensslecdsa_destroy_key(key->key);
        for (i = 0; i < app.lcore_io_num; i ++) {
            opensslecdsa_destroyctx(&(key->evp_md_ctx[i]));
        }

        rte_mempool_put(g_dnssec_key_pools[socket_id], (void *)key);
    }
}

EVP_PKEY *adns_openssl_new_key(uint8_t *pub_key_data, uint16_t pub_key_len, uint8_t *priv_key_data, uint16_t priv_key_len)
{
    int group_nid;
    EVP_PKEY *pkey;
    EC_KEY *eckey = NULL;
    BIGNUM *privkey = NULL;

    group_nid = NID_X9_62_prime256v1;

    eckey = EC_KEY_new_by_curve_name(group_nid);
    if (eckey == NULL) {
        return NULL;
    }

    privkey = BN_bin2bn(priv_key_data, priv_key_len, NULL);
    if (privkey == NULL) {
        EC_KEY_free(eckey);
        return NULL;
    }

    if (!EC_KEY_set_private_key(eckey, privkey)) {
        EC_KEY_free(eckey);
        BN_clear_free(privkey);
        return NULL;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        EC_KEY_free(eckey);
        BN_clear_free(privkey);
        return NULL;
    }

    if (!EVP_PKEY_set1_EC_KEY(pkey, eckey)) {
        EC_KEY_free(eckey);
        BN_clear_free(privkey);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}

/* rdata compare callback, use adns_rr_index for rdata compare */
static inline int __attribute((always_inline))
rdata_compare(const void *rdata1, const void *rdata2)
{
    adns_rr_index *index1;
    adns_rr_index *index2;
    int result;
    uint16_t cmp_len;

    index1 = (adns_rr_index *)rdata1;
    index2 = (adns_rr_index *)rdata2;

    cmp_len = (index1->len > index2->len)? index2->len : index1->len;
    /* skip type + class + ttl, since they are same within a rrset */
    /* NOTE: ignore case since all domain names in rdata are canonical */
    result = memcmp(index1->pos + ADNS_RR_HEADER_SIZE, index2->pos + ADNS_RR_HEADER_SIZE, cmp_len - ADNS_RR_HEADER_SIZE);
    if (likely(result != 0)) {
        return result;
    } else {
        if (unlikely(index1->len == index2->len)) {
            return 0;
        } else {
            return (index1->len > index2->len)? 1 : -1;
        }
    }
}

static inline int
dnssec_qps_ctl(struct adns_packet *query, struct adns_zone *zone)
{
    uint8_t print = 0;

    // source IP qos
    if (!dnssec_ip_pass(query->client_ip, g_dnssec_ip_qps_quota, &print)) {
        if (unlikely(print == 1)) {
            log_answer_custom(exceed_qps_fmt, fill_exceed_qps_log_data(EXCEED_DNSSEC_QPS_SRC_IP, query, g_dnssec_ip_qps_quota));
        }
        adns_counter_increase(g_adns_pkt_drop_counter[DNSSEC_OVER_QUOTA]);
        return ADNS_PKT_DROP;
    }

    // global qos
    if (!dnssec_pass(g_dnssec_qps_quota, &print)) {
        if (unlikely(print == 1)) {
            log_answer_custom(exceed_qps_fmt, fill_exceed_qps_log_data(EXCEED_DNSSEC_QPS_GLOBAL, query, g_dnssec_qps_quota));
        }
        adns_counter_increase(g_adns_pkt_drop_counter[DNSSEC_OVER_QUOTA]);
        return ADNS_PKT_DROP;
    }

#if 0
    // dnssec enabled zone qos
    if (!dnssec_zone_pass(zone->name, zone->name_len, g_dnssec_zone_qps_quota, &print)) {
        if (unlikely(print == 1)) {
            log_answer_custom(exceed_qps_fmt, fill_exceed_qps_log_data(EXCEED_DNSSEC_QPS_ZONE, query, g_dnssec_zone_qps_quota));
        }
        adns_counter_increase(g_adns_pkt_drop_counter[DNSSEC_OVER_QUOTA]);
        return ADNS_PKT_DROP;
    }
#endif

    return ADNS_PKT_ACCEPT;
}

// DNSSEC online signing
static int _dnssec_sign_rrset_online(struct adns_packet *query,
                                     uint8_t *pos,
                                     adns_rr_index *index_list,
                                     uint16_t index_num,
                                     const struct adns_zone *zone,
                                     uint8_t *rrset_owner_name,
                                     uint8_t rrset_owner_name_len,
                                     adns_type_t type,
                                     adns_viewid_t id,
                                     adns_ttl_t ttl,
                                     uint32_t timestampt,
                                     EVP_MD_CTX *evp_md_ctx,
                                     uint16_t key_tag,
                                     EVP_PKEY *key,
                                     dnssec_cache_operation_type op,
                                     uint8_t *rdata,
                                     uint16_t rdlen)
{
    uint8_t tmp[DNS_RRSIG_RDATA_MAX_LEN];
    adns_rrsig_rdata *rrsig = NULL;
    int label_cnt = 0, len = 0;
    int i;

    // Check DNSSEC QOS
    if (dnssec_qps_ctl(query, zone) == ADNS_PKT_DROP) {
        return -1;
    }

    // prepare RRSIG rdata
    rrsig = (adns_rrsig_rdata *)tmp;
    rrsig->covered = adns_htons(type);
    rrsig->algorithm = ECDSA_P256_ALGO;
    //TODO: consider save node->name label count in the first place
    label_cnt = adns_dname_labels(rrset_owner_name);
    rrsig->labels = label_cnt;
    rrsig->original_ttl = adns_htonl(ttl);
    rrsig->time_expire = adns_htonl(timestampt + SIGNATURE_TIME_BIAS);
    rrsig->time_signed = adns_htonl(timestampt - SIGNATURE_TIME_BIAS);
    rrsig->key_id = adns_htons(key_tag);
    // signer is zone itself
    rte_memcpy(rrsig->signer, zone->name, zone->name_len);

    //update digest
    /* RRsig rdata exclude signature */
    if (unlikely(opensslecdsa_adddata(evp_md_ctx, tmp, sizeof(adns_rrsig_rdata) + zone->name_len) < 0)) {
        log_server_error(rte_lcore_id(), "DNSSEC_SIGN_ONLINE: openssl ecdsa add data error\n");
        return -1;
    }

    // update digest each RR
    for (i = 0; i < index_num; i ++) {
        //update RR owner
        if (unlikely(opensslecdsa_adddata(evp_md_ctx, rrset_owner_name, rrset_owner_name_len) < 0)) {
            log_server_error(rte_lcore_id(), "DNSSEC_SIGN_ONLINE: openssl ecdsa add data error\n");
            return -1;
        }

        //update RR rdata
        if (unlikely(opensslecdsa_adddata(evp_md_ctx, index_list[i].pos, index_list[i].len) < 0)) {
            log_server_error(rte_lcore_id(), "DNSSEC_SIGN_ONLINE: openssl ecdsa add data error\n");
            return -1;
        }
    }

    //adns_rrsig_rdata *rrsig;
    rrsig = (adns_rrsig_rdata *)pos;
    rrsig->covered = adns_htons(type);
    rrsig->algorithm = ECDSA_P256_ALGO;
    rrsig->labels = label_cnt;
    rrsig->original_ttl = adns_htonl(ttl);
    rrsig->time_expire = adns_htonl(timestampt + SIGNATURE_TIME_BIAS);
    rrsig->time_signed = adns_htonl(timestampt - SIGNATURE_TIME_BIAS);
    rrsig->key_id = adns_htons(key_tag);
    memcpy(rrsig->signer, zone->name, zone->name_len);
    pos += sizeof(adns_rrsig_rdata) + zone->name_len;

    if (unlikely(opensslecdsa_sign(evp_md_ctx, key, pos) < 0)) {
        log_server_error(rte_lcore_id(), "DNSSEC_SIGN_ONLINE: openssl ecdsa sign error\n");
        return -1;
    }
    len += DNS_SIG_ECDSA256SIZE + sizeof(adns_rrsig_rdata) + zone->name_len + ADNS_RR_HEADER_SIZE;

    // send dnssec cache msg: insert dnssec cache or update dnssec cache when cache is about or already expired
    if (likely(*g_p_dnnssec_cache_switch == 1)) {
        /*
        if (cache_type == DNSSEC_RATIO_CACHE && index_num == 1) {
            rdata = index_list[0].pos + ADNS_RR_HEADER_SIZE;
            rdlen = index_list[0].len - ADNS_RR_HEADER_SIZE;
        }
        */
        if (send_dnssec_cache_msg(rte_lcore_id(),
                                  op,
                                  rrset_owner_name,
                                  rrset_owner_name_len,
                                  type,
                                  id,
                                  rrsig,
                                  zone->name,
                                  zone->name_len,
                                  pos,  /* signature */
                                  rdata,
                                  rdlen) < 0) {
            log_server_error(rte_lcore_id(), "DNSSEC_SIGN_ONLINE: sending DNSSEC_CACHE_INSERT msg error\n");
        }
    }

    // sign rrset succeed, increment dnssec_ans count
    STATS_INC(dnssec_ans);
    return len;
}

// DNSSEC rrsig from cache node
static int _dnssec_rrsig_from_cache_node_value(uint8_t *pos, adns_dnssec_cache_value *value, uint32_t timestampt, uint16_t key_tag)
{
    adns_rrsig_rdata *rrsig_rdata = NULL;
    int len = ADNS_RR_HEADER_SIZE;
    uint32_t tm_cache_h;

    // TODO: precheck DNSSEC cache node

    // fill rrsig rdata exclude signer
    rrsig_rdata = &(value->rrsig_rdata);

    // check if cache node is expired or will be expired in DNSSEC_CACHE_EXPIRE_BIAS, compare host order timestampt
    tm_cache_h = adns_ntohl(rrsig_rdata->time_expire);
    if ( (timestampt > tm_cache_h) ||
         (tm_cache_h - timestampt < DNSSEC_CACHE_EXPIRE_BIAS)) {
        STATS_INC(dnssec_cache_expire);
        return -1;
    }

    // check if key tag is matching, if key tag is changed, indicating a key rollover
    // should expire the cache
    if (rrsig_rdata->key_id != adns_htons(key_tag)) {
        STATS_INC(dnssec_cache_expire);
        return -1;
    }

    rte_memcpy(pos, rrsig_rdata, sizeof(adns_rrsig_rdata));
    pos += sizeof(adns_rrsig_rdata);
    len += sizeof(adns_rrsig_rdata);

    // fill rrsig signer
    rte_memcpy(pos, value->signer, value->signer_len);
    pos += value->signer_len;
    len += value->signer_len;

    // fill signature
    rte_memcpy(pos, value->signature, DNS_SIG_ECDSA256SIZE);
    pos += DNS_SIG_ECDSA256SIZE;
    len += DNS_SIG_ECDSA256SIZE;

    // increment DNSSEC cache hit count
    STATS_INC(dnssec_cache_hit);

    return len;
}

int adns_dnssec_sign_rrset(struct adns_packet *query,
                            uint8_t *data_pos,
                            adns_rr_index *index_list,
                            uint16_t index_num,
                            const struct adns_zone *zone,
                            uint8_t *rrset_owner_name,
                            uint8_t rrset_owner_name_len,
                            adns_type_t type,
                            adns_viewid_t id,
                            adns_ttl_t ttl,
                            const adns_dname_t *query_name_cursor)
{
    int ret, len = 0;
    uint8_t *pos;
    adns_dnssec_key *zsk;
    EVP_MD_CTX *evp_md_ctx = NULL;
    EVP_PKEY *key = NULL;
    // NOTE: io core must be in serial, otherwise io_core_id may be incorrect
    int l_core_id = rte_lcore_id() - g_io_lcore_id_start;
    // timestampt
    time_t t = 0;
    struct timeval tv_res = {0};
    uint32_t tm;
    
    adns_zsk_ctr_t *zsk_ctr;
    adns_dnssec_cache_node *cache_node = NULL;
    //adns_dnssec_neg_cache_node *neg_cache_node = NULL;
    adns_dnssec_cache_value *cache_value = NULL;
    uint8_t rdata[MAX_CACHE_KEY_SIZE];
    uint16_t rdlen = 0;
    int i;
    uint32_t ttl_n;

    // non authoritative data will not be signed
    if (unlikely(query->is_aa == 0)) {
        return -1;
    }

    // unexpected
    if (unlikely(index_num == 0)) {
        return -1;
    }

    // if zone's dnskey rrsig is deleted
    zsk_ctr = zone->adns_zsk_ctr;
    if (zsk_ctr == NULL) {
        return -1;
    }

    // get active zsk pointer
    zsk = adns_get_zsk_by_key_tag(zsk_ctr->active_zsk);
    // can not handle constants used in openssl, if query via TCP, create a new key and also ctx
    if (unlikely(query->is_tcp)) {
        key = adns_openssl_new_key(zsk->pubkey_data, zsk->pubkey_data_len, zsk->privkey_data, zsk->privkey_data_len);
        if (key == NULL) {
            return -1;
        }
        if (opensslecdsa_createctx(&evp_md_ctx) < 0) {
            return -1;
        }
    } else {
        key = zsk->key;
        evp_md_ctx = zsk->evp_md_ctx[l_core_id];
    }

    // only allow zsk sign
    if (unlikely(zsk->is_ksk == 1)) {
        return -1;
    }


    if (data_pos == NULL) {
        pos = query->wire + query->answered;
    } else {
        pos = data_pos;
    }

    /* fill query domain name */
    int node_name_size = rrset_owner_name_len;
    int ptr_offset, query_name_pos;
    if(query_name_cursor == NULL) {
        /* fill rr for domain in query segement */
        #if PVT_ZONE_PREFIX
        ptr_offset = query->qname_size_prefix - node_name_size;
        #else
        ptr_offset = query->qname_size - node_name_size;
        #endif
        query_name_pos = ADNS_WIRE_HEADER_SIZE;
    } else {
        /* fill rr for domain in answer segement (additional seg filling) */
        int query_name_size = adns_dname_size(query_name_cursor);
        query_name_cursor = adns_wire_seek_label(query_name_cursor, query->wire);
        ptr_offset = node_name_size - query_name_size;
        query_name_pos = query_name_cursor - query->wire; //relative to dns frame head
    }

    if (ptr_offset >= 0) {
        adns_wire_put_pointer(pos, query_name_pos + ptr_offset);
        pos += sizeof(uint16_t);
        len += sizeof(uint16_t);
    } else {
        ret = -1;
        goto done;
    }

    /* fill type, class, ttl */
    *(uint16_t *)pos = adns_htons(ADNS_RRTYPE_RRSIG);
    pos += 2;
    *(uint16_t *)pos = adns_htons(ADNS_CLASS_IN);
    pos += 2;
    ttl_n = adns_htonl(ttl);
    *(uint32_t *)pos = ttl_n;
    pos += 4;
    /* rdata length */
    *(uint16_t *)pos = adns_htons(DNS_SIG_ECDSA256SIZE + sizeof(adns_rrsig_rdata) + zone->name_len);
    pos += 2;

    // get current timestamp
    // rte_rdtsc use global variables, ndns does not handle them, use system call to get timestampt
    if (unlikely(query->is_tcp)) {
        t = time(NULL);
        tm = (uint32_t)t;
    } else {
        calculate_timestamp(&tv_res, rte_lcore_id(), rte_rdtsc());
        tm = tv_res.tv_sec;
    }

    // sort the RRs if there are more than one RR
    if (index_num > 1) {
        qsort(index_list, index_num, sizeof(adns_rr_index), rdata_compare);
    }

    // Lookup dnssec cache
    // NOTE: dnssec_cache_msg_pool shared between ADNS and NDNS, but NDNS
    //       crashes when allocate memory from shared hugepage mempool,
    //       dnssec cache is not working for query via TCP
    if (likely(*g_p_dnnssec_cache_switch == 1 && 
                query->is_tcp == 0)) {
        uint8_t *p = rdata;
        for (i = 0; i < index_num; i ++) {
            rte_memcpy(p, index_list[i].pos + ADNS_RR_HEADER_SIZE, index_list[i].len - ADNS_RR_HEADER_SIZE);
            rdlen += index_list[i].len - ADNS_RR_HEADER_SIZE;
            p += index_list[i].len - ADNS_RR_HEADER_SIZE;
        }
        cache_node = adns_dnssec_cache_hash_lookup(rrset_owner_name, rrset_owner_name_len, type, id, rdata, rdlen, ttl_n);
        if (cache_node != NULL) {
            cache_value = &(cache_node->value);
        }
        if (cache_value != NULL) { // DNSSEC cache hit
            // answer from DNSSEC cache node
            ret = _dnssec_rrsig_from_cache_node_value(pos, cache_value, tm, zsk->key_tag);
            if (likely(ret > 0)) {
                goto done;
            }
        }
    }
    // online signing
    ret = _dnssec_sign_rrset_online(query,
                                    pos,
                                    index_list,
                                    index_num,
                                    zone,
                                    rrset_owner_name,
                                    rrset_owner_name_len,
                                    type,
                                    id,
                                    ttl,
                                    tm,
                                    evp_md_ctx,
                                    zsk->key_tag,
                                    key,
                                    (cache_node == NULL)? DNSSEC_CACHE_INSERT : DNSSEC_CACHE_UPDATE,
                                    rdata,
                                    rdlen);

done:
    if (likely(ret > 0)) {
        len += ret;
        ret = len;
    }
    // if query via TCP, free newly created key and ctx
    if (unlikely(query->is_tcp)) {
        opensslecdsa_destroy_key(key);
        opensslecdsa_destroyctx(&evp_md_ctx);
    } else {
        EVP_DigestInit_ex(evp_md_ctx, EVP_sha256(), NULL);
    }
    return ret;
}
