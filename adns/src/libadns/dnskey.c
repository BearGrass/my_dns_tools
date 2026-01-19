#include "rte_malloc.h"
#include "dnskey.h"

// Key tag is a uint16_t, it's max value is 65535
#define MAX_KEY_TAG_SIZE (1 << 16)
// ZSK table, its index is key tag
// NOTE: can not handle 2 different ZSKs have the same key tag
adns_dnssec_key **zsk_p_table = NULL;


int adns_init_zsk_p_table(void)
{
    zsk_p_table = (adns_dnssec_key **)rte_zmalloc(NULL, sizeof(adns_dnssec_key *) * MAX_KEY_TAG_SIZE, 0);
    if (zsk_p_table == NULL) {
        return -1;
    }

    return 0;
}

void adns_free_zsk_p_table(void)
{
    if (zsk_p_table != NULL) {
        rte_free(zsk_p_table);
        zsk_p_table = NULL;
    }
}

adns_dnssec_key *adns_set_zsk(adns_dnssec_key *key)
{
    adns_dnssec_key *old_zsk = zsk_p_table[key->key_tag];
    zsk_p_table[key->key_tag] = key;
    return old_zsk;
}

adns_dnssec_key *adns_get_zsk_by_key_tag(uint16_t key_tag)
{
    return zsk_p_table[key_tag];
}

void adns_clear_zsk_by_key_tag(uint16_t key_tag)
{
    zsk_p_table[key_tag] = NULL;
}