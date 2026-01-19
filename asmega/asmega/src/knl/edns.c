#include "edns.h"
#include "stats.h"


/*-
 * parse additional, only support edns now
 */
int
parse_dns_additional(uint8_t **wire, uint16_t **opt_len_pos, uint16_t edns_len)
{
    uint8_t opt_owner, opt_version;
    uint16_t opt_type, opt_rdlen, opt_code, opt_len;
    //uint8_t opt_ext_rcode;
    //uint16_t opt_class, opt_flags;
    uint8_t *pos = *wire;

    if (EDNS_MIN_SIZE > edns_len) {
        return AS_ERROR;
    }

    /*---
     * edns0 format
     * Filed name    Filed type      Description
     * ------------------------------------------
     * NAME          domain name     empty(root domain)
     * TYPE          uint16_t        OPT
     * CLASS         uint16_t        sender's UDP payload size
     * TTL           uint32_t        extended RCODE and flags
     * RDLEN         uint16_t        describes RDATA
     * RDATA         octet stream    {attr, value} pairs
     */
    opt_owner = *pos;
    pos ++;
    opt_type = ntohs(*(uint16_t*)pos);
    pos += 2;
    if (opt_owner != 0 || opt_type != EDNS_OPT) {
        AS_INC_ESTATS(as_esmib, AS_ERROR_EDNS_TYPE);
        return AS_ERROR;
    }

    /* class - sender's UDP payload size */
    //opt_class = ntohs(*(uint16_t*)pos);
    pos += 2;

    /*-
     * ttl - extended RCODE and flags
     * extended rcode(uint8_t) | version(uint8_t) | zero flags(uint16_t)
     */
    //opt_ext_rcode = *pos;
    pos ++;
    opt_version = *pos;
    pos ++;
    if (opt_version != 0) {
        AS_INC_ESTATS(as_esmib, AS_ERROR_EDNS_VERSION);
        return AS_ERROR;
    }

    //opt_flags = ntohs(*(uint16_t*)pos);
    pos += 2;
    opt_rdlen = ntohs(*(uint16_t*)pos);
    *opt_len_pos = (uint16_t *)pos;
    pos += 2;
    if (likely(opt_rdlen == 0)) {
        *wire = pos;
        return AS_SUCCESS;
    }

    edns_len -= EDNS_MIN_SIZE;
    if (unlikely(edns_len < opt_rdlen)) {
        AS_INC_ESTATS(as_esmib, AS_ERROR_EDNS_LEN);
        return AS_ERROR;
    }
    while (opt_rdlen >= 4) {
        opt_code = ntohs(*(uint16_t*)pos);
        pos += 2;
        opt_len = ntohs(*(uint16_t*)pos);
        pos += 2;
        opt_rdlen -= 4;
        if (unlikely(opt_rdlen  < opt_len)) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_EDNS_LEN);
            return AS_ERROR;
        }

        if (opt_code == EDNS_OPTION_PVT) {
            *wire = pos + opt_len;
            return AS_PVT_EDNS;
        }

        pos += opt_len;
        opt_rdlen -= opt_len;
    }
    *wire = pos;
    return AS_SUCCESS;
}

