
#ifndef _ADNS_CONSTS_H_
#define _ADNS_CONSTS_H_

#include <stdint.h>

#include "utils.h"

#define ADNS_MAX_CNAME_CASCADE 3
#define ADNS_DNAME_MAXLEN 255      /*!< 1-byte maximum. */
#define ADNS_DNAME_MAXLABELS 127   /*!< 1-char labels. */
#define ADNS_DNAME_LABEL_MAXLEN 63 /* max length of a label */

#define ADNS_RR_HEADER_SIZE 10

typedef enum {
	ADNS_OPCODE_QUERY  = 0, /*!< Standard query. */
	ADNS_OPCODE_IQUERY = 1, /*!< Inverse query. */
	ADNS_OPCODE_STATUS = 2, /*!< Server status request. */
	ADNS_OPCODE_NOTIFY = 4, /*!< Notify message. */
	ADNS_OPCODE_UPDATE = 5  /*!< Dynamic update. */
} adns_opcode_t;

typedef enum {
	ADNS_RCODE_NOERROR  =  0, /*!< No error. */
	ADNS_RCODE_FORMERR  =  1, /*!< Format error. */
	ADNS_RCODE_SERVFAIL =  2, /*!< Server failure. */
	ADNS_RCODE_NXDOMAIN =  3, /*!< Non-existend domain. */
	ADNS_RCODE_NOTIMPL  =  4, /*!< Not implemented. */
	ADNS_RCODE_REFUSED  =  5, /*!< Refused. */
	ADNS_RCODE_YXDOMAIN =  6, /*!< Name should not exist. */
	ADNS_RCODE_YXRRSET  =  7, /*!< RR set should not exist. */
	ADNS_RCODE_NXRRSET  =  8, /*!< RR set does not exist. */
	ADNS_RCODE_NOTAUTH  =  9, /*!< Server not authoritative. */
	ADNS_RCODE_NOTZONE  = 10, /*!< Name is not inside zone. */
	ADNS_RCODE_BADSIG   = 16, /*!< TSIG signature failed. */
	ADNS_RCODE_BADKEY   = 17, /*!< Key is not supported. */
	ADNS_RCODE_BADTIME  = 18, /*!< Signature out of time window. */
	ADNS_RCODE_BADMODE  = 19, /*!< Bad TKEY mode. */
	ADNS_RCODE_BADNAME  = 20, /*!< Duplicate key name. */
	ADNS_RCODE_BADALG   = 21, /*!< Algorithm not supported. */
	ADNS_RCODE_BADTRUNC = 22  /*!< Bad truncation. */
} adns_rcode_t;

typedef enum {
	ADNS_QUERY_INVALID,   /*!< Invalid query. */
	ADNS_QUERY_NORMAL,    /*!< Normal query. */
	ADNS_QUERY_AXFR,      /*!< Request for AXFR transfer. */
	ADNS_QUERY_IXFR,      /*!< Request for IXFR transfer. */
	ADNS_QUERY_NOTIFY,    /*!< NOTIFY query. */
	ADNS_QUERY_UPDATE,    /*!< Dynamic update. */
	ADNS_RESPONSE_NORMAL, /*!< Normal response. */
	ADNS_RESPONSE_AXFR,   /*!< AXFR transfer response. */
	ADNS_RESPONSE_IXFR,   /*!< IXFR transfer response. */
	ADNS_RESPONSE_NOTIFY, /*!< NOTIFY response. */
	ADNS_RESPONSE_UPDATE  /*!< Dynamic update response. */
} adns_packet_type_t;

typedef enum {
	ADNS_TSIG_ALG_NULL        =   0,
	ADNS_TSIG_ALG_GSS_TSIG    = 128,
	ADNS_TSIG_ALG_HMAC_MD5    = 157,
	ADNS_TSIG_ALG_HMAC_SHA1   = 161,
	ADNS_TSIG_ALG_HMAC_SHA224 = 162,
	ADNS_TSIG_ALG_HMAC_SHA256 = 163,
	ADNS_TSIG_ALG_HMAC_SHA384 = 164,
	ADNS_TSIG_ALG_HMAC_SHA512 = 165
} adns_tsig_algorithm_t;

typedef enum {
	ADNS_TSIG_ALG_DIG_LENGTH_GSS_TSIG =  0,
	ADNS_TSIG_ALG_DIG_LENGTH_HMAC_MD5 = 16,
	ADNS_TSIG_ALG_DIG_LENGTH_SHA1     = 20,
	ADNS_TSIG_ALG_DIG_LENGTH_SHA224   = 28,
	ADNS_TSIG_ALG_DIG_LENGTH_SHA256   = 32,
	ADNS_TSIG_ALG_DIG_LENGTH_SHA384   = 48,
	ADNS_TSIG_ALG_DIG_LENGTH_SHA512   = 64
} adns_tsig_algorithm_digest_length_t;

typedef enum {
	ADNS_DNSSEC_ALG_RSAMD5             =  1,
	ADNS_DNSSEC_ALG_DH                 =  2,
	ADNS_DNSSEC_ALG_DSA                =  3,

	ADNS_DNSSEC_ALG_RSASHA1            =  5,
	ADNS_DNSSEC_ALG_DSA_NSEC3_SHA1     =  6,
	ADNS_DNSSEC_ALG_RSASHA1_NSEC3_SHA1 =  7,
	ADNS_DNSSEC_ALG_RSASHA256          =  8,

	ADNS_DNSSEC_ALG_RSASHA512          = 10,

	ADNS_DNSSEC_ALG_ECC_GOST           = 12,
	ADNS_DNSSEC_ALG_ECDSAP256SHA256    = 13,
	ADNS_DNSSEC_ALG_ECDSAP384SHA384    = 14
} adns_dnssec_algorithm_t;

enum adns_ds_algorithm_len
{
	ADNS_DS_DIGEST_LEN_SHA1   = 20, /*!< RFC 3658 */
	ADNS_DS_DIGEST_LEN_SHA256 = 32, /*!< RFC 4509 */
	ADNS_DS_DIGEST_LEN_GOST   = 32, /*!< RFC 5933 */
	ADNS_DS_DIGEST_LEN_SHA384 = 48  /*!< RFC 6605 */
};

typedef enum {
	ADNS_DS_ALG_SHA1   = 1,
	ADNS_DS_ALG_SHA256 = 2,
	ADNS_DS_ALG_GOST   = 3,
	ADNS_DS_ALG_SHA384 = 4
} adns_ds_algorithm_t;


#define DNS_SIG_ECDSA256SIZE    64       /* ECDSAP256 signature size */
#define DNS_KEY_ECDSA256SIZE    64       /* ECDSAP256 public key size */
#define DNS_DNSKEY_PROTOCOL      3       /* DNSKEY protocol field, must be 3 */
#define ECDSA_P256_ALGO         13       /* algorithm number for ECDSA-P256 */

#define MAX_DNSKEY_NUM          3        /* max dnskey number, in keyrollover, could have 2 ZSKs */
#define MAX_ZSK_NUM             2        /* max zsk number, in keyrollover, could have 2 ZSKs */


/*
extern adns_lookup_table_t adns_rcode_names[];
extern adns_lookup_table_t adns_tsig_alg_names[];
extern adns_lookup_table_t adns_tsig_alg_dnames_str[];
extern adns_lookup_table_t adns_tsig_alg_dnames[];
size_t adns_tsig_digest_length(const uint8_t algorithm);
size_t adns_ds_digest_length(const uint8_t algorithm);
*/

#ifdef PVT_ZONE
#define PVT_ZONE_PREFIX 1
#else
#define PVT_ZONE_PREFIX 0
#endif
#define PVT_ZONE_POSTFIX_MAX 30
#define ZONEID_BUFF_SIZE 16
#endif

