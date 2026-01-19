
#ifndef _DNS_CONSTS_H_
#define _DNS_CONSTS_H_

#include <stdint.h>


#define DNS_DNAME_MAXLEN 255     /*!< 1-byte maximum. */
#define DNS_DNAME_MAXLABELS 127  /*!< 1-char labels. */

#define DNS_RR_HEADER_SIZE 10

typedef enum {
	DNS_OPCODE_QUERY  = 0, /*!< Standard query. */
	DNS_OPCODE_IQUERY = 1, /*!< Inverse query. */
	DNS_OPCODE_STATUS = 2, /*!< Server status request. */
	DNS_OPCODE_NOTIFY = 4, /*!< Notify message. */
	DNS_OPCODE_UPDATE = 5  /*!< Dynamic update. */
} dns_opcode_t;

typedef enum {
	DNS_RCODE_NOERROR  =  0, /*!< No error. */
	DNS_RCODE_FORMERR  =  1, /*!< Format error. */
	DNS_RCODE_SERVFAIL =  2, /*!< Server failure. */
	DNS_RCODE_NXDOMAIN =  3, /*!< Non-existend domain. */
	DNS_RCODE_NOTIMPL  =  4, /*!< Not implemented. */
	DNS_RCODE_REFUSED  =  5, /*!< Refused. */
	DNS_RCODE_YXDOMAIN =  6, /*!< Name should not exist. */
	DNS_RCODE_YXRRSET  =  7, /*!< RR set should not exist. */
	DNS_RCODE_NXRRSET  =  8, /*!< RR set does not exist. */
	DNS_RCODE_NOTAUTH  =  9, /*!< Server not authoritative. */
	DNS_RCODE_NOTZONE  = 10, /*!< Name is not inside zone. */
	DNS_RCODE_BADSIG   = 16, /*!< TSIG signature failed. */
	DNS_RCODE_BADKEY   = 17, /*!< Key is not supported. */
	DNS_RCODE_BADTIME  = 18, /*!< Signature out of time window. */
	DNS_RCODE_BADMODE  = 19, /*!< Bad TKEY mode. */
	DNS_RCODE_BADNAME  = 20, /*!< Duplicate key name. */
	DNS_RCODE_BADALG   = 21, /*!< Algorithm not supported. */
	DNS_RCODE_BADTRUNC = 22  /*!< Bad truncation. */
} dns_rcode_t;

typedef enum {
	DNS_QUERY_INVALID,   /*!< Invalid query. */
	DNS_QUERY_NORMAL,    /*!< Normal query. */
	DNS_QUERY_AXFR,      /*!< Request for AXFR transfer. */
	DNS_QUERY_IXFR,      /*!< Request for IXFR transfer. */
	DNS_QUERY_NOTIFY,    /*!< NOTIFY query. */
	DNS_QUERY_UPDATE,    /*!< Dynamic update. */
	DNS_RESPONSE_NORMAL, /*!< Normal response. */
	DNS_RESPONSE_AXFR,   /*!< AXFR transfer response. */
	DNS_RESPONSE_IXFR,   /*!< IXFR transfer response. */
	DNS_RESPONSE_NOTIFY, /*!< NOTIFY response. */
	DNS_RESPONSE_UPDATE  /*!< Dynamic update response. */
} dns_packet_type_t;

typedef enum {
	DNS_TSIG_ALG_NULL        =   0,
	DNS_TSIG_ALG_GSS_TSIG    = 128,
	DNS_TSIG_ALG_HMAC_MD5    = 157,
	DNS_TSIG_ALG_HMAC_SHA1   = 161,
	DNS_TSIG_ALG_HMAC_SHA224 = 162,
	DNS_TSIG_ALG_HMAC_SHA256 = 163,
	DNS_TSIG_ALG_HMAC_SHA384 = 164,
	DNS_TSIG_ALG_HMAC_SHA512 = 165
} dns_tsig_algorithm_t;

typedef enum {
	DNS_TSIG_ALG_DIG_LENGTH_GSS_TSIG =  0,
	DNS_TSIG_ALG_DIG_LENGTH_HMAC_MD5 = 16,
	DNS_TSIG_ALG_DIG_LENGTH_SHA1     = 20,
	DNS_TSIG_ALG_DIG_LENGTH_SHA224   = 28,
	DNS_TSIG_ALG_DIG_LENGTH_SHA256   = 32,
	DNS_TSIG_ALG_DIG_LENGTH_SHA384   = 48,
	DNS_TSIG_ALG_DIG_LENGTH_SHA512   = 64
} dns_tsig_algorithm_digest_length_t;

typedef enum {
	DNS_DNSSEC_ALG_RSAMD5             =  1,
	DNS_DNSSEC_ALG_DH                 =  2,
	DNS_DNSSEC_ALG_DSA                =  3,

	DNS_DNSSEC_ALG_RSASHA1            =  5,
	DNS_DNSSEC_ALG_DSA_NSEC3_SHA1     =  6,
	DNS_DNSSEC_ALG_RSASHA1_NSEC3_SHA1 =  7,
	DNS_DNSSEC_ALG_RSASHA256          =  8,

	DNS_DNSSEC_ALG_RSASHA512          = 10,

	DNS_DNSSEC_ALG_ECC_GOST           = 12,
	DNS_DNSSEC_ALG_ECDSAP256SHA256    = 13,
	DNS_DNSSEC_ALG_ECDSAP384SHA384    = 14
} dns_dnssec_algorithm_t;

enum dns_ds_algorithm_len
{
	DNS_DS_DIGEST_LEN_SHA1   = 20, /*!< RFC 3658 */
	DNS_DS_DIGEST_LEN_SHA256 = 32, /*!< RFC 4509 */
	DNS_DS_DIGEST_LEN_GOST   = 32, /*!< RFC 5933 */
	DNS_DS_DIGEST_LEN_SHA384 = 48  /*!< RFC 6605 */
};

typedef enum {
	DNS_DS_ALG_SHA1   = 1,
	DNS_DS_ALG_SHA256 = 2,
	DNS_DS_ALG_GOST   = 3,
	DNS_DS_ALG_SHA384 = 4
} dns_ds_algorithm_t;


#endif

