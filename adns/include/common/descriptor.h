
#ifndef _ADNS_DESCRIPTOR_H_
#define _ADNS_DESCRIPTOR_H_

#include <stdint.h>
#include <stdio.h>

#define ADNS_MAX_RDATA_BLOCKS	8
#define ADNS_ROTATE_SIZE_MAX_LEN 5

#define IS_NEGATIVE(x) ((x) < 0)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

enum adns_rr_class {
	ADNS_CLASS_IN   =   1,
	ADNS_CLASS_CH   =   3,
	ADNS_CLASS_NONE = 254,
	ADNS_CLASS_ANY  = 255
};

enum adns_rr_type {
	ADNS_RRTYPE_A          =   1, /*!< An IPv4 host address. */
	ADNS_RRTYPE_NS         =   2, /*!< An authoritative name server. */

	ADNS_RRTYPE_CNAME      =   5, /*!< The canonical name for an alias. */
	ADNS_RRTYPE_SOA        =   6, /*!< The start of a zone of authority. */

	ADNS_RRTYPE_PTR        =  12, /*!< A domain name pointer. */
	ADNS_RRTYPE_HINFO      =  13, /*!< A host information. */
	ADNS_RRTYPE_MINFO      =  14, /*!< A mailbox information. */
	ADNS_RRTYPE_MX         =  15, /*!< Mail exchange. */
	ADNS_RRTYPE_TXT        =  16, /*!< Text strings. */
	ADNS_RRTYPE_RP         =  17, /*!< For responsible person. */
	ADNS_RRTYPE_AFSDB      =  18, /*!< For AFS Data Base location. */

	ADNS_RRTYPE_RT         =  21, /*!< For route through. */

	ADNS_RRTYPE_SIG        =  24, /*!< METATYPE. Transaction signature. */
	ADNS_RRTYPE_KEY        =  25, /*!< For security key. */

	ADNS_RRTYPE_AAAA       =  28, /*!< IPv6 address. */
	ADNS_RRTYPE_LOC        =  29, /*!< Location information. */

	ADNS_RRTYPE_SRV        =  33, /*!< Server selection. */

	ADNS_RRTYPE_NAPTR      =  35, /*!< Naming authority pointer . */
	ADNS_RRTYPE_KX         =  36, /*!< Key exchanger. */
	ADNS_RRTYPE_CERT       =  37, /*!< Certificate record. */

	ADNS_RRTYPE_DNAME      =  39, /*!< Delegation name. */

	ADNS_RRTYPE_OPT        =  41, /*!< METATYPE. Option for EDNS. */
	ADNS_RRTYPE_APL        =  42, /*!< Address prefix list. */
	ADNS_RRTYPE_DS         =  43, /*!< Delegation signer. */
	ADNS_RRTYPE_SSHFP      =  44, /*!< SSH public key fingerprint. */
	ADNS_RRTYPE_IPSECKEY   =  45, /*!< IPSEC key. */
	ADNS_RRTYPE_RRSIG      =  46, /*!< DNSSEC signature. */
	ADNS_RRTYPE_NSEC       =  47, /*!< Next-secure record. */
	ADNS_RRTYPE_DNSKEY     =  48, /*!< DNS key. */
	ADNS_RRTYPE_DHCID      =  49, /*!< DHCP identifier. */
	ADNS_RRTYPE_NSEC3      =  50, /*!< NSEC version 3. */
	ADNS_RRTYPE_NSEC3PARAM =  51, /*!< NSEC3 parameters. */
	ADNS_RRTYPE_TLSA       =  52, /*!< DANE record. */

	ADNS_RRTYPE_SPF        =  99, /*!< Sender policy framework. */

	ADNS_RRTYPE_NID        = 104, /*!< Node identifier. */
	ADNS_RRTYPE_L32        = 105, /*!< 32-bit network locator. */
	ADNS_RRTYPE_L64        = 106, /*!< 64-bit network locator. */
	ADNS_RRTYPE_LP         = 107, /*!< Subnetwork name. */
	ADNS_RRTYPE_EUI48      = 108, /*!< 48-bit extended unique identifier. */
	ADNS_RRTYPE_EUI64      = 109, /*!< 64-bit extended unique identifier. */

	ADNS_RRTYPE_TKEY       = 249, /*!< METATYPE. Transaction key. */
	ADNS_RRTYPE_TSIG       = 250, /*!< METATYPE. Transaction signature. */
	ADNS_RRTYPE_IXFR       = 251, /*!< QTYPE. Incremental zone transfer. */
	ADNS_RRTYPE_AXFR       = 252, /*!< QTYPE. Authoritative zone transfer. */

	ADNS_RRTYPE_ANY        = 255,  /*!< QTYPE. Any record. */
	ADNS_RRTYPE_CAA        = 257   /*!< QTYPE. CAA record, for Letsencrypt. */
};

enum adns_obsolete_rr_type {
	ADNS_RRTYPE_MD         =   3,
	ADNS_RRTYPE_MF         =   4,
	ADNS_RRTYPE_MB         =   7,
	ADNS_RRTYPE_MG         =   8,
	ADNS_RRTYPE_MR         =   9,
	ADNS_RRTYPE_PX         =  26,
	ADNS_RRTYPE_NXT        =  30
};
enum adns_LOG_CLASS {
    ADNS_LOG_SWITCH   =   1,
    ADNS_LOG_LEVEL    =   2,
    ADNS_LOG_ROTATE_SIZE   =   3,
    ADNS_LOG_ROTATE_COUNT   =   4
};
enum adns_LOG_TYPE {
    ADNS_LOG_SWITCH_DOWN   =   0,
    ADNS_LOG_SWITCH_UP     =   1,

    ADNS_LOG_LEVEL_ERROR  =   0,
    ADNS_LOG_LEVEL_WARN   =   1,
    ADNS_LOG_LEVEL_INFO   =   2,
    ADNS_LOG_LEVEL_DEBUG  =   3
};

enum adns_SYSLOG_CLASS {
    ADNS_SYSLOG_IP     =   1,
    ADNS_SYSLOG_SHOW   =   2
};

enum adns_53_CLASS {
    ADNS_DROP53     =   1,
    ADNS_RATE53     =   2,
    ADNS_SIP53      =   3,
    ADNS_TOTAL53    =   4,
    ADNS_PPS53      =   5,
	ADNS_ZONE53     =   6
};

#define DNS_ZONE_SIGNING_KEY_FLAGS 256   /* zone signing key */
#define DNS_ZONE_SIGNING_KEY_STR   "ZSK" 
#define DNS_KEY_SIGNING_KEY_FLAGS  257   /* key signing key */
#define DNS_KEY_SIGNING_KEY_STR    "KSK"

struct id_name_map {
	int id;
	const char *name;
};


static const struct id_name_map class_maps[] = {
	{ADNS_CLASS_IN, "IN"},
	{ADNS_CLASS_CH, "CH"},
	{ADNS_CLASS_NONE, "NONE"},
	{ADNS_CLASS_ANY, "ANY"},
};

static const struct id_name_map type_maps[] = {
	{ADNS_RRTYPE_A, "A"},
	{ADNS_RRTYPE_NS, "NS"},
	{ADNS_RRTYPE_CNAME, "CNAME"},
	{ADNS_RRTYPE_SOA, "SOA"},
	{ADNS_RRTYPE_PTR, "PTR"},
	{ADNS_RRTYPE_MX, "MX"},
	{ADNS_RRTYPE_TXT, "TXT"},
	{ADNS_RRTYPE_SRV, "SRV"},
	{ADNS_RRTYPE_AAAA, "AAAA"},
	{ADNS_RRTYPE_CAA, "CAA"},
	{ADNS_RRTYPE_DNSKEY, "DNSKEY"},
	{ADNS_RRTYPE_NSEC, "NSEC"},
	{ADNS_RRTYPE_RRSIG, "RRSIG"},
};

static const struct id_name_map log_level_maps[] = {
	{ADNS_LOG_LEVEL_ERROR, "ERROR"},
	{ADNS_LOG_LEVEL_WARN, "WARN"},
	{ADNS_LOG_LEVEL_INFO, "INFO"},
	{ADNS_LOG_LEVEL_DEBUG, "DEBUG"},
};

static const struct id_name_map log_switch_maps[] = {
	{ADNS_LOG_SWITCH_DOWN, "DOWN"},
	{ADNS_LOG_SWITCH_UP, "UP"},
};

enum adns_rdata_wireformat {
	/*!< Possibly compressed dname. */
	ADNS_RDATA_WF_COMPRESSED_DNAME   = -10,
	/*!< Uncompressed dname. */
	ADNS_RDATA_WF_UNCOMPRESSED_DNAME,
	/*!< Initial part of NAPTR record before dname. */
	ADNS_RDATA_WF_NAPTR_HEADER,
	/*!< Final part of a record. */
	ADNS_RDATA_WF_REMAINDER,
	/*!< The last descriptor in array. */
	ADNS_RDATA_WF_END                =   0
};

typedef struct {
	/*!< Item types describing rdata. */
	const int  block_types[ADNS_MAX_RDATA_BLOCKS];
	/*!< RR type name. */
	const char *type_name;
} rdata_descriptor_t;

const rdata_descriptor_t *get_rdata_descriptor(const uint16_t type);

const rdata_descriptor_t *get_obsolete_rdata_descriptor(const uint16_t type);

static inline const char* adns_rrtype_to_string(const uint16_t rrtype)
{
	unsigned int i;

    for (i = 0; i < ARRAY_SIZE(type_maps); i++) {
		if (type_maps[i].id == rrtype) {
			return type_maps[i].name;
		}
    }

	return NULL;
}

int adns_rrtype_from_string(const char *name, uint16_t *num);

int adns_rrclass_to_string(const uint16_t rrclass, char *out, size_t out_len);

int adns_rrclass_from_string(const char *name, uint16_t *num);

int descriptor_item_is_dname(const int item);

int descriptor_item_is_compr_dname(const int item);

int descriptor_item_is_fixed(const int item);

int descriptor_item_is_remainder(const int item);

int adns_rrtype_is_metatype(const uint16_t type);

#endif

