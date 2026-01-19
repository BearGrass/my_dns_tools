
#ifndef _ADNS_CONF_H_
#define _ADNS_CONF_H_

#include "adns_types.h"

/* ---  system  --- */
#define ADNS_MAX_SOCKETS      1
#define MAX_HOSTNAME_LEN 256

/* ---  DNS  --- */
#define ADNS_DOMAIN_MAX_LEN       255 

#define NAME_LEN_TYPE_NUM 4

#define ADNS_DOMAIN_MAX_LEN_32    32 
#define ADNS_DOMAIN_MAX_LEN_64    64
#define ADNS_DOMAIN_MAX_LEN_128   128 
#define ADNS_DOMAIN_MAX_LEN_256   256

/* ---  zone database  --- */
#define ADNS_ZONEDB_NAME      "adns"
#define ADNS_ZONEDB_MAGIC     0x20131026
#define ADNS_ZONEDB_NAMELEN   64

#define ADNS_ZONEDB_HASH_BITS 22  /* 16k bucket, for zone hash table */
#define ADNS_ZONEDB_HASH_SIZE (1 << ADNS_ZONEDB_HASH_BITS)
#define ADNS_ZONEDB_HASH_MASK (ADNS_ZONEDB_HASH_SIZE - 1)

#define ADNS_ZONE_DEF_VER     0x20131101
#define ADNS_SOA_RRLEN        530

#define ADNS_NODE_HASH_SIZE (1<<6)
#define ADNS_NODE_HASH_MASK (ADNS_NODE_HASH_SIZE-1)

/* ---  view --- */
#define ADNS_VIEW_HASH_BITS   6
#define ADNS_VIEW_HASH_SIZE   (1 << ADNS_VIEW_HASH_BITS)
#define ADNS_VIEW_HASH_MASK   (ADNS_VIEW_HASH_SIZE - 1)
#define ADNS_RRSET_MAX        256

/* ---  rrset --- */
#define RRSET_RDATA_MAX_NUM   90
#define RRSET_A_RDATA_MAX_NUM 90

#define  TCP_DNS_MAX_LENGTH  6143       /*tcp max length 6k */
#define  UDP_DNS_MAX_LENGTH  512
#define  UDP_DNS_TXT_MAX_LENGTH  2048   /* TXT rr may be very long */
#define  DNS_EDNS0_MAX_LENGTH 4096
#define  MTU_SIZE  1500


#define  MAX_A_RR_FOR_PKT     10    //If the domain name is 64,the max a rr for one package.
#define ADNS_RRSET_NUM 10 //rr type for adns support.


/* --- domain hash --- */
#define ADNS_DOMAINDB_HASH_SIZE  (1<<27)
#define ADNS_DOMAINDB_HASH_MASK (ADNS_DOMAINDB_HASH_SIZE - 1)

/* --- common NS list hash --- */
#define ADNS_NS_LIST_HASH_SIZE  (1024)
#define ADNS_NS_LIST_HASH_MASK (ADNS_NS_LIST_HASH_SIZE - 1)

/* --- NS list macro --- */
#define ADNS_MAX_NS_NUM_PER_GROUP 2

/* --- DNSSEC cache hash --- */
#define ADNS_DNSSEC_CACHE_HASH_SIZE (1 << 22)
#define ADNS_DNSSEC_CACHE_HASH_MASK (ADNS_DNSSEC_CACHE_HASH_SIZE - 1)
#define ADNS_DNSSEC_CLEAN_BULK_NUM 128

#define CORES_MAX_NUM   16

#define ADNS_UINT8_BIT       8
#define ADNS_UINT4_BIT       4
#define ADNS_UINT8_MAC       0xff
#define ADNS_UINT4_MAC       0xf
#define ADNS_8_MAC           0x7
#define ADNS_4_MAC           0x3
#define ADNS_8_LOG2          3
#define ADNS_4_LOG2          2

#define USE_BIT_NODE_TAG

#ifdef USE_BIT_NODE_TAG
#define SET_TAG(tag, id) ((tag)[(id) >> ADNS_8_LOG2] |= (1 << ((id) & ADNS_8_MAC)))
#define CLR_TAG(tag, id) ((tag)[(id) >> ADNS_8_LOG2] &= ~(1 << ((id) & ADNS_8_MAC)))
//#define GET_TAG(tag, id) ((tag)[(id) >> ADNS_8_LOG2] & (1 << ((id) & ADNS_8_MAC)))
#define GET_TAG(tag, id) ((tag)[(id) >> ADNS_8_LOG2] >> ((id) & ADNS_8_MAC) & 1)
#else
#define SET_TAG(tag, id) ((tag)[(id)] = 1)
#define CLR_TAG(tag, id) ((tag)[(id)] = 0)
#define GET_TAG(tag, id) ((tag)[(id)])
#endif

/* zone/view/domain/rr Configurable*/
extern uint32_t g_zone_max_num;
extern uint32_t g_private_route_zone_max_num;
extern adns_private_route_id_t g_private_route_per_zone_max_num;
extern uint8_t g_ip_segment_per_route_max_num;
extern adns_viewid_t g_view_max_num;
extern uint32_t g_domain_max_num;
extern uint32_t g_rr_max_num;
extern uint32_t g_rrset_memory_max_num;
extern uint32_t g_rdata_ctl_max_num;
extern uint32_t g_private_rdata_ctl_max_num;
extern uint8_t  g_response_answer_max_record_num;
extern uint8_t  g_response_authority_max_record_num;
extern uint8_t  g_response_additional_max_record_num;
extern uint32_t g_ns_group_max_num;
extern uint32_t g_dnssec_zone_max_num;
extern uint32_t g_dnssec_cache_max_num;
extern uint8_t *g_p_dnnssec_cache_switch;
extern char *g_hostname;
extern uint8_t g_hostname_len;


/* Custom view prefix */
#define CUSTOM_VIEW_PREFIX "custom_"

extern int name_len_to_index[];

/* schedule mode */
enum {
    SCHEDULE_MODE_RATIO = 0,
    SCHEDULE_MODE_ALLRR = 1,
    SCHEDULE_MODE_UNKNOWN = 2,
};

#define SCHEDULE_MODE_VALIDATE(mode, set_to_line) \
    (( (set_to_line) && ((mode) > SCHEDULE_MODE_UNKNOWN) ) || ( (!set_to_line) && ((mode) > SCHEDULE_MODE_ALLRR)) )

#endif

