#ifndef __FWD_STATS__
#define __FWD_STATS__
#include <stdint.h>
#include "rte_core.h"
#include <rte_atomic.h>

#include "view.h"
#include "status.h"

#define STATS(type)      (inc_stats(LCORE_ID,type))
#define STATS_ADD(type,val)      (add_stats(LCORE_ID,type,val))
#define DSTATS(type)      (dec_stats(LCORE_ID,type))
#define VSTATS(vid,type) (inc_vstats(LCORE_ID,vid,type))
#define DVSTATS(vid,type) (dec_vstats(LCORE_ID,vid,type))

typedef enum{
    OVERSEALIST_STATUS,
    BLACKLIST_STATUS,
    WHITELIST_STATUS,
    MAN_WHITELIST_STATUS,
    MAN_BLACKLIST_STATUS,
    LCORESHARE_STATUS,
    STATUS_TYPE_MAX
}_status_type;

typedef enum {
    /* UDPDNS counters */
    IPV4_DNS_IN,
    IPV6_DNS_IN,
    TCP_DNS_IN,
    KNI_DNS_IN,
    DNS_OUT,
    KNI_DNS_OUT,
    TCP_IN,
    UDP_IN,
    TCP_OUT,
    UDP_OUT,
    HIT_REQ,
    HOLD_REQ,
    FWD_REQ,
    DNS_RESP,
    FWD_LOGIC_RESP,
    FWD_REAL_RESP,
    FWD_TIMEOUT,
    ANSWER_SERVFAIL,
    HIJACK_ANSWER,
    HEALTH_CHECK_REQ,
    SRVFAIL_NOT_UPD,
    ALINK_ADD_NODE,
    SRVFAIL_TRY_FIX,
    FWD_DOWN,
    ALL_VIEW_DOWN,
    IPC_REQ_FWD,
    IPC_MSG_REVC,
    IPV4_AUTH_IN,
    IPV6_AUTH_IN,
    AUTH_DNS_OUT,
    IPV4_SEC_IN,
    IPV6_SEC_IN,
    SEC_DNS_OUT,

    /* TTL counters */
    TTL_PREFETCH_NODE,
    TTL_PREFETCH_SEND,
    TTL_PREFETCH_RECV,
    TTL_PREFETCH_RECV_IMPACT,
    TTL_PREFETCH_SEND_FAIL,
    TTL_EXPIRE,

    /* drop counters */
    NIC_SEND_DROP,
    DNS_DROP,
    TCP_DNS_RST,
    RESP_DROP,
    ETH_FILTER_DROP,
    IP_FILTER_DROP,
    IPv6_FILTER_DROP,
    TCP_FILTER_DROP,
    UDP_FILTER_DROP,
    MBUF_APPEND_DROP,
    ADD_EDNS_DROP,
    SAME_REQ_DROP,
    DNS_PARSE_DROP,
    RESP_FWD_NONE_DROP, //response ,but no forwarderf found
    JMALLOC_FAIL_DROP,
    MP_GET_FAIL_DROP,
    KNI_DROP,
    FWD_SEND_FAIL,
    UNSUPPORT_HIJACK,
    IPC_MSG_EXCEED,
    MSG_MALLOC_FAIL,
    MSG_ENQUEUE_FAIL,
    UDP_PKT_LEN_ERR,
    DNS_PKT_LEN_ERR,
    TCP_PKT_LEN_ERR,
    DNAME_PARSE_ERR,
    DNAME_COMP_ERR,
    UNKNOWN_UDP_PKT,
    EDNS_PACK_ERR,
    PKT_MP_GET_FAIL,
    ALINK_EXCEED_LIST_MAX,
    ALINK_EXCEED_MAX,
    AN_MP_GET_FAIL,
    NODE_MP_GET_FAIL,
    DVAL_MP_GET_FAIL,
    BLACK_DNAME_DROP,
    BLACK_IP_DROP,
    SEND_PKT_FAIL,
    UNKNOWN_IPC_MSG,
    DKEY_MP_GET_FAIL,
    DEL_CACHE_DROP,
    RESP_WRONG_LCORE_DROP,
    RESP_FAIL_PARSE_ECS,
    AUTH_FWD_NO_CONF,
    AUTH_RESP_NO_CONF,
    AUTH_RESP_NONE_DROP, //response ,but no source node found
    AUTH_SRC_DOWN,
    AUTH_NODE_DOWN,
	ALINK_NK_VEXIST,

    LCORE_STATS_MAX
}stats_type;

/* per view request counters */
typedef enum{
    VIN_REQ,        /* request's IP src addr is in this view */
    VMST_REQ,       /* request hit the master core of this view */
    VSLV_REQ,      /* request hit the slave core of this view */
    VBIN_REQ,       /* in backup view, request's packet IP addr when src IP different from real IP */
    VBOUT_REQ,      /* in backup view, request's real IP addr when src IP different from real IP */
    VHIT_REQ,       /* request hit local cache */
    VFWD_REQ,       /* requests forwarded to secondary DNS */
    VFWD_TIMEOUT,
    VFWD_DOWN,

    VNODE_NEW,
    VNODE_PREFETCH,
    VNODE_TRUST,

    VS_MAX
}vstats_type;

struct cpu_util{
    int lcore_id;
    uint64_t send;
    uint64_t recv;
    uint64_t hc_send;
    uint64_t hc_tw;
    uint64_t retry;
    uint64_t ttl_ck;
    uint64_t msg;
    uint64_t all;
};

extern char gstatus_type[STATUS_TYPE_MAX][30];
extern char gstatus_info[STATUS_INFO_MAX][30];
extern const char *gstats_type_string[LCORE_STATS_MAX];
extern struct cpu_util gcpu_util[RTE_MAX_LCORE];
extern uint64_t lcore_stats[RTE_MAX_LCORE][LCORE_STATS_MAX];
extern uint64_t lcore_vstats[RTE_MAX_LCORE][VIEW_MAX_COUNT][VS_MAX];

static inline const char * __attribute__ ((always_inline))
fdns_stats_id_to_name(int id) {
    if (id >= LCORE_STATS_MAX) {
        return "this stats id is not support by fdns\n";
    }
    return gstats_type_string[id];
}

static inline void __attribute__ ((always_inline))
inc_stats(uint8_t lcore_id, stats_type type)
{
    lcore_stats[lcore_id][type]++;
}
static inline void __attribute__ ((always_inline))
add_stats(uint8_t lcore_id, stats_type type, uint64_t val)
{
    lcore_stats[lcore_id][type] += val;
}
static inline void __attribute__ ((always_inline))
dec_stats(uint8_t lcore_id, stats_type type)
{
    lcore_stats[lcore_id][type]--;
}

static inline void __attribute__ ((always_inline))
inc_vstats(uint8_t lcore_id, int vid, vstats_type type)
{
    lcore_vstats[lcore_id][vid][type]++;
}
static inline void __attribute__ ((always_inline))
dec_vstats(uint8_t lcore_id, int vid, vstats_type type)
{
    lcore_vstats[lcore_id][vid][type]--;
}

extern void stat_init();
#endif
