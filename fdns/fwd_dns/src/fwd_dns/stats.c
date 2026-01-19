#include <assert.h>
#include "stats.h"
uint64_t lcore_stats[RTE_MAX_LCORE][LCORE_STATS_MAX];
uint64_t lcore_vstats[RTE_MAX_LCORE][VIEW_MAX_COUNT][VS_MAX];
struct cpu_util gcpu_util[RTE_MAX_LCORE];
char gstatus_type[STATUS_TYPE_MAX][30];
char gstatus_info[STATUS_INFO_MAX][30];
const char *gstats_type_string[LCORE_STATS_MAX] = {
    /* UDPDNS counters */
    [IPV4_DNS_IN] =            "ipv4_dns_in",
    [IPV6_DNS_IN] =            "ipv6_dns_in",
    [TCP_DNS_IN] =             "tcp_dns_in",
    [KNI_DNS_IN] =             "kni_dns_in",
    [DNS_OUT] =                "dns_out",
    [KNI_DNS_OUT] =            "kni_dns_out",
    [TCP_IN] =                 "tcp_in",
    [UDP_IN] =                 "udp_in",
    [TCP_OUT] =                "tcp_out",
    [UDP_OUT] =                "udp_out",
    [HIT_REQ] =                "hit_req",
    [HOLD_REQ] =               "hold_req",
    [FWD_REQ] =                "fwd_req",
    [DNS_RESP] =               "dns_resp",
    [FWD_LOGIC_RESP] =         "fwd_logic_resp",
    [FWD_REAL_RESP] =          "fwd_real_resp",
    [FWD_TIMEOUT] =            "fwd_timeout",
    [ANSWER_SERVFAIL] =        "aswer_srvfail",
    [HIJACK_ANSWER] =          "hijack_answer",
    [HEALTH_CHECK_REQ] =       "helth_chk_req",
    [SRVFAIL_NOT_UPD] =        "srvfail_no_upd",
    [ALINK_ADD_NODE] =         "alink_add_node",
    [SRVFAIL_TRY_FIX] =        "srvfail_tryfix",
    [FWD_DOWN] =               "fwd_down",
    [ALL_VIEW_DOWN] =          "all_view_down",
    [IPC_REQ_FWD] =            "ipc_req_fwd",
    [IPC_MSG_REVC] =           "ipc_msg_recv",
    [IPV4_AUTH_IN] =           "ipv4_auth_in",
    [IPV6_AUTH_IN] =           "ipv6_auth_in",
    [AUTH_DNS_OUT] =           "auth_dns_out",
    [IPV4_SEC_IN] =            "ipv4_sec_in",
    [IPV6_SEC_IN] =            "ipv6_sec_in",
    [SEC_DNS_OUT] =            "sec_dns_out",

    /* TTL counters */
    [TTL_PREFETCH_NODE] =      "ttl_pref_node",
    [TTL_PREFETCH_SEND] =      "ttl_pref_send",
    [TTL_PREFETCH_RECV] =      "ttl_pref_recv",
    [TTL_PREFETCH_RECV_IMPACT] ="ttl_pref_imp",
    [TTL_PREFETCH_SEND_FAIL] = "ttl_pref_sfail",
    [TTL_EXPIRE] =             "ttl_expire",

    /* drop counters */
    [NIC_SEND_DROP] =          "nic_send_drop",
    [DNS_DROP] =               "dns_drop",
    [TCP_DNS_RST] =            "tcp_dns_rst",
    [RESP_DROP] =              "resp_drop",
    [ETH_FILTER_DROP] =        "eth_filt_drop",
    [IP_FILTER_DROP] =         "ip_filt_drop",
    [IPv6_FILTER_DROP] =       "ipv6_filt_drop",
    [TCP_FILTER_DROP] =        "tcp_filt_drop",
    [UDP_FILTER_DROP] =        "udp_filt_drop",
    [MBUF_APPEND_DROP] =       "mb_apend_drop",
    [ADD_EDNS_DROP] =          "add_edns_drop",
    [SAME_REQ_DROP] =          "same_req_drop",
    [DNS_PARSE_DROP] =         "dns_parse_drop",
    [RESP_FWD_NONE_DROP] =     "resp_fwd_drop",
    [JMALLOC_FAIL_DROP] =      "jmal_fail_drop",
    [MP_GET_FAIL_DROP] =       "mp_g_fail_drop",
    [KNI_DROP] =               "kni_drop",
    [FWD_SEND_FAIL] =          "fwd_send_fail",
    [UNSUPPORT_HIJACK] =       "unsport_hijack",
    [IPC_MSG_EXCEED] =         "ipc_msg_exceed",
    [MSG_MALLOC_FAIL] =        "msg_mal_fail",
    [MSG_ENQUEUE_FAIL] =       "msg_enqu_fail",
    [UDP_PKT_LEN_ERR] =        "udp_plen_err",
    [DNS_PKT_LEN_ERR] =        "dns_plen_err",
    [TCP_PKT_LEN_ERR] =        "tcp_plen_err",
    [DNAME_PARSE_ERR] =        "dnam_parse_err",
    [DNAME_COMP_ERR] =         "dnam_comp_err",
    [UNKNOWN_UDP_PKT] =        "unkno_udp_pkt",
    [EDNS_PACK_ERR] =          "edns_pack_err",
    [PKT_MP_GET_FAIL] =        "pkt_mp_g_fail",
    [ALINK_EXCEED_LIST_MAX] =  "alnk_exced_lst",
    [ALINK_EXCEED_MAX] =       "alnk_exceed",
    [AN_MP_GET_FAIL] =         "an_mp_g_fail",
    [NODE_MP_GET_FAIL] =       "nod_mp_g_fail",
    [DVAL_MP_GET_FAIL] =       "dval_mp_g_fail",
    [BLACK_DNAME_DROP] =       "blk_dnam_drop",
    [BLACK_IP_DROP] =          "blk_ip_drop",
    [SEND_PKT_FAIL] =          "send_pkt_fail",
    [UNKNOWN_IPC_MSG] =        "unkn_ipc_msg",
    [DKEY_MP_GET_FAIL] =       "dkey_mp_g_fail",
    [DEL_CACHE_DROP] =         "del_cache_drop",
    [RESP_WRONG_LCORE_DROP] =  "resp_wro_lcore",
    [RESP_FAIL_PARSE_ECS] =    "resp_fail_ecs",
    [AUTH_FWD_NO_CONF] =       "afwd_no_conf",
    [AUTH_RESP_NO_CONF] =      "aresp_no_conf",
    [AUTH_RESP_NONE_DROP] =    "aresp_no_src",
    [AUTH_SRC_DOWN] =          "auth_src_down",
    [AUTH_NODE_DOWN] =         "auth_node_down",
	[ALINK_NK_VEXIST] =        "alink_nk_vexist",
};

void stat_init()
{
    memset(lcore_stats, 0, sizeof(lcore_stats));
    memset(lcore_vstats, 0, sizeof(lcore_vstats));
    memset(gcpu_util, 0, sizeof(gcpu_util));
    memset(gstatus_info, 0, sizeof(gstatus_info));
    memset(gstatus_type, 0, sizeof(gstatus_type));
    sprintf(gstatus_type[OVERSEALIST_STATUS], "oversea_list");
    sprintf(gstatus_type[WHITELIST_STATUS], "whitelist");
    sprintf(gstatus_type[MAN_WHITELIST_STATUS], "man_whitelist");
    sprintf(gstatus_type[MAN_BLACKLIST_STATUS], "man_blacklist");
    sprintf(gstatus_type[LCORESHARE_STATUS],"lcore_data_share");
    sprintf(gstatus_info[STATUS_ON], "ON");
    sprintf(gstatus_info[STATUS_OFF], "OFF");

}

