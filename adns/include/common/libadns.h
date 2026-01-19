#ifndef _LIBADNS_H_
#define _LIBADNS_H_

#include <stdint.h>

#define CMD_RESP_ERR_LEN 256
#define REQ_MAX_LEN (1 << 25)
#define DUMP_PATH_DEF "/home/adns/dump/adns.dump"


#define MSG_HDR_LEN         (sizeof(struct cmd_msg))
#define CMD_ENTRY_LEN(ce)   (sizeof(struct adns_command_entry) + (ce)->rdata_len)
#define DOMAIN_MAX_SIZE     255
#define RDATA_MAX_SIZE      255
#define ADNS_SOA_RRLEN      530
#define LABEL_MAX_SIZE       63
#define WEIGHT_MAX          200000
#define TOTAL_WEIGHT_MAX    4000000
#define RECV_BUFSIZE        (1<<20)
#define TXT_MAX_SIZE        2048
#define BATCH_MAX_TXT_NUM   200
#define CHARACTER_STRING_MAX_LEN 255 /* defined in RFC 1035 */
#define CAA_FLAGS_NONE 0
#define CAA_FLAGS_CRITICAL 0x80
#define CAA_TAG_LEN_MIN 1
#define CAA_TAG_LEN_MAX 15
#define CAA_VALUE_LEN_MAX 255 /* the length of caa value is unlimited in
                                 RFC 6844, but ADNS limits it to 255 */
#define KEY_TAG_MAX        65535 /* key tag is a uint16_t */

/* For private zone function only */
#ifdef PVT_ZONE
#define REGION_BUFF_SIZE     64
#define TUNNEL_BUFF_SIZE     16
#define FORWARD_BUFF_SIZE    16
#endif

struct adns_stats;
struct adns_info;
struct adns_dpdk_port_stats;

enum {
    ADNS_GET_INFO = 0,

    CMD_START,
    CMD_STOP,
    CMD_RECONF,
    CMD_RELOAD,

    CMD_ADDZONE,
    CMD_EDITZONE,
    CMD_DELZONE,
    CMD_LISTZONE,

    CMD_ADDRR,
    CMD_EDITRR,
    CMD_DELRR,
    CMD_DELDOMAIN,
    CMD_DELDOMAIN_ALL,
    CMD_LISTDOMAIN,
    CMD_LISTSCHEDULE,
    CMD_SCHEDULE_MODE,
    CMD_LISTDOMAIN_QPS,

    CMD_BATCH,
    CMD_INITLOAD,
    CMD_CLEAR,
    CMD_STATUS,
    CMD_DUMP,
    CMD_LOOKUP,
    CMD_QUOTA,
    CMD_LOG,
    CMD_53,
    CMD_UTILI,
    CMD_STATS,
    CMD_TCPSTATS,
    CMD_COUNTER,
    CMD_IP2VIEW,
    CMD_IPV62VIEW,
    CMD_RCODE_STATS,
    CMD_SHOW,
    CMD_SHOW_DPDK_HEAP,
    CMD_PORT,
    CMD_PORT_STATS,
    CMD_RELOAD_IPLIB,
    CMD_RELOAD_VM,
    CMD_SYSLOG,
    CMD_MEMORY_INFO,
    CMD_SET_CNAME_CASCADE,
    CMD_SET_WILDCARD_FALLBACK,
    CMD_REFRESH_ZONE,
    CMD_REFRESH_DOMAIN,

    CMD_ADDROUTE,
    CMD_DELROUTE,
    CMD_RELOADROUTE,
    CMD_DUMPROUTE,

    CMD_RELOAD_NSLIST,
    CMD_SHOW_NSLIST,

    CMD_SET_DNSSEC,
    CMD_DNSSEC_ADD_KEY,
    CMD_DNSSEC_DEL_ZSK,
    CMD_DNSSEC_ADD_DNSKEY_RRSIG,
    CMD_DNSSEC_QUOTA,
    CMD_DNSSEC_CACHE,

    CMD_QUIT,

    CMD_MAX,
};

enum adns_dnssec_cache_adm_ops {
    // set to ce->rclass, be distinguished by rclass for RR
    DNSSEC_CACHE_ADM_SWITCH = 10,      // DNSSEC cache switch
    DNSSEC_CACHE_ADM_DUMP,             // DNSSEC cache dump
    DNSSEC_CACHE_ADM_FLUSH,            // DNSSEC cache flush
};

struct adns_str {
    char rdata[TXT_MAX_SIZE]; /* need macro */
};

struct adns_command_entry {
	int cmd;
	uint8_t custom_view;     /* flag indicate that if view_id correspond to custom view */
	int num_cmds;

	char zone[DOMAIN_MAX_SIZE];
    char domain[DOMAIN_MAX_SIZE];
    adns_viewid_t view_id;

	uint16_t type;
	uint16_t rclass;
	uint32_t ttl;
	uint32_t weight;
	
	uint16_t rdata_len;
    char original_rdata[RDATA_MAX_SIZE];
	char rdata[0];
} __attribute__((packed));


struct batch_entry {
	int opcode;

	char zone[DOMAIN_MAX_SIZE];
	char domain[DOMAIN_MAX_SIZE];
    uint8_t custom_view;      /* flag indicate that if view_id correspond to custo view */
	adns_viewid_t view_id;

	uint16_t type;
	uint16_t rclass;
	uint32_t ttl;
	uint32_t weight;

	uint16_t rdata_len;
    char original_rdata[RDATA_MAX_SIZE];
    char rdata[0];
} __attribute__((packed));


struct cmd_resp {
    int cmd;
    int ret_val;
    int init_done;
    char err_msg[CMD_RESP_ERR_LEN];
    char data[0];
} __attribute__((packed));

int socket_init();
void socket_cleanup();
int adns_add_zone(struct adns_command_entry *ce);
int adns_del_zone(struct adns_command_entry *ce);
int adns_edit_zone(struct adns_command_entry *ce);
int adns_list_zone(struct adns_command_entry *ce);
int adns_add_rr(struct adns_command_entry *ce);
int adns_edit_rr(struct adns_command_entry *ce);
int adns_del_rr(struct adns_command_entry *ce);
int adns_del_domain(struct adns_command_entry *ce);
int adns_list_dname(struct adns_command_entry *ce);
int adns_list_schedule(struct adns_command_entry *ce);
int adns_schedule_mode(struct adns_command_entry *ce);
int adns_list_qps(struct adns_command_entry *ce);
int adns_init_load(uint8_t *batch_cmd_buff, int buff_len);
int adns_batch_process(uint8_t *batch_cmd_buff, int buff_len);
int adns_dump(struct adns_command_entry *ce);
int adns_clear(struct adns_command_entry *ce);
int adns_info_get(struct adns_command_entry *ce, struct adns_info **info);
int adns_show(struct adns_command_entry *ce);
int adns_show_dpdk_heap(struct adns_command_entry *ce);
int adns_status(struct adns_command_entry *ce);
int adns_stats(struct adns_command_entry *ce, struct adns_stats **st);
int adns_list_stats(struct adns_command_entry *ce);
int adns_counter_info(struct adns_command_entry *ce, uint64_t **value);
char *rcode_counter_id_to_name(int id);
int adns_rcode_stats(struct adns_command_entry *ce);
int adns_dpdk_port_info(struct adns_command_entry *ce, struct adns_dpdk_port_stats **value);
int adns_dpdk_port_stats(struct adns_command_entry *ce);
int adns_counter(struct adns_command_entry *ce);
int adns_list_utili(struct adns_command_entry *ce);
int adns_reload_iplib(struct adns_command_entry *ce);
int adns_reload_nslist(struct adns_command_entry *ce);
int adns_show_nslist(struct adns_command_entry *ce);
int adns_nslist_info(struct adns_command_entry *ce);
int adns_reload_vm(struct adns_command_entry *ce);
int adns_ip2view(struct adns_command_entry *ce, int adm_view_nums, struct adns_view_map *adm_view_maps);
int adns_lookup(struct adns_command_entry *ce);
int adns_quota(struct adns_command_entry *ce);
int adns_log(struct adns_command_entry *ce);
int adns_syslog(struct adns_command_entry *ce);
int adns_memory_info(struct adns_command_entry *ce);
int adns_set_cname_cascade(struct adns_command_entry *ce);
int adns_nslist_info(struct adns_command_entry *ce);
int adns_53(struct adns_command_entry *ce);
int adns_set_wildcard_fallback(struct adns_command_entry *ce);
int adns_set_dnssec(struct adns_command_entry *ce);
int adns_add_key(struct adns_command_entry *ce);
int adns_del_zsk(struct adns_command_entry *ce);
int adns_add_dnskey_rrsig(struct adns_command_entry *ce);
int adns_dnssec_quota(struct adns_command_entry *ce);
int adns_dnssec_cache(struct adns_command_entry *ce);

int adns_add_reload_route(uint8_t *route_cmd_buff, int buff_len);
int adns_del_route(struct adns_command_entry *ce);
int adns_dump_route(struct adns_command_entry *ce);
int adns_53(struct adns_command_entry *ce);

int adns_exit_app(struct adns_command_entry *ce);

#endif

