#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>

#include "admin.h"
#include "log.h"
#include "ae.h"
#include "anet.h"
#include "networking.h"
#include "descriptor.h"
#include "common_value.h"
#include "utili_base.h"
#include "libadns.h"
#include "dname.h"
#include "domain_hash.h"
#include "zonedb.h"
#include "zone.h"
#include "node.h"
#include "rrset.h"
#include "adns_counter.h"
#include "adns_share.h"
#include "iplib.h"
#include "errcode.h"
#include "adns.h"
#include "syslog.h"
#include "adns_stats.h"
#include "adns_types.h"
#include "mem_info.h"
#include "rcu.h"
#include "murmurhash3.h"
#include "private_route.h"
#include "ns_info.h"
#include "ring_list.h"
#include "dnssec.h"
#include "qps_limit.h"
#include "dnssec_cache.h"
#include "dnssec_cache_msg.h"

extern int sysctl_tcp_in_53_drop;
extern int sysctl_tcp_in_53_rate;
extern int sysctl_tcp_in_53_quota;
extern int sysctl_tcp_in_53_total_quota;
extern int sysctl_tcp_in_53_total_pps_quota;

extern size_t g_log_rotate_max_size;
extern uint32_t g_log_rotate_max_count;
extern struct adns_utili g_adns_utili;
extern adns_viewid_t g_view_max_num;
extern struct adns_view_map *g_view_map_tbl;

extern uint32_t g_domain_name_max_num[];
extern uint32_t g_domain_name_used_num[];
extern uint32_t g_zone_name_max_num[];
extern uint32_t g_zone_name_used_num[];
extern uint64_t g_zone_qps_quota;
extern uint64_t g_zone_bps_quota;
extern uint64_t g_domain_qps_quota;
extern uint64_t g_domain_bps_quota;
extern uint64_t g_time_interval;


uint64_t g_zone_bps_defense_quota;
uint64_t g_zone_qps_defense_quota;
uint64_t g_domain_bps_defense_quota;
uint64_t g_domain_qps_defense_quota;
uint64_t g_data_flush_sec;
uint64_t g_cycles_defense_sec;


extern adns_weight_t g_large_weight;
extern adns_dnssec_key **g_dnssec_ksk;

int g_init_done = 0;
int g_exit_now = 0;

uint32_t g_zone_num = 0;
uint32_t g_private_route_zone_num = 0;
uint32_t g_dnssec_zone_num = 0;
uint32_t g_domain_num = 0;
uint32_t g_rr_num = 0;
uint32_t g_rrset_memory_num = 0;
uint32_t g_rdata_ctl_num = 0;
uint32_t g_private_rdata_ctl_num = 0;

struct rr_detail_num_t g_rr_detail_num = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

//int g_adns_pkt_drop_counter[ADNS_PKT_DROP_COUNTER_MAX];
//int g_adns_pkt_rcode_counter[ADNS_RCODE_COUNTER_MAX];
int *g_adns_pkt_drop_counter;
int *g_adns_pkt_rcode_counter;

char *g_req_buf = NULL;
uint32_t g_req_len = 0;


static void master_add_zone(ioClient *c);
static void master_del_zone(ioClient *c);
static void master_edit_zone(ioClient *c);
static void master_list_zone(ioClient *c);

static void master_add_rr(ioClient *c);
static void master_edit_rr(ioClient *c);
static void master_del_rr(ioClient *c);
static void master_del_domain(ioClient *c);
static void master_del_domain_all(ioClient *c);
static void master_list_domain(ioClient *c);
static void master_list_schedule(ioClient *c);
static void master_schedule_mode(ioClient *c);
static void master_list_domain_qps(ioClient *c);

static void master_dump(ioClient *c);
static void master_batch(ioClient *c);
static void master_refresh_zone(ioClient *c);
static void master_refresh_domain(ioClient *c);
static void master_initload(ioClient *c);
static void master_get_info(ioClient *c);
static void master_get_dpdk_heap(ioClient *c);
static void master_status(ioClient *c);
static void master_stats(ioClient *c);
static void master_get_counter_value(ioClient *c);
static void master_get_rcode_stats(ioClient *c);
static void master_get_dev_stats(ioClient *c);
static void master_utili(ioClient *c);
static void master_clear(ioClient *c);
static void master_log(ioClient *c);
static void master_53(ioClient *c);

static void master_reload_iplib(ioClient *c);
static void master_reload_vm(ioClient *c);
static void master_reload_nslist(ioClient *c);
static void master_show_nslist(ioClient *c);
static void master_ip2view(ioClient *c);
static void master_lookup(ioClient *c);
static void master_quota(ioClient *c);
static void master_syslog(ioClient *c);
static void master_memory_info(ioClient *c);
static void master_set_cname_cascade(ioClient *c);
static void master_set_wildcard_fallback(ioClient *c);


static void master_set_dnssec(ioClient *c);
static void master_dnssec_add_key(ioClient *c);
static void master_dnssec_del_zsk(ioClient *c);
static void master_dnssec_add_dnskey_rrsig(ioClient *c);
static void master_dnssec_quota(ioClient *c);
static void master_dnssec_cache(ioClient *c);

static void master_add_route(ioClient *c);
static void master_del_route(ioClient *c);
static void master_reload_route(ioClient *c);
static void master_dump_route(ioClient *c);
static void master_tcpstats(ioClient *c);
static void master_exit(ioClient *c);

static struct adnsCommand adnsCommandTable[] = {
    {CMD_ADDZONE, "Add new zone", 0, master_add_zone},
    {CMD_DELZONE, "Delete specified zone", 0, master_del_zone},
    {CMD_EDITZONE, "Edit specified zone", 0, master_edit_zone},
    {CMD_LISTZONE, "List all zones", 0, master_list_zone},
    
    {CMD_ADDRR, "ADD a domain name to specified zone view", 0, master_add_rr},
    {CMD_EDITRR, "EDIT a rdata to specified domain and specified zone view", 0, master_edit_rr},
    {CMD_DELRR, "Delete a domain name from specified zone view", 0, master_del_rr},
    {CMD_DELDOMAIN, "Delete all rdata belong to specified domain", 0, master_del_domain},
    {CMD_DELDOMAIN_ALL, "Delete specified domain node in zone each view.", 0, master_del_domain_all},
    {CMD_LISTDOMAIN, "List all rrset in specified domain", 0, master_list_domain},
    {CMD_LISTSCHEDULE, "list schedule mode of domain', 0", 0,  master_list_schedule},
    {CMD_SCHEDULE_MODE, "set schedule mode all-rr or ratio", 0, master_schedule_mode},
    {CMD_LISTDOMAIN_QPS, "list domain qps", 0, master_list_domain_qps},
    
    {CMD_DUMP, "Dump all zone data", 0, master_dump},
    {CMD_BATCH, "Batch process", 0, master_batch},
    {CMD_REFRESH_ZONE, "Refresh zone", 0, master_refresh_zone},
    {CMD_REFRESH_DOMAIN, "Refresh domain", 0, master_refresh_domain},
    {CMD_INITLOAD, "Init adns server data", 0, master_initload},
    {CMD_SHOW, "Get adns info such as qps etc", 0, master_get_info},
    {CMD_SHOW_DPDK_HEAP, "Get dpdk heap memory information", 0, master_get_dpdk_heap},
    {CMD_STATUS, "Get adns server status", 0, master_status},
    {CMD_STATS, "Get adns statistics", 0, master_stats},
    {CMD_TCPSTATS, "Get adns statistics", 0, master_tcpstats},
    {CMD_COUNTER, "get the adns counter value", 0, master_get_counter_value},
    {CMD_RCODE_STATS, "get the rcode counter value", 0, master_get_rcode_stats},
    {CMD_PORT_STATS, "Get the dpdk port statistics", 0, master_get_dev_stats},
    {CMD_UTILI, "Get adns cpu/mem utilization", 0, master_utili},
    {CMD_CLEAR, "Clear all zone data", 0, master_clear},
    {CMD_LOG, "Control log switch", 0, master_log},
    {CMD_53, "Control sys53", 0, master_53},
    
    {CMD_RELOAD_IPLIB, "reload ip lib", 0, master_reload_iplib},
    {CMD_RELOAD_VM, "reload view map", 0, master_reload_vm},
    {CMD_RELOAD_NSLIST, "reload default NS list", 0, master_reload_nslist},
    {CMD_SHOW_NSLIST, "show default NS list", 0, master_show_nslist},
    {CMD_IP2VIEW, "ip locat to view", 0, master_ip2view},
    {CMD_IPV62VIEW, "ipv6 locat to view", 0, master_ip2view},
    {CMD_LOOKUP, "look up zone or domain whether exsit", 0, master_lookup},    
    {CMD_QUOTA, "config zone qps bps quota time interval", 0, master_quota},
    {CMD_SYSLOG, "get and set syslog related configuration", 0, master_syslog},
    {CMD_MEMORY_INFO, "get dpdk memory information", 0, master_memory_info},
    {CMD_SET_CNAME_CASCADE, "set cname cascade", 0, master_set_cname_cascade},
    {CMD_SET_WILDCARD_FALLBACK, "set wildcard fallback", 0, master_set_wildcard_fallback},


    {CMD_ADDROUTE, "add private route for a zone", 0, master_add_route},
    {CMD_DELROUTE, "delete private route for a zone", 0, master_del_route},
    {CMD_RELOADROUTE, "reload private route for a zone", 0, master_reload_route},
    {CMD_DUMPROUTE, "dump private route for a zone", 0, master_dump_route},

    {CMD_SET_DNSSEC, "set DNSSEC", 0, master_set_dnssec},
    {CMD_DNSSEC_ADD_KEY, "add new dnssec key", 0, master_dnssec_add_key},
    {CMD_DNSSEC_DEL_ZSK, "delete ZSK by key tag", 0, master_dnssec_del_zsk},
    {CMD_DNSSEC_ADD_DNSKEY_RRSIG, "add dnskey rrsig", 0, master_dnssec_add_dnskey_rrsig},
    {CMD_DNSSEC_QUOTA, "DNSSEC quota", 0, master_dnssec_quota},
    {CMD_DNSSEC_CACHE, "DNSSEC cache", 0, master_dnssec_cache},
    {CMD_QUIT, "quit the running ADNS", 0, master_exit},
};

void cmd_set_err(char *str, const char *fmt, ...)
{
    va_list ap;

    if (str == NULL) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(str, CMD_RESP_ERR_LEN, fmt, ap);
    va_end(ap);
}

/**
 * Append error msg to err_collected buf
 *
 * @return
 *   - >=0: appending bytes number;
 *   - -1: appending failed, buffer avaiable length not enough
 */
static int init_load_append_err(char * error_collected, int avail_len, char * prev_err_zone,
                                char * cur_zone, char * fmt, ...)
{
    int est_len = 0;
    va_list args1, args2;
    int ret = 0;

    if (error_collected == NULL || avail_len <= 0) {
        return -1;
    }

    if (strcmp(prev_err_zone, cur_zone) != 0) {

        va_start(args1, fmt);
        va_copy(args2, args1);
        est_len = vsnprintf(NULL, 0, fmt, args1);
        va_end(args1);

        if (est_len > avail_len) {
            ret = -1;
        }
        else {
            ret = vsnprintf(error_collected, avail_len, fmt, args2);
        }
        va_end(args2);

        strcpy(prev_err_zone, cur_zone);
    }

    return ret;
}

inline adns_dname_t * adns_dname_lastlabel(const adns_dname_t *name)
{
    adns_dname_t *prev = NULL;
    if (name == NULL)
        return prev;

    while (*name != '\0') {
        prev = name;
        name = adns_wire_next_label(name);
        if (!name)
            return prev;
    }
    return prev;
}

/* Admin Cmd Function */
/*
 * Add a zone into zonedb, or construct a dangled new zone struct
 *
 * @zonedb: when not NULL, try to add the new zone into zonedb
 *          when NULL, only contruct the zone struct without adding it to the zonedb *
 * @zone_addded: is used when zonedb == NULL, to get the constructed zone
 */
int __add_zone(struct adns_zonedb *zonedb, const char *name, uint8_t *rdata, int rdata_len,
        uint32_t ttl, uint8_t enable_cname_cascade, struct adns_zone **zone_added, char *err)
{
    int ret;
    adns_dname_t *add_name;
    struct adns_zone *add_zone = NULL;
    int socket_id = 0;

    add_name = adns_dname_from_str(name, strlen(name));
    if (add_name == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_ADD_ZONE_CONVERT_ZONE_ERROR;
    }

    if (zonedb != NULL) {
        add_zone = adns_zonedb_lookup_exact(zonedb, add_name);
        if (NULL != add_zone) {
            adns_dname_free(&add_name);
            cmd_set_err(err, "[%s]: Zone %s already existed\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Zone %s already existed\n", __FUNCTION__, name);
            return 0;
        }
    }
    else {
        if (zone_added == NULL) {
            adns_dname_free(&add_name);
            cmd_set_err(err, "[%s]: Failed to construct the new zone, NULL zone pointer\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to construct the  new zone, NULL zone pointer\n", __FUNCTION__);
            return -1;
        }
    }

    add_zone = adns_zone_new(socket_id, add_name);
    if (add_zone == NULL) {
        adns_dname_free(&add_name);
        cmd_set_err(err, "[%s]: Failed to alloc zone: %s, g_zone_num = %d\n", __FUNCTION__, name, g_zone_num);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to alloc zone: %s, g_zone_num = %d\n", __FUNCTION__, name, g_zone_num);
        return ADNS_ADMIN_ADD_ZONE_ALLOC_ERROR;
    }

    adns_dname_free(&add_name);

    /* set zone SOA */
    add_zone->soa.type = ADNS_RRTYPE_SOA;
    add_zone->soa.rclass = ADNS_CLASS_IN;
    add_zone->soa.ttl = ttl;
    add_zone->soa.len = rdata_len;
    #if ZONE_CNT
    add_zone->counter_id = todo_forzone_adns_counter_get();
    adns_counter_init_value(add_zone->counter_id);
    #endif
    add_zone->enable_cname_cascade = enable_cname_cascade;

    if (add_zone->soa.len > ADNS_SOA_RRLEN) {
        adns_zone_free(add_zone);
        cmd_set_err(err, "[%s]: Failed to add zone: %s, zone->soa.len = %d\n", __FUNCTION__, name, add_zone->soa.len);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to add zone: %s, zone->soa.len = %d\n", __FUNCTION__, name, add_zone->soa.len);
        return ADNS_ADMIN_ADD_ZONE_LENGTH_ERROR;
    }
    memcpy(add_zone->soa.data, rdata, rdata_len);

    if (zonedb != NULL) {
        ret = adns_zonedb_add_zone(zonedb, add_zone);
        if (ret < 0) {
            adns_zone_free(add_zone);
            cmd_set_err(err, "[%s]: Failed add zone %s to zone database, ret = %d\n", __FUNCTION__, name, ret);
            log_server_warn(rte_lcore_id(), "[%s]: Failed add zone %s to zone database, ret = %d\n", __FUNCTION__, name, ret);
            return ADNS_ADMIN_ADD_ZONE_TO_ZONEDB_ERROR;
        }
    }

    if (zone_added != NULL) {
        *zone_added = add_zone;
    }
    return 0;
}


static void master_add_zone(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_ADDZONE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __add_zone(g_datacore_db, ce->zone, (uint8_t *)ce->rdata, ce->rdata_len,
                        ce->ttl, ce->type, NULL, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm -A --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return; 
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -A --zone %s, SUCCESS\n", ce->zone);
    return;    
}


int __del_zone(struct adns_zonedb *zonedb, char *name, char *err)
{
    int ret;
    adns_dname_t *zone_dname;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(name, strlen(name));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_DEL_ZONE_CONVERT_ZONE_ERROR;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (NULL == zone) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        return 0;
    }

    ret = adns_zonedb_del_zone(zonedb, zone_dname);
    if (ret < 0) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Failed to delete zone: %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to delete zone: %s, ret = %d\n", __FUNCTION__, name, ret);
        return ADNS_ADMIN_DEL_ZONE_ERROR;
    }
    
    typedef void (*pfn) (void *);
    ret = call_rcu( (pfn)adns_zone_free, zone);
    if (ret < 0) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: fail to register rcu event\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s] register rcu event, ret = %d, FAILURE\n", __FUNCTION__);
        adns_zonedb_add_zone(zonedb, zone);
        return ADNS_ADMIN_DEL_ZONE_RCU_REGISTER_ERROR;
    }

    adns_dname_free(&zone_dname);
    
    return 0;
}


static void master_del_zone(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DELZONE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __del_zone(g_datacore_db, ce->zone, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm -D --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return;
    }
    
    cmd_resp->ret_val = 0; 
    log_server_warn(rte_lcore_id(), "adns_adm -D --zone %s, SUCCESS\n", ce->zone); 
}

                       
static int __edit_zone(struct adns_zonedb *zonedb, char *name, uint8_t *rdata,
        int rdata_len, uint32_t ttl, char *err)
{
    adns_dname_t *zone_name;
    struct adns_zone *zone;

    zone_name = adns_dname_from_str(name, strlen(name));
    if (zone_name == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_EDIT_ZONE_CONVERT_ZONE_ERROR;
    }

    zone = adns_zonedb_lookup_exact(zonedb, zone_name);
    if (zone == NULL) {
        adns_dname_free(&zone_name);
        cmd_set_err(err, "[%s]: Zone %s does not exist\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not exist\n", __FUNCTION__, name);
        return ADNS_ADMIN_EDIT_ZONE_NOT_FOUND_ERROR;
    }

    if (rdata_len > ADNS_SOA_RRLEN) {
        adns_dname_free(&zone_name);
        cmd_set_err(err, "[%s]: Failed to edit zone: %s, rdata_len = %d\n", __FUNCTION__, name, rdata_len);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to edit zone: %s, rdata_len = %d\n", __FUNCTION__, name, rdata_len);
        return ADNS_ADMIN_EDIT_ZONE_LENGTH_ERROR;
    }
    zone->soa.ttl = ttl;
    zone->soa.len = rdata_len;
    memcpy(zone->soa.data, rdata, rdata_len);

    adns_dname_free(&zone_name);
    return 0;
}


static void master_edit_zone(ioClient *c)
{
    int ret;   
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_EDITZONE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    
    ret = __edit_zone(g_datacore_db, ce->zone, (uint8_t *)ce->rdata, ce->rdata_len, ce->ttl, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm -E --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return;
    }
       
    cmd_resp->ret_val = 0; 
    log_server_warn(rte_lcore_id(), "adns_adm -E --zone %s, SUCCESS\n", ce->zone); 
}


static int adns_zone_txt_put(char *str, char *buf, unsigned int maxlen)
{
    int len;

    if (str == NULL) {
        return -1;
    }

    if (strlen(str) + 2 >= maxlen) {
        return -2;
    }

    len = snprintf(buf, maxlen, "%s", str);
    buf[len++] = '\t';
    buf[len] = '\0';

    return len;
}


static void master_list_zone(ioClient *c)
{
    int i, zone_count, zone_count_before, maxlen, ret; 
    char *buf, *name;
    struct adns_zone **zone_array;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
       
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_LISTZONE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    
    maxlen = ADNS_ADM_MAX_REPLY_LEN - c->buf_size;
    buf = (char *)(c->buf + 2 + sizeof(struct cmd_resp));
    
    zone_count_before = g_datacore_db->zone_count;
    zone_array = adns_zonedb_list(g_datacore_db);    
    if (zone_array == NULL) {
        ret = ADNS_ADMIN_LIST_ZONE_ALLOC_ERROR;
        goto err;     
    }
    
    zone_count = g_datacore_db->zone_count;
    if (zone_count != zone_count_before) {
        cmd_set_err(cmd_resp->err_msg, "[%s]: Zones changed, before = %d, after = %d\n", __FUNCTION__, zone_count_before, zone_count);
        log_server_warn(rte_lcore_id(), "[%s]: Zones changed, before = %d, after = %d\n", __FUNCTION__, zone_count_before, zone_count);
        ret = ADNS_ADMIN_LIST_ZONE_CHANGE_ERROR;
        goto err;
    }

    for (i = 0; i < zone_count; i++) {
        if (zone_array[i] == NULL) {
            cmd_set_err(cmd_resp->err_msg, "[%s]: Zones changed\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s]: Zones changed\n", __FUNCTION__);
            ret = ADNS_ADMIN_LIST_ZONE_CHANGE_ERROR;
            goto err;
        }

        name = adns_dname_to_str(zone_array[i]->name);
        ret = adns_zone_txt_put(name, buf, maxlen);
        free(name);
        if (ret < 0) {
            cmd_set_err(cmd_resp->err_msg, "[%s]: The sum of the zones length exceeded the max\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s]: The sum of the zones length exceeded the max, ret = %d\n", __FUNCTION__, ret);
            ret = ADNS_ADMIN_LIST_ZONE_MEMORY_LACK_ERROR;
            goto err; 
        }

        buf += ret;
        maxlen -= ret;
        c->buf_size += ret;
    }
    free(zone_array);
    *len = htons(c->buf_size - 2);
    
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -L, SUCCESS\n");
    return;
    
err:
    if (zone_array != NULL) {
        free(zone_array); 
    }
    
    *len = htons(sizeof(struct cmd_resp));
    c->buf_size = 2 + sizeof(struct cmd_resp);
    cmd_resp->ret_val = ret;
    log_server_warn(rte_lcore_id(), "adns_adm -L, ret = %d, FAILURE\n", cmd_resp->ret_val);
    return;
}


/* RR */
static struct adns_node *create_node(struct adns_zone *zone, adns_dname_t *dname, adns_viewid_t view_id)
{
    int ret;
    struct adns_node *node;

    node = adns_node_new(dname);
    if (node == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: adns_node_new failed\n", __FUNCTION__);
        return NULL;
    }

    ret = adns_zone_add_node(zone, node, view_id);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: adns_zone_add_node failed, ret = %d\n", __FUNCTION__, ret);
        adns_domain_delete_hash(node);
        adns_node_free(node);
        return NULL;
    }

    return node;
}

/*
 * setup a node's attributes
 * no affecting parent node or the zone it belongs to
 */
int adns_node_add_rr(struct adns_node *node, const char *domain, uint8_t custom_view, adns_viewid_t view_id, uint16_t type, uint32_t ttl,
        const char *rdata, int rdata_len, int weight, const char *original_rdata, char *err, uint8_t zone_apex) {
    int ret, __weight;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL, *ns_rrset = NULL;
    struct adns_ns_list_elem* ns = NULL;
    uint32_t ns_group_id;
    char *ns_str;

    if (custom_view && view_id >= g_private_route_per_zone_max_num) {
        cmd_set_err(err, "[%s]: custom view ID %d exceed limit\n", __FUNCTION__, view_id);
        log_server_warn(rte_lcore_id(),"[%s]: custom view ID %d exceed limit\n", __FUNCTION__, view_id);
        return ADNS_ADMIN_ADD_RR_NEW_RDATA_CTL_ERROR;
    }

    ret = adns_node_check_type(type);
    if (ret < 0) {
        cmd_set_err(err, "[%s]: Error rr type %d\n", __FUNCTION__, type);
        log_server_warn(rte_lcore_id(),"[%s]: Error rr type %d\n", __FUNCTION__, type);
        return ADNS_ADMIN_ADD_RR_TYPE_ERROR;
    }

    rrset = adns_node_get_rrset(node, type);
    if (rrset == NULL) {
        /* The first time add rr to a new rrset */
        /* handle default NS process only if add zone apex NS to default view */
        if (zone_apex == 1 && type == ADNS_RRTYPE_NS && custom_view == 0 && view_id == 0) {
            ns = ns_list_lookup(g_ns_tbl, (uint8_t *)rdata, (uint8_t)rdata_len, ttl);
            /* If the NS to be added match the default NS group */
            if (ns != NULL) {
                ns_group_id = ns->ns_group_id;
                ns_rrset = g_ns_rrsets[ns_group_id];
                /* set the default NS rrset pointer */
                if (adns_node_set_rrset(node, ADNS_RRTYPE_NS, ns_rrset)) {
                    cmd_set_err(err, "[%s]: Failed to set default NS rrset, node %s, type %d\n", __FUNCTION__, domain, type);
                    log_server_warn(rte_lcore_id(), "[%s]: Failed set default NS rrset, node %s, type %d\n", __FUNCTION__, domain, type);
                    return ADNS_ADMIN_ADD_RR_SET_RRSET_ERROR;
                }
                /* increment the default ns rrset reference count */
                ns_rrset->ref_count ++;
                SET_TAG(node->node_tag, 0);
                return 0;
            }
        }
        rrset = adns_rrset_new(type, ADNS_CLASS_IN, ttl);
        if (rrset == NULL) {
            cmd_set_err(err, "[%s]: Failed to new rrset, node %s, type %d\n", __FUNCTION__, domain, type);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to new rrset, node %s, type %d\n", __FUNCTION__, domain, type);
            return ADNS_ADMIN_ADD_RR_NEW_RRSET_ERROR;
        }

        ret = adns_node_set_rrset(node, type, rrset);
        if (ret < 0) {
            cmd_set_err(err, "[%s]: Failed to set rrset, node %s, type %d\n", __FUNCTION__, domain, type);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to set rrset, node %s, type %d, ret = %d\n", __FUNCTION__, domain, type, ret);
            return ADNS_ADMIN_ADD_RR_SET_RRSET_ERROR;
        }
    }
    /* add rr to existing rrset */
    /* handle default NS process only if add NS to default view */
    if (zone_apex == 1 && rrset->default_ns == 1 && type == ADNS_RRTYPE_NS) {
        struct list_head *h_list;
        struct adns_rdata *elem, *elem_next;

        ns = ns_list_lookup(g_ns_tbl, (uint8_t *)rdata, (uint8_t)rdata_len, ttl);
        /* If the NS to be added match the default NS group and is added to default view */
        if (ns != NULL && custom_view == 0 && view_id == 0) {
            ns_group_id = ns->ns_group_id;
            ns_rrset = g_ns_rrsets[ns_group_id];
            /* The same NS group */ 
            if (ns_rrset == rrset) {
                /* check if rr to be added exist in the rrset */
                h_list = &(rrset->default_rdata.list);
                list_for_each_entry_safe(elem, elem_next, h_list, list) {
                    if ((elem->len == rdata_len)
                        && (!memcmp(elem->data, rdata, rdata_len))) {
                        /* set node tag */
                        SET_TAG(node->node_tag, 0);
                        return 0;
                    }
                }
                cmd_set_err(err, "[%s]: NS to be added not exist in NS rrset, node %s, type %d\n", __FUNCTION__, domain, type);
                log_server_warn(rte_lcore_id(), "[%s]: NS to be added not exist in NS rrset, node %s, type %d\n", __FUNCTION__, domain, type);
                return ADNS_ADMIN_ADD_RR_SET_RRSET_ERROR;
            }
            /* add mutiple NS groups */
        }
        /* the NS to be added not match the default NS group or add rr to non-default view */
        /* If the NS to be add matches another default NS group or not match any default NS group, create a new non-default NS rrset
           copy the NS rdata from the matched default NS group to the new NS rrset */
        /* create a new rrset */
        ns_rrset = adns_rrset_new(type, ADNS_CLASS_IN, ttl);
        if (ns_rrset == NULL) {
            cmd_set_err(err, "[%s]: Failed to new rrset, node %s, type %d\n", __FUNCTION__, domain, type);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to new rrset, node %s, type %d\n", __FUNCTION__, domain, type);
            return ADNS_ADMIN_ADD_RR_NEW_RRSET_ERROR;
        }
        /* copy the default NS rdata to the new rrset */
        h_list = &(rrset->default_rdata.list);
        list_for_each_entry_safe(elem, elem_next, h_list, list) {
            ns_str = adns_dname_to_str(elem->data);
            if (adns_rrset_add_rdata(&(ns_rrset->default_rdata), elem->data, elem->len, elem->cw, ns_str, ADNS_RRTYPE_NS)) {
                adns_rrset_deep_free(ns_rrset);
                free(ns_str);
                cmd_set_err(err, "[%s]: Failed to merge default NS rrset, node %s, type %d\n", __FUNCTION__, domain, type);
                log_server_warn(rte_lcore_id(), "[%s]: Failed to merge default NS rrset, node %s, type %d\n", __FUNCTION__, domain, type);
                return ADNS_ADMIN_ADD_RR_NEW_RDATA_CTL_ERROR;
            }
            free(ns_str);
        }
        /* set the new rrset to the domain node */
        if (adns_node_set_rrset(node, ADNS_RRTYPE_NS, ns_rrset)) {
            cmd_set_err(err, "[%s]: Failed to set new NS rrset, node %s, type %d\n", __FUNCTION__, domain, type);
            log_server_warn(rte_lcore_id(), "[%s]: Failed set new NS rrset, node %s, type %d\n", __FUNCTION__, domain, type);
            adns_rrset_deep_free(ns_rrset);
            return ADNS_ADMIN_ADD_RR_SET_RRSET_ERROR;
        }
        /* decrease the default ns rrset reference count */
        rrset->ref_count --;
        /* replace rrset pointer */
        rrset = ns_rrset;
    }

    if (custom_view) {
        rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
        if (rdata_ctl == NULL) {
            rdata_ctl = adns_rrset_new_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id); 
        }
    }
    else {
        rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
        if (rdata_ctl == NULL) {
            rdata_ctl = adns_rrset_new_rdata_ctl(rrset, view_id); 
        }
    }
    if (rdata_ctl == NULL) {
        cmd_set_err(err, "[%s]: Failed to new rdata_ctl, node %s, type %d, %sview %d\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to new rdata_ctl, node %s, type %d, %sview %d\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        return ADNS_ADMIN_ADD_RR_NEW_RDATA_CTL_ERROR;
    }
    
    if (weight >= 0) {
        __weight = weight;
    } else {
        __weight = 1;
    }

    ret = adns_rrset_add_rdata(rdata_ctl, (const uint8_t *)rdata, rdata_len, __weight, original_rdata, type);
    if (ret < 0) {
        cmd_set_err(err, "[%s]: Failed to add rdata to rrset %s, node %s, type %d, %sview %d\n", __FUNCTION__, original_rdata, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to add data to rrset %s, node %s, type %d, %sview %d, ret = %d\n", __FUNCTION__, original_rdata, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id, ret);
        return ADNS_ADMIN_ADD_RR_ADD_RDATA_ERROR;
    }

    // Uses the TTL of last RR as the whole RRSET's TTL.
    rrset->ttl = ttl;

    SET_TAG(node->node_tag, custom_view? view_id + g_view_max_num : view_id);

    return 0;
}

int adns_zone_get_node(struct adns_zone *zone, const char *domain, struct adns_node **p_node, char *err)
{
    adns_dname_t *dname = NULL;

    if (zone == NULL || domain == NULL || p_node == NULL) {
        cmd_set_err(err, "[%s]: NULL pointer is passed in.\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: NULL pointer is passed in.\n", __FUNCTION__);
        return -1;
    }

    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        return -2;
    }
    *p_node = adns_zone_lookup_node(zone, dname);
    adns_dname_free(&dname);
    if( *p_node == NULL) {
        return -3;
    }

    return 0;
}

int adns_zone_add_rr(struct adns_zone *zone, const char *domain, uint8_t custom_view, adns_viewid_t view_id, uint16_t type, uint32_t ttl,
        char *rdata, int rdata_len, int weight, const char *original_rdata, char *err, struct adns_node ** p_node)
{
    int ret;
    adns_dname_t *dname = NULL;
    struct adns_node *node = NULL;
    adns_viewid_t m_view_id;
    uint8_t zone_apex = 0;

    if (zone == NULL || original_rdata == NULL) {
        cmd_set_err(err, "[%s]: NULL pointer is passed in.\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(),"[%s]: NULL pointer is passed in, FAILURE\n", __FUNCTION__);
        return ADNS_ADMIN_ADD_RR_INTERNAL_ERROR;
    }

    if (custom_view && view_id >= g_private_route_per_zone_max_num) {
        cmd_set_err(err, "[%s]: custom view ID %d exceed limit\n", __FUNCTION__, view_id);
        log_server_warn(rte_lcore_id(),"[%s]: custom view ID %d exceed limit\n", __FUNCTION__, view_id);
        return ADNS_ADMIN_ADD_RR_NEW_RDATA_CTL_ERROR;
    }
    m_view_id = custom_view? view_id + g_view_max_num : view_id;

    if (*p_node == NULL) {
        dname = adns_dname_from_str(domain, strlen(domain));
        if (dname == NULL) {
            cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s, FAILURE\n", __FUNCTION__, domain);
            return ADNS_ADMIN_ADD_RR_DOMAIN_ERROR;
        }
        /* if the rr is to be added to custom view, should add view_id by g_view_max_num to handle wild_tag and node_tag */
        node = adns_domain_hash_lookup(zone, dname);
        if (node == NULL) {
            node = create_node(zone, dname, m_view_id);
            if (node == NULL) {
                adns_domain_delete_hash(node);
                adns_node_free(node);
                cmd_set_err(err, "[%s]: Failed to create node %s, g_domain_num = %d\n", __FUNCTION__, domain, g_domain_num);
                log_server_warn(rte_lcore_id(), "[%s]: Failed to create node %s, g_domain_num = %d, FAILURE\n", __FUNCTION__, domain, g_domain_num);
                return ADNS_ADMIN_ADD_RR_CREATE_NODE_ERROR;
            }
        }
        adns_dname_free(&dname);
        *p_node = node;
    }
    else {
        node = *p_node;
    }

    /* if the domain name equals to the zone name, the domain is zone apex */
    if (node->name_len == zone->name_len) {
        zone_apex = 1;
    }

    /* the zone/parent_node irrelevant part of jobs for adding a rr, extracting it for reusing in refresDomain */
    ret = adns_node_add_rr(node, domain, custom_view, view_id, type, ttl, rdata, rdata_len, weight, original_rdata, err, zone_apex);
    if (ret < 0) {
        return ret;
    }

    /* the zone/parent_node relevant part of jobs for adding a rr*/
    if (node->parent) {
        SET_TAG(node->parent->node_tag, m_view_id);
    }
    if (adns_dname_is_wildcard(node->name) ||
       ((type == ADNS_RRTYPE_NS) && (zone->name_len != node->name_len))) {
        /* CAUTION: wild_tag also includes NS record. node contains a NS record is also counted as parent node. */
        zone->wild_tag[m_view_id >> ADNS_8_LOG2] |= 1 << (m_view_id & ADNS_8_MAC);
    }

    return 0;
}

int __add_rr(struct adns_zonedb *zonedb, const char *zone_str, const char *domain, uint8_t custom_view, adns_viewid_t view_id, uint16_t type, uint32_t ttl, char *rdata,
        int rdata_len, int weight, char *original_rdata, char *err)
{
    struct adns_zone * zone = NULL;
    struct adns_node * node = NULL;

    if (adns_zonedb_get_zone(g_datacore_db, zone_str, &zone, err) < 0 || zone == NULL) {
        return ADNS_ADMIN_ADD_RR_FIND_ZONE_ERROR;
    }

    return adns_zone_add_rr(zone, domain, custom_view, view_id, type, ttl, rdata, rdata_len, weight, original_rdata, err, &node);
}


static void master_add_rr(ioClient *c)
{
    int ret;   
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_ADDRR;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    ret = __add_rr(g_datacore_db, ce->zone, ce->domain, ce->custom_view, ce->view_id, ce->type,
            ce->ttl, ce->rdata, ce->rdata_len, ce->weight, ce->original_rdata, cmd_resp->err_msg);
    if(ret < 0){
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm -a --zone %s --domain %s %s %d --ttl %d --type %d -r \"%s\" -w %d, ret = %d, FAILURE\n",
                                     ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->ttl, ce->type, ce->original_rdata, ce->weight, cmd_resp->ret_val);
        return;
    }
    
    cmd_resp->ret_val = 0;

    log_server_warn(rte_lcore_id(), "adns_adm -a --zone %s --domain %s %s %d --ttl %d --type %d -r \"%s\" -w %d, SUCCESS\n",
                                     ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->ttl, ce->type, ce->original_rdata, ce->weight);
}


int __edit_rr(struct adns_zonedb *zonedb, char *zone_str, char *domain, uint8_t custom_view, adns_viewid_t view_id,
        uint16_t type, uint32_t ttl, char *rdata,
        int rdata_len, int weight, char *original_rdata, char *err, int set_ttl)
{
    int ret, __weight;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;
    struct adns_node *node = NULL;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        return ADNS_ADMIN_EDIT_RR_CONVERT_ZONE_ERROR;
    }

    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        cmd_set_err(err, "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str);
        ret = ADNS_ADMIN_EDIT_RR_FIND_ZONE_ERROR;
        goto err_zone;
    }

    ret = adns_node_check_type(type);
    if (ret < 0) {
        ret = ADNS_ADMIN_EDIT_RR_TYPE_ERROR;
        goto err_type;
    }

    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        ret = ADNS_ADMIN_EDIT_RR_DOMAIN_ERROR;
        goto err_dname;
    }

    node = adns_domain_hash_lookup(zone, dname);
    if (node == NULL) {
        cmd_set_err(err, "[%s]: Node %s does not exist\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Node %s does not exist\n", __FUNCTION__, domain);
        ret = ADNS_ADMIN_EDIT_RR_FIND_NODE_ERROR;
        goto err_node;
    }

    rrset = adns_node_get_rrset(node, type);
    if (rrset == NULL) {
        cmd_set_err(err, "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain, type);
        log_server_warn(rte_lcore_id(), "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain, type);
        ret = ADNS_ADMIN_EDIT_RR_GET_RRSET_ERROR;
        goto err_rrset;
    }

    if (custom_view) {
        rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
    }
    else {
        rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
    }
    if (rdata_ctl == NULL) {
        cmd_set_err(err, "[%s]: Rdata_ctl of node %s(type = %d, %sview_id = %d) does not exist\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Rdata_ctl of node %s(type = %d, %sview_id = %d) does not exist\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        ret = ADNS_ADMIN_EDIT_RR_GET_RDATA_CTL_ERROR;
        goto err_rdata_ctl;
    }

    if (weight >= 0) {
        __weight = weight;
    } else {
        __weight = 1;
    }

    ret = adns_rrset_edit_rdata(rdata_ctl, (uint8_t *)rdata, rdata_len, __weight, original_rdata);
    if (ret < 0) {
        cmd_set_err(err, "[%s]: Failed to edit rdata to rrset %s, node %s, type %d, %sview %d\n", __FUNCTION__, original_rdata, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to edit data to rrset %s, node %s, type %d, %sview %d, ret = %d\n", __FUNCTION__, original_rdata, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id, ret);
        ret = ADNS_ADMIN_EDIT_RR_MODIFY_RDATA_ERROR;
        goto err_rdata;
    }

    if (set_ttl)
        rrset->ttl = ttl;
    adns_dname_free(&dname);
    adns_dname_free(&zone_dname);

    return 0;

err_node:
err_rrset:
err_rdata_ctl:
err_rdata:
    adns_dname_free(&dname);

err_zone:
err_type:
err_dname:
    adns_dname_free(&zone_dname);
    return ret;
}


static void master_edit_rr(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_ADDRR;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    ret = __edit_rr(g_datacore_db, ce->zone, ce->domain, ce->custom_view, ce->view_id, ce->type,
            ce->ttl, ce->rdata, ce->rdata_len, ce->weight, ce->original_rdata, cmd_resp->err_msg, 1);
    if(ret < 0){
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm -e --zone %s --domain %s %s %d --ttl %d --type %d -r \"%s\" -w %d, ret = %d, FAILURE\n",
                                     ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->ttl, ce->type, ce->original_rdata, ce->weight, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;

    log_server_warn(rte_lcore_id(), "adns_adm -e --zone %s --domain %s %s %d --ttl %d --type %d -r \"%s\" -w %d, SUCCESS\n",
                                     ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->ttl, ce->type, ce->original_rdata, ce->weight);
}

static void node_update_tag(struct adns_node *node, uint8_t custom_view, adns_viewid_t view_id)
{
    int i, flag;
    adns_viewid_t m_view_id;
    int ret = 0;

    if (node == NULL) {
        return;  
    }

    if (custom_view && view_id >= g_private_route_per_zone_max_num) {
        return;
    }

    m_view_id = custom_view? view_id + g_view_max_num : view_id;
   
    //called only when delete an rr of delete a domain's view
    //if the current node is normal node, or a parent, whose child is empty in that view
    //update the current node
    //update the current node's parent, so that the node_tag of node's parent is ensured synchronized
    if ((node->wildcard_child == NULL) || (GET_TAG(node->wildcard_child->node_tag, m_view_id) == 0)){
        flag = 0;
        for (i = 0; i < ADNS_RRSET_NUM; i++) {
            if (custom_view) {
                ret = adns_rrset_check_rdata_exist_in_private_route(node->rrsets[i], (adns_private_route_id_t)view_id);
            }
            else {
                ret = adns_rrset_check_rdata_exist_in_view(node->rrsets[i], view_id);
            }
            if (ret != 0) {
                flag = 1;
                return; 
            }
        }
        
        if (flag == 0) {
            CLR_TAG(node->node_tag, m_view_id);
        } 
        
        if (node->parent != NULL) {
          
            flag = 0;
            for (i = 0; i < ADNS_RRSET_NUM; i++) {
                if (custom_view) {
                    ret = adns_rrset_check_rdata_exist_in_private_route(node->parent->rrsets[i], (adns_private_route_id_t)view_id);
                }
                else {
                    ret = adns_rrset_check_rdata_exist_in_view(node->parent->rrsets[i], view_id);
                }
                if ( ret != 0) {
                    flag = 1;
                    return; 
                }
            }
            
            if (flag == 0) {
                CLR_TAG(node->parent->node_tag, m_view_id);
            }                                     
        }
    }   
}

int __del_rr(struct adns_zonedb *zonedb, const char *zone_str, const char *domain, 
        uint8_t custom_view, adns_viewid_t view_id,
        uint16_t type, char *rdata, int rdata_len, const char *original_rdata, char *err)
{
    int ret, i, rdata_exist_flag, node_is_empty = true;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;
    struct adns_node *node = NULL;
    struct adns_zone *zone = NULL;

    struct list_head *h_list;
    struct adns_rdata *elem, *elem_next;

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "%s: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        return 0;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s(node %s) does not exist\n", __FUNCTION__, zone_str, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s(node %s) does not exist\n", __FUNCTION__, zone_str, domain); 
        return 0;
    }
        
    ret = adns_node_check_type(type);
    if (ret < 0) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s(node %s), type %d does not exist\n", __FUNCTION__, zone_str, domain, type);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s(node %s) type %d, does not exist\n", __FUNCTION__, zone_str, domain, type); 
        return 0;
    }

    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        return 0;
    }
    
    node = adns_domain_hash_lookup(zone, dname); 
    if (node == NULL) {
        adns_dname_free(&zone_dname);
        adns_dname_free(&dname);
        cmd_set_err(err, "[%s]: Node %s does not exist\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Node %s does not exist\n", __FUNCTION__, domain); 
        return 0; 
    }
        
    rrset = adns_node_get_rrset(node, type); 
    if (rrset == NULL) {
        adns_dname_free(&zone_dname);
        adns_dname_free(&dname);
        cmd_set_err(err, "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain, type);
        log_server_warn(rte_lcore_id(), "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain, type); 
        return 0;  
    }

    /* rrset is the default NS rrset, and rr to be deleted is NS */
    /* handle default NS process only if delete NS from default view */
    if (rrset->default_ns == 1 && type == ADNS_RRTYPE_NS && custom_view == 0 && view_id == 0) {
        rdata_ctl = &(rrset->default_rdata);
        h_list = &(rdata_ctl->list);
        list_for_each_entry_safe(elem, elem_next, h_list, list) {
            if ((elem->len == rdata_len)
                && (!memcmp(elem->data, rdata, rdata_len))) {
                /* NS rr to be deleted exist in the default NS rrset */
                /* set the whole default NS rrset non available */
                adns_node_set_rrset(node, ADNS_RRTYPE_NS, NULL);
                /* decrease the default NS rrset ref count */
                rrset->ref_count --;
                /* update node tag */
                node_update_tag(node, 0, 0);
                rdata_exist_flag = 1;
                goto CLEAR_RRSET_TTL;
            }
        }
        /* NS rr to be deleted not exist in the default NS rrset */
        adns_dname_free(&zone_dname);
        adns_dname_free(&dname);
        cmd_set_err(err, "[%s]: RR not exist in default NS RRset\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: RR not exist in default NS RRset\n", __FUNCTION__); 
        return 0;
    }
    
    if (custom_view) {
        rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
    }
    else {
        rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
    }
    if (rdata_ctl == NULL) {
        adns_dname_free(&zone_dname);                                                                             
        adns_dname_free(&dname);
        cmd_set_err(err, "[%s]: Rdata_ctl of node %s(type = %d, %sview_id = %d) does not exist\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Rdata_ctl of node %s(type = %d, %sview_id = %d) does not exist\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id); 
        return 0; 
    }
    
    
    adns_rrset_del_rdata(rdata_ctl, rdata, rdata_len, original_rdata, type);
    node_update_tag(node, custom_view, view_id);

    /* modify the rrset->ttl */
    rdata_exist_flag = 0;
    if (rrset->default_rdata.rdata_count != 0) {
        rdata_exist_flag = 1;
        goto CLEAR_RRSET_TTL;
    }
    if (rrset->ctl_rdata) {
        for (i = 0; i < g_view_max_num; i++) {
            rdata_ctl = adns_rrset_get_rdata_ctl(rrset, i);
            if (rdata_ctl == NULL) {
                continue;
            }

            if (rdata_ctl->rdata_count != 0) {
                rdata_exist_flag = 1;
                goto CLEAR_RRSET_TTL;
            }
        }
    }
    if (rrset->private_ctl_rdata) {
        for (i = 0; i < g_private_route_per_zone_max_num; i++) {
            rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)i);
            if (rdata_ctl == NULL) {
                continue;
            }

            if (rdata_ctl->rdata_count != 0) {
                rdata_exist_flag = 1;
                break;
            }
        }
    }
    
CLEAR_RRSET_TTL:
    if (rdata_exist_flag == 0) {
        rrset->ttl = 0;
    }

    /* if all node tag is empty, delete the node */
    for (i = 0; i < g_view_max_num + g_private_route_per_zone_max_num; i++) {
        if (GET_TAG(node->node_tag, i)) {
            node_is_empty = false;
            break;
        }
    }
    if (node_is_empty == true) {
        ret = adns_zone_del_node(zone, dname);
        if (ret != 0) {
            cmd_set_err(err, "[%s]: adns_zone_del_node failed\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s] : adns_zone_del_node failed, ret = %d", __FUNCTION__, ret);
        }
    }

    adns_dname_free(&dname);
    adns_dname_free(&zone_dname);
    return 0;
}


static void master_del_rr(ioClient *c)
{
    int ret;   
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DELRR;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    ret = __del_rr(g_datacore_db, ce->zone, ce->domain, ce->custom_view, ce->view_id, ce->type,
            ce->rdata, ce->rdata_len, ce->original_rdata, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm -d --zone %s --domain %s %s %d --type %d -r \"%s\", ret = %d, FAILURE\n", 
                                          ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->type, ce->original_rdata, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0; 

    log_server_warn(rte_lcore_id(), "adns_adm -d --zone %s --domain %s %s %d --type %d -r \"%s\", SUCCESS\n", 
                                          ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->type, ce->original_rdata);
}


int __del_domain(struct adns_zonedb *zonedb, char *zone_str, char *domain, 
        uint8_t custom_view, adns_viewid_t view_id, char *err)
{
    int i, ret, node_is_empty = true;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;
    struct adns_node *node = NULL;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "%s: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        return 0;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s(node %s) does not exist\n", __FUNCTION__, zone_str, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s(node %s) does not exist\n", __FUNCTION__, zone_str, domain); 
        return 0;
    }

    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        return 0;
    }
    
    node = adns_domain_hash_lookup(zone, dname); 
    if (node == NULL) {
        adns_dname_free(&zone_dname);
        adns_dname_free(&dname);
        cmd_set_err(err, "[%s]: Node %s does not exist\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Node %s does not exist\n", __FUNCTION__, domain); 
        return 0;
    }
    
    for (i = 0; i < ADNS_RRSET_NUM; i++) {
        rrset = node->rrsets[i];
        if (rrset == NULL) {
            continue; 
        }

        /* if default_ns flag is set, means that the rrset is default NS rrset, which only has
        default rdata_ctl and should not be free, only decrement the ref count is enough
        */
        if (rrset->default_ns == 1) {
            rrset->ref_count --;
            node->rrsets[i] = NULL;
            continue;
        }

        if (custom_view) {
            rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
        }
        else {
            rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
        }
        if (rdata_ctl == NULL) {
            continue; 
        }
        adns_rrset_cleanup_rdatas_for_ctl(rdata_ctl, rrset->type);
    }
    
    node_update_tag(node, custom_view, view_id);

     /* if all node tag is empty, delete the node */
    for (i = 0; i < g_view_max_num + g_private_route_per_zone_max_num; i++) {
        if (GET_TAG(node->node_tag, i)) {
            node_is_empty = false;
            break;
        }
    }
    if (node_is_empty == true) {
        ret = adns_zone_del_node(zone, dname);
        if (ret != 0) {
            cmd_set_err(err, "[%s]: adns_zone_del_node failed\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s] : adns_zone_del_node failed, ret = %d", __FUNCTION__, ret);
        }
    }

    adns_dname_free(&zone_dname);
    adns_dname_free(&dname);

    return 0;
}


static void master_del_domain(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DELDOMAIN;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __del_domain(g_datacore_db, ce->zone, ce->domain, ce->custom_view, ce->view_id, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm -x --zone %s --domain %s %s %d, ret = %d, FAILURE\n", 
                                         ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;  
    log_server_warn(rte_lcore_id(), "adns_adm -x --zone %s --domain %s %s %d, SUCCESS\n", 
                                     ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id);
}


int __del_domain_all(struct adns_zonedb *zonedb, char *zone_str, char *domain, char *err)
{
    int ret, i, j;
    uint8_t custom_view;
    adns_viewid_t view_id;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_zone *zone = NULL;
    struct adns_node *dnode = NULL;
    struct adns_rrset *rrset = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "%s: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        return 0;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s(node %s) does not exist\n", __FUNCTION__, zone_str, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s(node %s) does not exist\n", __FUNCTION__, zone_str, domain); 
        return 0;
    }

    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        return 0;
    }
   
    dnode = adns_domain_hash_lookup(zone, dname); 
    if (dnode)
    for (j = 0; j < g_view_max_num + g_private_route_per_zone_max_num; j++) {
        custom_view = (j >= g_view_max_num)?1:0;
        view_id = (custom_view == 1)?(j-g_view_max_num):j;
        for (i = 0; i < ADNS_RRSET_NUM; i++) {
            rrset = dnode->rrsets[i];
            if (rrset == NULL) {
                continue; 
            }

            /* if default_ns flag is set, means that the rrset is default NS rrset, which only has
            default rdata_ctl and should not be free, only decrement the ref count is enough
            */
            if (rrset->default_ns == 1) {
                rrset->ref_count --;
                dnode->rrsets[i] = NULL;
                continue;
            }

            if (custom_view) {
                rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
            } else {
                rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
            }
            if (rdata_ctl == NULL) {
                continue; 
            }
            adns_rrset_cleanup_rdatas_for_ctl(rdata_ctl, rrset->type);
        }
    
        node_update_tag(dnode, custom_view, view_id);
    }

    ret = adns_zone_del_node(zone, dname);
    if (ret != 0) {
        cmd_set_err(err, "[%s]: adns_zone_del_node failed\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s] : adns_zone_del_node failed, ret = %d", __FUNCTION__, ret);
        ret = ADNS_ADMIN_DEL_DOMAIN_ALL_DOMAIN_ERROR;
    }
   
    adns_dname_free(&zone_dname);
    adns_dname_free(&dname);

    return ret;
}


static void master_del_domain_all(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DELDOMAIN_ALL;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __del_domain_all(g_datacore_db, ce->zone, ce->domain, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm -O --zone %s --domain %s, ret = %d, FAILURE\n", 
                                         ce->zone, ce->domain, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -O --zone %s --domain %s, SUCCESS\n", 
                                     ce->zone, ce->domain); 
}


static int rrset_node_schedule_to_str(struct adns_node *node, char *buf, size_t maxlen)
{
    int   len;
    char *dname_str;

    if (node == NULL || buf == NULL) {
        return -1;
    }
    
    /*
     * header format: domain name | schedule_mode
     */
    dname_str = adns_dname_to_str(node->name); 
    len = snprintf(buf, maxlen, "%s A:%u AAAA:%u\n", dname_str, node->A_schedule_mode, node->AAAA_schedule_mode);
    free(dname_str);
    if (len < 0) {
        return -1;
    }

    return len;
}


static int node_schedule_to_str(struct adns_node *node, char *buf, size_t maxlen)
{
    int   len;
    char *dname_str;

    if (node == NULL || buf == NULL) {
        return -1;
    }
    
    /*
     * header format: domain name | schedule_mode
     */
    dname_str = adns_dname_to_str(node->name); 

    len = snprintf(buf, maxlen, "%s A:%s AAAA:%s\n", dname_str, node->A_schedule_mode == SCHEDULE_MODE_RATIO? "ratio" : "all-rr", node->AAAA_schedule_mode == SCHEDULE_MODE_RATIO? "ratio" : "all-rr");

    free(dname_str);
    if (len < 0) {
        return -1;
    }

    return len;
}

static const char *__get_view_name(char *custom_view_name_buf, uint8_t custom_view, adns_viewid_t view_id)
{
    int ret;
    const char *view_name = NULL;

    if (custom_view_name_buf == NULL) {
        return NULL;
    }

    if (custom_view) {
        ret = snprintf(custom_view_name_buf, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, view_id);
        if (ret < 0 || ret >= VIEW_NAME_LEN) {
            return NULL;
        }
        view_name = custom_view_name_buf;
    } else {
        if (view_id == 0) {
            view_name = "default";
        } else {
            view_name = (char *)view_id_to_name(view_id);
        }
    }

    return view_name;
}

static int __view_schedule_to_str(struct adns_rdata_ctl *rdata_ctl, uint16_t type, uint8_t custom_view, adns_viewid_t view_id, char *buf, size_t maxlen)
{
    const char *type_name = NULL, *view_name = NULL, *sche_name = NULL;
    char custom_view_name[VIEW_NAME_LEN] = {0};
    uint8_t sche_mode;
    int len;

    if (rdata_ctl == NULL || buf == NULL) {
        return -1;
    }

    view_name = __get_view_name(custom_view_name, custom_view, view_id);
    if (view_name == NULL) {
        return -1;
    }

    if (type == ADNS_RRTYPE_A) {
        type_name = "A";
    } else if (type == ADNS_RRTYPE_AAAA) {
        type_name = "AAAA";
    } else {
        type_name = "unknown";
    }

    sche_mode = rdata_ctl->schedule_mode;
    if (sche_mode == SCHEDULE_MODE_ALLRR) {
        sche_name = "all-rr";
    } else if (sche_mode == SCHEDULE_MODE_RATIO) {
        sche_name = "ratio";
    } else {
        sche_name = "invalid";
    }

    len = snprintf(buf, maxlen, "%s %s %s\n", type_name, view_name, sche_name);
    if (len < 0 || len >= maxlen) {
        return -1;
    }

    return len;
}


static int adns_rdata_ctl_a_to_str(struct adns_node *node, struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl, char *buf, int maxlen)
{
    int len = 0, total = 0;
    char *dname_str, rdata_str[64];
    const char *view_name = NULL, *type_name = NULL;
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    view_name = __get_view_name(custom_view_name, custom_view, view_id);
    if (view_name == NULL) {
        free(dname_str);
        return -1;
    }

    type_name = "A";
    struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        if( (maxlen - total) <= 0 ) {
            free(dname_str);
            return -2;
        }
        if (inet_ntop(AF_INET, rdata->data, rdata_str, 64) == NULL) {
            continue;
        }
        /*
         * RR format: domain | view name | TTL | TYPE | rdata | <weight>
         */
        if( g_large_weight == 0){
            log_server_error(rte_lcore_id(), "[%s]: g_large_weight is 0 at division\n", __FUNCTION__);
            free(dname_str);
            return -3;
        }
        len = snprintf(buf + total, maxlen - total, "%s %s %u IN %s %s %u\n", dname_str, view_name, rrset->ttl, type_name, rdata_str, rdata->cw / g_large_weight);
        if (len < 0) {
            free(dname_str);
            return -4;
        }
        total += len;
    }

    free(dname_str);
    return total;
}


static int adns_rdata_ctl_domain_to_str(struct adns_node *node, struct adns_rrset *rrset, char *type_name, uint8_t custom_view, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl, char *buf, int maxlen)
{
    int len = 0, total = 0;
    char *dname_str;
    const char *view_name = NULL;
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    view_name = __get_view_name(custom_view_name, custom_view, view_id);
    if (view_name == NULL) {
        free(dname_str);
        return -1;
    }

    struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        if( (maxlen - total) <= 0 ) {
            free(dname_str);
            return -2;
        }
		char *rdata_str = adns_dname_to_str((adns_dname_t *)(rdata->data));
        /*
         * RR format: domain | view name | TTL | TYPE | rdata
         */
        if (!strcmp(type_name, "CNAME")) {
            if( g_large_weight == 0){
                log_server_error(rte_lcore_id(), "[%s]: g_large_weight is 0 at division\n", __FUNCTION__);
                free(dname_str);
                free(rdata_str);
                return -3;
            }
            len = snprintf(buf + total, maxlen - total, "%s %s %u IN %s %s %u\n", dname_str, view_name, rrset->ttl, type_name, rdata_str, rdata->cw / g_large_weight);
        } else {
            len = snprintf(buf + total, maxlen - total, "%s %s %u IN %s %s\n", dname_str, view_name, rrset->ttl, type_name, rdata_str);
        }
        if (len < 0) {
            free(rdata_str);
            free(dname_str);
            return -3; 
        }
        total += len;

		free(rdata_str);
    }

    free(dname_str);
    return total;
}


static int adns_rdata_ctl_mx_to_str(struct adns_node *node, struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl, char *buf, int maxlen)
{
    int len = 0, total = 0;
    char *dname_str;
    const char *view_name = NULL, *type_name = NULL;
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    view_name = __get_view_name(custom_view_name, custom_view, view_id);
    if (view_name == NULL) {
        free(dname_str);
        return -1;
    }

    type_name = "MX";

    struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        if( (maxlen - total) <= 0 ) {
            free(dname_str);
            return -2;
        }
        uint16_t prefer = ntohs(*(uint16_t *)rdata->data);
        char *rdata_str = adns_dname_to_str((adns_dname_t *)(rdata->data 
                    + sizeof(uint16_t)));

        /*
         * RR format: domain | view name | TTL | TYPE | prefer | rdata 
         */
        len = snprintf(buf + total, maxlen - total, "%s %s %u IN %s %u %s\n", dname_str, view_name, rrset->ttl, type_name, prefer, rdata_str);
        if (len < 0) {
            free(dname_str);
            free(rdata_str);
            return -2; 
        }
        total += len;

		free(rdata_str);
    }

    free(dname_str);
    return total;
}


static int adns_rdata_ctl_txt_to_str(struct adns_node *node, struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl, char *buf, int maxlen)
{
    int len = 0, total = 0;
    char *dname_str;
    const char *view_name = NULL, *type_name = NULL;
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    view_name = __get_view_name(custom_view_name, custom_view, view_id);
    if (view_name == NULL) {
        free(dname_str);
        return -1;
    }

    type_name = "TXT";

    struct list_head *h_list = &(rdata_ctl->list);
    uint8_t num;
    int now = 0;
    list_for_each_entry(rdata, h_list, list) {
        if( (maxlen - total) <= 0 ) {
            free(dname_str);
            return -2;
        }
        /*
         * RR format: domain | view name | TTL | TYPE | rdata | <weight>
         */
        len = snprintf(buf + total, maxlen - total, "%s %s %u IN %s ", dname_str, view_name, rrset->ttl, type_name);
        if (len < 0) {
            free(dname_str);
            return -3; 
        }
        total += len;
        now = 0;
        while (now < rdata->len) {
            buf[total++] = '"';
            num = rdata->data[now];
            memcpy(buf+total, rdata->data + now + 1, num);
            total += num;
            now += num + 1;
            buf[total++] = '"';
            buf[total++] = ' ';
        }
		buf[total++] = '\n';
    }

    free(dname_str);
    return total;
}


static int adns_rdata_ctl_aaaa_to_str(struct adns_node *node, struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl, char *buf, int maxlen)
{
    int len = 0, total = 0;
    char *dname_str, rdata_str[64];
    const char *view_name = NULL, *type_name = NULL;
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    view_name = __get_view_name(custom_view_name, custom_view, view_id);
    if (view_name == NULL) {
        free(dname_str);
        return -1;
    }

    type_name = "AAAA";

    struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        if( (maxlen - total) <= 0 ) {
            free(dname_str);
            return -2;
        }

        if (inet_ntop(AF_INET6, rdata->data, rdata_str, 64) == NULL) {
            continue;
        }
        /*
         * RR format: domain | view name | TTL | TYPE | rdata
         */
        len = snprintf(buf + total, maxlen - total, "%s %s %u IN %s %s\n", dname_str, view_name, rrset->ttl, type_name, rdata_str);
        if (len < 0) {
            free(dname_str);
            return -3; 
        }
        total += len;
    }

    free(dname_str);
    return total;
}


static int adns_rdata_ctl_srv_to_str(struct adns_node *node, struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl, char *buf, int maxlen)
{
    int len = 0, total = 0;
    char *dname_str;
    const char *view_name = NULL, *type_name = NULL;
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    view_name = __get_view_name(custom_view_name, custom_view, view_id);
    if (view_name == NULL) {
        free(dname_str);
        return -1;
    }

    type_name = "SRV";

    struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        if( (maxlen - total) <= 0 ) {
            free(dname_str);
            return -2;
        }
        uint16_t pri = ntohs(*(uint16_t *)rdata->data);
        uint16_t weight = ntohs(*((uint16_t *)rdata->data + 1));
        uint16_t port = ntohs(*((uint16_t *)rdata->data + 2));
        char *rdata_str = adns_dname_to_str((adns_dname_t *)(rdata->data 
    				+ sizeof(uint16_t) * 3));

        /*
         * RR format: domain | view name | TTL | TYPE | PRI | WEIGHT | PORT | Rdata
         */
        len = snprintf(buf + total, maxlen - total, "%s %s %u IN %s %u %u %u %s\n", dname_str, view_name, rrset->ttl, type_name, pri, weight, port, rdata_str);
        if (len < 0) {
            free(dname_str);
            free(rdata_str);
            return -3; 
        }
        total += len;

		free(rdata_str);
    }

    free(dname_str);
    return total;
}


static int adns_rdata_ctl_caa_to_str(struct adns_node *node, struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl, char *buf, int maxlen)
{
    int len = 0, total = 0;
    char *dname_str;
    const char *view_name = NULL, *type_name = NULL;
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    view_name = __get_view_name(custom_view_name, custom_view, view_id);
    if (view_name == NULL) {
        free(dname_str);
        return -1;
    }

    type_name = "CAA";

    struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list)
    {
        if ((maxlen - total) <= 0) {
            free(dname_str);
            return -2;
        }
        /*
         * RR format: domain | view name | TTL | CLASS | TYPE | FLAGS | TAG | VALUE
         */
        len = snprintf(buf + total, maxlen - total, "%s %s %u IN %s ",
                dname_str, view_name, rrset->ttl, type_name);
        if (len < 0) {
            free(dname_str);
            return -3;
        }
        total += len;
        int len = dump_caa_rdata(buf + total, maxlen - total, rdata);
        if (len < 0) {
            free(dname_str);
            return -4;
        }
        total += len;
    }

    free(dname_str);
    return total;
}


static int adns_rdata_ctl_to_str(struct adns_node *node,struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, struct adns_rdata_ctl *rdata_ctl, char *buf, int maxlen)
{
    int ret = 0;
    switch (rrset->type) {
        case ADNS_RRTYPE_A:
            ret = adns_rdata_ctl_a_to_str(node, rrset, custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_NS:
            ret = adns_rdata_ctl_domain_to_str(node, rrset, "NS", custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_CNAME:
            ret = adns_rdata_ctl_domain_to_str(node, rrset, "CNAME", custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_PTR:
            ret = adns_rdata_ctl_domain_to_str(node, rrset, "PTR", custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_DNAME:
            ret = adns_rdata_ctl_domain_to_str(node, rrset, "DNAME", custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_MX:
            ret = adns_rdata_ctl_mx_to_str(node, rrset, custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_TXT:
        case ADNS_RRTYPE_SPF:
            ret = adns_rdata_ctl_txt_to_str(node, rrset, custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_AAAA:
            ret = adns_rdata_ctl_aaaa_to_str(node, rrset, custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_SRV:
            ret = adns_rdata_ctl_srv_to_str(node, rrset, custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        case ADNS_RRTYPE_CAA:
            ret = adns_rdata_ctl_caa_to_str(node, rrset, custom_view, view_id, rdata_ctl, buf, maxlen);
            break;
        default:
            break;
    }
    return ret;
}


static int __list_domain(struct adns_zonedb *zonedb, char *zone_str, char *domain, uint8_t custom_view, adns_viewid_t view_id,
        uint16_t type, char *buf, int maxlen, char *err)
{
    int ret, len, total;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;
    struct adns_node *node = NULL;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "%s: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        return ADNS_ADMIN_LIST_DOMAIN_CONVERT_ZONE_ERROR;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        cmd_set_err(err, "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str); 
        ret = ADNS_ADMIN_LIST_DOMAIN_FIND_ZONE_ERROR;
        goto err_zone;
    }
        
    ret = adns_node_check_type(type);
    if (ret < 0) {
        ret = ADNS_ADMIN_LIST_DOMAIN_TYPE_ERROR;
        goto err_type;  
    }

    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        ret = ADNS_ADMIN_LIST_DOMAIN_DOMAIN_ERROR;
        goto err_dname;
    }
    
    node = adns_domain_hash_lookup(zone, dname); 
    if (node == NULL) {
        cmd_set_err(err, "[%s]: Node %s does not exist\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Node %s does not exist\n", __FUNCTION__, domain); 
        ret = ADNS_ADMIN_LIST_DOMAIN_FIND_NODE_ERROR;                                           
        goto err_node;        
    }
        
    rrset = adns_node_get_rrset(node, type); 
    if (rrset == NULL) {
        cmd_set_err(err, "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain, type);
        log_server_warn(rte_lcore_id(), "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain, type); 
        ret = ADNS_ADMIN_LIST_DOMAIN_FIND_RRSET_ERROR;                                           
        goto err_rrset;     
    }
    
    if (custom_view) {
        rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
    }
    else {
        rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
    }
    if (rdata_ctl == NULL) {
        cmd_set_err(err, "[%s]: Rdata_ctl of node %s(type = %d, %sview_id = %d) does not exist\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Rdata_ctl of node %s(type = %d, %sview_id = %d) does not exist\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id); 
        ret = ADNS_ADMIN_LIST_DOMAIN_FIND_RDATA_CTL_ERROR; 
        goto err_rdata_ctl;   
    }
    
    /* list soa */
    total = 0;
    len = adns_zonedb_soa_to_str(zone, buf + total, maxlen - total);
    if (len < 0) {
        goto err_convert_soa;
    }
    total += len;
    
    /* list schedule */
    len = rrset_node_schedule_to_str(node, buf + total, maxlen - total);
    if (len < 0) {
        goto err_convert_schedule;
    }
    total += len;
   
    /* list type->view_id rdata*/
    len = adns_rdata_ctl_to_str(node, rrset, custom_view, view_id, rdata_ctl, buf + total, maxlen - total);
    if (len < 0){
        if( len == -2 ) {
            cmd_set_err(err, "[%s]: Rdata of domain %s exceeds maximum capacity of message tunnel.\n", __FUNCTION__, domain);
            log_server_error(rte_lcore_id(), "[%s]: Rdata of domain %s exceeds maximum capacity of message tunnel.\n", __FUNCTION__, domain);
            ret = ADNS_ADMIN_LIST_DOMAIN_FILL_RDATA_ERROR;
        }
      goto err_rdata_ctl;
    }
    total += len;

    adns_dname_free(&dname);
    adns_dname_free(&zone_dname);
    return total;
      
err_node:
err_rrset:
err_rdata_ctl:
err_convert_soa:
err_convert_schedule:
    adns_dname_free(&dname);

err_zone:
err_type:
err_dname:    
    adns_dname_free(&zone_dname);
    return ret;   
}


static int __list_schedule(struct adns_zonedb *zonedb, char *zone_str, char *domain, uint16_t type, 
                        uint8_t custom_view, adns_viewid_t view_id, uint8_t sche_set_to_line, char *buf, int maxlen, char *err)
{
    int ret = 0, len = 0, total = 0;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_node *node = NULL;
    struct adns_zone *zone = NULL;
    struct adns_rrset *rrset = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "%s: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        return ADNS_ADMIN_LIST_DOMAIN_CONVERT_ZONE_ERROR;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        cmd_set_err(err, "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str); 
        ret = ADNS_ADMIN_LIST_DOMAIN_FIND_ZONE_ERROR;
        goto err;
    }
        
    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        ret = ADNS_ADMIN_LIST_DOMAIN_DOMAIN_ERROR;
        goto err;
    }
    
    node = adns_domain_hash_lookup(zone, dname); 
    if (node == NULL) {
        cmd_set_err(err, "[%s]: Node %s does not exist\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Node %s does not exist\n", __FUNCTION__, domain); 
        ret = ADNS_ADMIN_LIST_DOMAIN_FIND_NODE_ERROR;                                           
        goto err;        
    }
        
    /* list schedule */
    total = 0;
    len = node_schedule_to_str(node, buf + total, maxlen - total);
    if (len < 0) {
        ret = len;
        goto err;
    }
    total += len;

    if (sche_set_to_line) {
        rrset = adns_node_get_rrset(node, type);
        if (rrset == NULL) {
            cmd_set_err(err, "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain, type);
            log_server_warn(rte_lcore_id(), "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain, type);
            ret = ADNS_ADMIN_SCHEDULE_FIND_RRSET_ERROR;
            goto err;
        }

        if (custom_view) {
            rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
        }
        else {
            rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
        }
        if (rdata_ctl == NULL) {
            cmd_set_err(err, "[%s]: rdata_ctl not exist, node %s, type %d, %sview %d\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
            log_server_warn(rte_lcore_id(), "[%s]: rdata_ctl not exist, node %s, type %d, %sview %d\n", __FUNCTION__, domain, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
            ret = ADNS_ADMIN_SCHEDULE_FIND_VIEW_ERROR;
            goto err;
        }
        len = __view_schedule_to_str(rdata_ctl, type, custom_view, view_id, buf + total, maxlen - total);
        if (len < 0) {
            ret = len;
            goto err;
        }
        total += len;
    }
    ret = total;

err:
    adns_dname_free(&dname);
    adns_dname_free(&zone_dname);
    return ret;
}


static void master_list_domain(ioClient *c)
{
    int ret, maxlen, total = 0;  
    uint8_t *buf;  
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_LISTDOMAIN;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    maxlen = ADNS_ADM_MAX_REPLY_LEN - c->buf_size; 
    buf = (uint8_t *)(c->buf + 2 + sizeof(struct cmd_resp));

    ret = __list_domain(g_datacore_db, ce->zone, ce->domain, ce->custom_view, ce->view_id,
        ce->type, (char *)buf, maxlen, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        c->buf_size = 2 + sizeof(struct cmd_resp);
        *len = htons(sizeof(struct cmd_resp));
        log_server_warn(rte_lcore_id(), "adns_adm -l --zone %s --domain %s %s %d --type %d, ret = %d, FAILURE\n", 
                                         ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->type, cmd_resp->ret_val);
        return;
    }
    
    total = ret;
    buf[total++] = '\0';
    c->buf_size = 2 + sizeof(struct cmd_resp) + total;
    *len = htons(sizeof(struct cmd_resp) + total);
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -l --zone %s --domain %s %s %d --type %d, SUCCESS\n", 
                                     ce->zone, ce->domain, ce->custom_view? "--custom_view" : "--view", ce->view_id, ce->type);
}


static void master_list_schedule(ioClient *c)
{
    int ret, maxlen, total = 0;  
    uint8_t *buf;  
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_LISTSCHEDULE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    maxlen = ADNS_ADM_MAX_REPLY_LEN - c->buf_size; 
    buf = (uint8_t *)(c->buf + 2 + sizeof(struct cmd_resp));

    ret = __list_schedule(g_datacore_db, ce->zone, ce->domain, ce->type, ce->custom_view, ce->view_id, ce->weight, (char *)buf, maxlen, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        c->buf_size = 2 + sizeof(struct cmd_resp);
        *len = htons(sizeof(struct cmd_resp));
        log_server_warn(rte_lcore_id(), "adns_adm -u --zone %s --domain %s, ret = %d, FAILURE\n", 
                                         ce->zone, ce->domain, cmd_resp->ret_val);
        return;
    }
    
    total = ret;
    buf[total++] = '\0';
    c->buf_size = 2 + sizeof(struct cmd_resp) + total;
    *len = htons(sizeof(struct cmd_resp) + total);
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -u --zone %s --domain %s, SUCCESS\n", 
                                     ce->zone, ce->domain);
}

int __schedule_mode_set_node(struct adns_node *node, const char *domain_str, uint16_t type,
                            uint8_t custom_view, adns_viewid_t view_id, uint8_t sche_set_to_line, uint8_t mode, char *err)
{
    int ret = 0;
    struct adns_rrset *rrset = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;

    if (node == NULL || domain_str == NULL) {
        cmd_set_err(err, "[%s]: Node does not exist\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: Node does not exist\n", __FUNCTION__); 
        return ADNS_ADMIN_SCHEDULE_FIND_NODE_ERROR;
    }

    if (SCHEDULE_MODE_VALIDATE(mode, sche_set_to_line) != 0) {
        cmd_set_err(err, "[%s]: Invalid schedule mode %u\n", __FUNCTION__, mode);
        log_server_warn(rte_lcore_id(), "%s: Invalid schedule mode %u\n", __FUNCTION__, mode);
        return ADNS_ADMIN_SCHEDULE_INVALID_MODE;
    }

    // Schedule mode set to node
    if (sche_set_to_line == 0) {
        if (type == ADNS_RRTYPE_AAAA) {
            node->AAAA_schedule_mode = mode;
        } else {
            node->A_schedule_mode = mode;
        }
    } else { // Schedule mode set to line
        // only allow to set schedule mode for type A and AAAA
        if (type != ADNS_RRTYPE_AAAA) {
            type = ADNS_RRTYPE_A;
        }
        if (custom_view == 0 && view_id >= g_view_max_num) {
            cmd_set_err(err, "[%s]: view ID %d exceed limit\n", __FUNCTION__, view_id);
            log_server_warn(rte_lcore_id(),"[%s]: view ID %d exceed limit %d\n", __FUNCTION__, view_id);
            ret = ADNS_ADMIN_SCHEDULE_FIND_VIEW_ERROR;
            goto err;
        }
        if (custom_view == 1 && view_id >= g_private_route_per_zone_max_num) {
            cmd_set_err(err, "[%s]: custom view ID %d exceed limit %u\n", __FUNCTION__, view_id, g_private_route_per_zone_max_num);
            log_server_warn(rte_lcore_id(),"[%s]: custom view ID %d exceed limit\n", __FUNCTION__, view_id);
            ret = ADNS_ADMIN_SCHEDULE_FIND_VIEW_ERROR;
            goto err;
        }

        rrset = adns_node_get_rrset(node, type);
        if (rrset == NULL) {
            cmd_set_err(err, "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain_str, type);
            log_server_warn(rte_lcore_id(), "[%s]: RRset of node %s(type = %d) does not exist\n", __FUNCTION__, domain_str, type);
            ret = ADNS_ADMIN_SCHEDULE_FIND_RRSET_ERROR;
            goto err;
        }

        if (custom_view) {
            rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
        }
        else {
            rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
        }
        if (rdata_ctl == NULL) {
            cmd_set_err(err, "[%s]: rdata_ctl not exist, node %s, type %d, %sview %d\n", __FUNCTION__, domain_str, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
            log_server_warn(rte_lcore_id(), "[%s]: rdata_ctl not exist, node %s, type %d, %sview %d\n", __FUNCTION__, domain_str, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
            ret = ADNS_ADMIN_SCHEDULE_FIND_VIEW_ERROR;
            goto err;
        }
        // if rdata_ctl is empty, not allow to set schedule mode
        if (rdata_ctl->rdata_count == 0) {
            cmd_set_err(err, "[%s]: rdata_ctl empty, node %s, type %d, %sview %d\n", __FUNCTION__, domain_str, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
            log_server_warn(rte_lcore_id(), "[%s]: rdata_ctl empty, node %s, type %d, %sview %d\n", __FUNCTION__, domain_str, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
            ret = ADNS_ADMIN_SCHEDULE_EMPTY_VIEW;
            goto err;
        }
        rdata_ctl->schedule_mode = mode;
    }

err:
    return ret;
}


int __schedule_mode_set(struct adns_zonedb *zonedb, char *zone_str, char *domain_str, uint16_t type, 
                        uint8_t custom_view, adns_viewid_t view_id, uint8_t sche_set_to_line, uint8_t mode, char *err)
{   
    int ret = 0;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_node *node = NULL;
    struct adns_zone *zone = NULL;

    if (SCHEDULE_MODE_VALIDATE(mode, sche_set_to_line) != 0) {
        cmd_set_err(err, "[%s]: Invalid schedule mode %u\n", __FUNCTION__, mode);
        log_server_warn(rte_lcore_id(), "%s: Invalid schedule mode %u\n", __FUNCTION__, mode);
        return ADNS_ADMIN_SCHEDULE_INVALID_MODE;
    }

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "%s: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        return ADNS_ADMIN_SCHEDULE_CONVERT_ZONE_ERROR;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        cmd_set_err(err, "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str); 
        ret = ADNS_ADMIN_SCHEDULE_FIND_ZONE_ERROR;
        goto err;
    }
        
    dname = adns_dname_from_str(domain_str, strlen(domain_str));
    if (dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain_str);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain_str);
        ret = ADNS_ADMIN_SCHEDULE_DOMAIN_ERROR;
        goto err;
    }
    
    node = adns_zone_lookup_node(zone, dname); 
    if (node == NULL) {
        cmd_set_err(err, "[%s]: Node %s does not exist\n", __FUNCTION__, domain_str);
        log_server_warn(rte_lcore_id(), "[%s]: Node %s does not exist\n", __FUNCTION__, domain_str); 
        ret = ADNS_ADMIN_SCHEDULE_FIND_NODE_ERROR;
        goto err;
    }

    ret = __schedule_mode_set_node(node, domain_str, type, custom_view, view_id, sche_set_to_line, mode, err);
err:
    adns_dname_free(&zone_dname);
    adns_dname_free(&dname);
    return ret;
}


static void master_schedule_mode(ioClient *c)
{
    int ret;
    uint8_t mode;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    uint16_t type;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_SCHEDULE_MODE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    /* get the rrset schedule mode */
    mode = (uint8_t)(ce->rclass);
    /* get the rrset type */
    type = ce->type;
    ret = __schedule_mode_set(g_datacore_db, ce->zone, ce->domain, type, ce->custom_view, ce->view_id, ce->weight, mode, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        if (ce->weight) {
            log_server_warn(rte_lcore_id(), "adns_adm -k --zone %s --domain %s --custom-view %d --view %d --mode %d --type %d,  ret = %d, FAILURE\n", 
                                         ce->zone, ce->domain, ce->custom_view, ce->view_id, mode, type? type : ADNS_RRTYPE_A, cmd_resp->ret_val);
            return;
        } else {
            log_server_warn(rte_lcore_id(), "adns_adm -k --zone %s --domain %s --mode %d --type %d,  ret = %d, FAILURE\n", 
                                         ce->zone, ce->domain, mode, type? type : ADNS_RRTYPE_A, cmd_resp->ret_val);
            return;
        }
    }

    cmd_resp->ret_val = 0;
    if (ce->weight) {
        log_server_warn(rte_lcore_id(), "adns_adm -k --zone %s --domain %s --custome-view %d, --view %d --mode %d --type %d, SUCCESS\n", 
                                     ce->zone, ce->domain, ce->custom_view, ce->view_id, mode, type? type : ADNS_RRTYPE_A);
    } else {
        log_server_warn(rte_lcore_id(), "adns_adm -k --zone %s --domain %s --mode %d --type %d, SUCCESS\n", 
                                     ce->zone, ce->domain, mode, type? type : ADNS_RRTYPE_A);
    }
}


/* Other Function */
static int __dump_database(struct adns_zonedb *zonedb, struct adns_command_entry *ce, char *err)
{
    int ret = 0;
    FILE *fp;
    
    fp = fopen(DUMP_PATH_DEF, "w+");
    if (fp == NULL) {
        ret = ADNS_ADMIN_DUMP_OPEN_DUMP_FILE_ERROR; 
        return ret;
    }

    if (ce->type == ADNS_RRTYPE_A || ce->type == ADNS_RRTYPE_DS) {
        /* dump all zonedb */
        log_server_warn(rte_lcore_id(), "[%s]: Dump all data start\n", __FUNCTION__); 
       
        ret = adns_zonedb_dump(zonedb, fp, NULL, NULL, 0, 0, ce->type, err);
        if (ret < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: Dump all data failed, ret = %d\n", __FUNCTION__, ret);  
        } else {
            log_server_warn(rte_lcore_id(), "[%s]: Dump all data succeed\n", __FUNCTION__);
        }
        log_server_warn(rte_lcore_id(), "[%s]: Dump all data finish\n", __FUNCTION__); 
    } else {
        /* dump specify data */
        log_server_warn(rte_lcore_id(), "[%s]: Dump specify data, zone %s, domain %s, %sview_id %d start\n", __FUNCTION__, ce->zone, ce->domain, ce->custom_view? CUSTOM_VIEW_PREFIX : "", ce->view_id); 
        
        ret = adns_zonedb_dump(zonedb, fp, ce->zone, ce->domain, ce->custom_view, ce->view_id, 0, err);
        if (ret < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: Dump all data failed, ret = %d\n", __FUNCTION__, ret);  
        } else {
            log_server_warn(rte_lcore_id(), "[%s]: Dump all data succeed\n", __FUNCTION__);
        }
        
        log_server_warn(rte_lcore_id(), "[%s]: Dump specify data, zone %s, domain %s, %sview_id %d finish\n", __FUNCTION__, ce->zone, ce->domain, ce->custom_view? CUSTOM_VIEW_PREFIX : "", ce->view_id); 
    }
    
    fclose(fp); 
    return ret;
}


static void master_dump(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DUMP;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __dump_database(g_datacore_db, ce, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --dump --zone %s --domain %s % %d --type %d, ret = %d, FAILURE\n", 
                                         ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->type, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;  
    log_server_warn(rte_lcore_id(), "adns_adm --dump --zone %s --domain %s %s %d --type %d, SUCCESS\n", 
                                     ce->zone, ce->domain, ce->custom_view? "--custom-view" : "--view", ce->view_id, ce->type);
}

static int __set_cname_cascade(struct adns_zonedb *zonedb, char *name, int enable_cname_cascade, char *err)
{
    adns_dname_t *zone_dname;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(name, strlen(name));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_CNAME_CASCADE_CONVERT_ZONE_ERROR;
    }

    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (NULL == zone) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        return ADNS_ADMIN_CNAME_CASCADE_FIND_ZONE_ERROR;
    }

    zone->enable_cname_cascade = enable_cname_cascade;

    return 0;
}

static int __set_wildcard_fallback(struct adns_zonedb *zonedb, char *name, int enable_wildcard_fallback, char *err)
{
    adns_dname_t *zone_dname;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(name, strlen(name));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_WILDCARD_FALLBACK_CONVERT_ZONE_ERROR;
    }

    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (NULL == zone) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        return ADNS_ADMIN_WILDCARD_FALLBACK_FIND_ZONE_ERROR;
    }

    zone->wildcard_fallback_enable = enable_wildcard_fallback;

    return 0;
}

int __set_zone_dnssec(struct adns_zone *zone, int enable_dnssec, char *err)
{
    int ret;

    if (enable_dnssec < 0 || enable_dnssec > 1) {
        cmd_set_err(err, "[%s]: invalid dnssec opt value %d\n", __FUNCTION__, enable_dnssec);
        log_server_warn(rte_lcore_id(), "[%s]: invalid dnssec opt value %d\n", __FUNCTION__, enable_dnssec);
        return ADNS_ADMIN_DNSSEC_SET_ZONE_ERROR;
    }

    if (zone->enable_dnssec != enable_dnssec) {
        if (enable_dnssec == 1) {
            if (g_dnssec_zone_num == g_dnssec_zone_max_num) {
                cmd_set_err(err, "[%s]: dnssec enabled zone num exceed limit %d\n", __FUNCTION__, g_dnssec_zone_max_num);
                log_server_warn(rte_lcore_id(), "[%s]: dnssec enabled zone num exceed limit %d\n", __FUNCTION__, g_dnssec_zone_max_num);
                return ADNS_ADMIN_DNSSEC_ZONE_EXCEED_LIMIT_ERROR;
            }
            INCREASE_DNSSEC_ZONE_NUM(1);
        } else {
            /* For now, disable dnssec of a zone will cause the deletion of the
             * zone's zsk_ctrl
             * TODO: add a new command entry del_dnskeyrrsig to delete a zone's zsk_ctrl
             */
            adns_zsk_ctr_t *zsk_ctr;
            zsk_ctr = zone->adns_zsk_ctr;
            if (zsk_ctr != NULL) {
                // set zone's dnssec unready
                zone->dnssec_ok = 0;
                // clear zone's zsk_ctr pointer
                // is safe since command handle is in serial
                zone->adns_zsk_ctr = NULL;
                typedef void (*pfn) (void *);
                // active zsk's refcount is decremente in adns_put_zone_zsk_ctr
                ret = call_rcu((pfn)adns_put_zone_zsk_ctr, zsk_ctr);
                // hardly go into this branch
                if (ret < 0) {
                    // recover zone's zsk_ctrl
                    zone->adns_zsk_ctr = zsk_ctr;
                    // set zone's dnssec ready
                    zone->dnssec_ok = 1;
                    cmd_set_err(err, "[%s]: delete zone zsk ctrl error\n", __FUNCTION__);
                    log_server_warn(rte_lcore_id(), "[%s]: delete zone zsk ctrl error\n", __FUNCTION__);
                    return ADNS_ADMIN_DNSSEC_SET_ZONE_ERROR;
                }
            }
            DECREASE_DNSSEC_ZONE_NUM(1);
        }
    }

    zone->enable_dnssec = enable_dnssec;

    return 0;
}

int __set_dnssec(struct adns_zonedb *zonedb, char *name, int enable_dnssec, char *err)
{
    adns_dname_t *zone_dname;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(name, strlen(name));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_DNSSEC_CONVERT_ZONE_ERROR;
    }

    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (NULL == zone) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        return ADNS_ADMIN_DNSSEC_FIND_ZONE_ERROR;
    }
    adns_dname_free(&zone_dname);

    return __set_zone_dnssec(zone, enable_dnssec, err);
}

int __add_key(char *key_data, int data_len, uint16_t type, char *err)
{
    uint8_t pub_key_len = 0, priv_key_len = 0;
    uint8_t *pub_key = NULL, *priv_key = NULL;
    int ret;
    adns_dnssec_key *new_key;
    adns_dnssec_key *tmp_key;

    if (key_data == NULL || data_len == 0) {
        cmd_set_err(err, "[%s]: Failed to add key type %u, NULL or empty key data\n", __FUNCTION__, type);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to add key type %u, NULL or empty key data\n", __FUNCTION__, type);
        return ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR;
    }

    pub_key_len = *((uint8_t *)key_data);
    pub_key = (uint8_t *)key_data + 1;
    if (type == DNS_ZONE_SIGNING_KEY_FLAGS) {
        priv_key_len = *((uint8_t *)key_data + 1 + pub_key_len);
        priv_key = (uint8_t *)key_data + 1 + pub_key_len + 1;
    }

    if (type == DNS_ZONE_SIGNING_KEY_FLAGS && 
        ( ((uint8_t)data_len != (pub_key_len + priv_key_len + 2)) || pub_key_len == 0 || priv_key_len == 0) ) {
        cmd_set_err(err, "[%s]: Failed to add key type %u, invalid option\n", __FUNCTION__, type);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to add key type %u, invalid option\n", __FUNCTION__, type);
        return ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR;
    }

    if (type == DNS_KEY_SIGNING_KEY_FLAGS && 
        ( ((uint8_t)data_len != (pub_key_len + 1)) || pub_key_len == 0) ) {
        cmd_set_err(err, "[%s]: Failed to add key type %u, invalid option\n", __FUNCTION__, type);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to add key type %u, invalid option\n", __FUNCTION__, type);
        return ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR;
    }

    // KSK
    if (type == DNS_KEY_SIGNING_KEY_FLAGS) {
        // get a dnssec key as global ksk
        new_key = adns_get_dnssec_key(1, pub_key, pub_key_len, NULL, 0);
        if (new_key == NULL) {
            cmd_set_err(err, "[%s]: Failed to add key type %u, get dnssec key error\n", __FUNCTION__, type);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to add key type %u, get dnssec key error\n", __FUNCTION__, type);
            return ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR;
        }

        // if global ksk already exists, replace it 
        if (*g_dnssec_ksk != NULL) {
            // replace global KSK by new ksk
            tmp_key = *g_dnssec_ksk;
            *g_dnssec_ksk = new_key;
            typedef void (*pfn) (void *);
            log_server_warn(rte_lcore_id(), "[%s]: Replace global KSK\n", __FUNCTION__);
            ret = call_rcu((pfn)adns_put_dnssec_key, tmp_key);
            if (ret < 0) { //hardly go into this branch
                *g_dnssec_ksk = tmp_key;
                // RISK: new key is already serving DNSKEY query
                adns_put_dnssec_key(new_key);
                cmd_set_err(err, "[%s]: Failed to add key type %u, replace dnssec key error\n", __FUNCTION__, type);
                log_server_warn(rte_lcore_id(), "[%s]: Failed to add key type %u, replace dnssec key error\n", __FUNCTION__, type);
                return ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR;
            }
        } else { // if global ksk not added, set it
            *g_dnssec_ksk = new_key;
        }
    } else { // ZSK
        // get a dnssec key as zsk
        new_key = adns_get_dnssec_key(0, pub_key, pub_key_len, priv_key, priv_key_len);
        if (new_key == NULL) {
            cmd_set_err(err, "[%s]: Failed to add key type %u, get dnssec key error\n", __FUNCTION__, type);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to add key type %u, get dnssec key error\n", __FUNCTION__, type);
            return ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR;
        }

        // replace zsk
        tmp_key = adns_set_zsk(new_key);
        if (tmp_key != NULL) {
            // copy the active reference count
            new_key->active_ref_cnt = tmp_key->active_ref_cnt;
            typedef void (*pfn) (void *);
            ret = call_rcu((pfn)adns_put_dnssec_key, tmp_key);
            if (ret < 0) { //hardly go into this branch
                tmp_key = adns_set_zsk(tmp_key);
                // RISK: new key is already serving DNSKEY query
                adns_put_dnssec_key(new_key);
                cmd_set_err(err, "[%s]: Failed to add key type %u, replace dnssec key error\n", __FUNCTION__, type);
                log_server_warn(rte_lcore_id(), "[%s]: Failed to add key type %u, replace dnssec key error\n", __FUNCTION__, type);
                return ADNS_ADMIN_DNSSEC_ADD_KEY_ERROR;
            }
        }
    }

    return 0;
}


static struct adns_rdata* __new_dnskey_rrsig_data(uint8_t *sig, uint16_t sig_len)
{
    struct adns_rdata *new_dnskey_sig;

    new_dnskey_sig = rdata_alloc(ADNS_RRTYPE_RRSIG);
    if (new_dnskey_sig == NULL) {
        return NULL;
    }
    // save dnskey rrsig rdata
    uint8_t *dst = (uint8_t *)rte_zmalloc(NULL, sig_len, 0);
    if (dst == NULL) {
        rdata_free(new_dnskey_sig, ADNS_RRTYPE_RRSIG);
        return NULL;
    }
    rte_memcpy(dst, sig, sig_len);
    new_dnskey_sig->data = dst;
    new_dnskey_sig->len = sig_len;

    return new_dnskey_sig;
}

int __add_zone_dnskeyrrsig(struct adns_zone *zone, uint8_t *sig, uint16_t sig_len, 
                      uint16_t tag_num, uint16_t active_key, uint16_t alt_zsk_tag, char *err)
{
    struct adns_rdata *dnskey_sig;
    adns_zsk_ctr_t *zsk_ctr, *old_zsk_ctr;
    adns_dnssec_key *alt_zsk, *active_zsk;
    int ret;

    if (tag_num < 1 || tag_num > MAX_ZSK_NUM) {
        cmd_set_err(err, "[%s]: key tag number error\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: key tag number error\n", __FUNCTION__);
        return ADNS_ADMIN_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
    }

    active_zsk = adns_get_zsk_by_key_tag(active_key);
    if (active_zsk == NULL) {
        cmd_set_err(err, "[%s]: active zsk %u not exist\n", __FUNCTION__, active_key);
        log_server_warn(rte_lcore_id(), "[%s]: active zsk %u not exist\n", __FUNCTION__, active_key);
        return ADNS_ADMIN_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
    }

    if (tag_num > 1) {
        alt_zsk = adns_get_zsk_by_key_tag(alt_zsk_tag);
        if (alt_zsk == NULL) {
            cmd_set_err(err, "[%s]: zsk %u not exist\n", __FUNCTION__, alt_zsk_tag);
            log_server_warn(rte_lcore_id(), "[%s]: zsk %u not exist\n", __FUNCTION__, alt_zsk_tag);
            return ADNS_ADMIN_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
        }
    }

    // new the dnskey rrsig rdata
    dnskey_sig = __new_dnskey_rrsig_data(sig, sig_len);
    if (dnskey_sig == NULL) {
        cmd_set_err(err, "[%s]: new zone dnskey rrsig error\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: new zone dnskey rrsig error\n", __FUNCTION__);
        return ADNS_ADMIN_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
    }
    // get a adns_zsk_ctr_t
    zsk_ctr = adns_get_zone_zsk_ctr(dnskey_sig, tag_num, active_key, alt_zsk_tag);
    if (zsk_ctr == NULL) {
        rte_free(dnskey_sig->data);
        rdata_free(dnskey_sig, ADNS_RRTYPE_RRSIG);
        cmd_set_err(err, "[%s]: new zone zsk ctrl error\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: new zone zsk ctrl error\n", __FUNCTION__);
        return ADNS_ADMIN_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
    }

    if (zone->adns_zsk_ctr == NULL) {
        zone->adns_zsk_ctr = zsk_ctr;
        // zsk_ctr is newly set, just increment active zsk's active refcount
        DNS_DNSSEC_KEY_ACTIVE_CNT_INC(active_zsk);
    } else {
        old_zsk_ctr = zone->adns_zsk_ctr;
        zone->adns_zsk_ctr = zsk_ctr;
        typedef void (*pfn) (void *);
        ret = call_rcu((pfn)adns_put_zone_zsk_ctr, old_zsk_ctr);
        if (ret < 0) {
            zone->adns_zsk_ctr = old_zsk_ctr;
            adns_put_zone_zsk_ctr(zsk_ctr);
            cmd_set_err(err, "[%s]: replace zone zsk ctrl error\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s]: replace zone zsk ctrl error\n", __FUNCTION__);
            return ADNS_ADMIN_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
        }
        // zsk_ctr is replaced, decrement old active zsk's active ref count, increment the new active zsk's active ref count
        // old active zsk's active ref count decrement is done in adns_put_zone_zsk_ctr

        // increment new active zsk's ref count
        DNS_DNSSEC_KEY_ACTIVE_CNT_INC(active_zsk);
    }

    // dnssec is OK
    zone->dnssec_ok = 1;
    
    return 0;
}

int __add_dnskeyrrsig(struct adns_zonedb *zonedb, char *name, uint8_t *sig, uint16_t sig_len, 
                      uint16_t tag_num, uint16_t active_key, uint16_t alt_zsk_tag, char *err)
{
    adns_dname_t *zone_dname;
    struct adns_zone *zone = NULL;

    // convert zone name
    zone_dname = adns_dname_from_str(name, strlen(name));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_DNSSEC_CONVERT_ZONE_ERROR;
    }

    // find zone
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (NULL == zone) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        return ADNS_ADMIN_DNSSEC_FIND_ZONE_ERROR;
    }
    adns_dname_free(&zone_dname);

    return __add_zone_dnskeyrrsig(zone, sig, sig_len, tag_num, active_key, alt_zsk_tag, err);
}

int __del_zsk(uint16_t key_tag, char *err)
{
    adns_dnssec_key *zsk;
    int ret;

    zsk = adns_get_zsk_by_key_tag(key_tag);
    if (zsk == NULL) {
        cmd_set_err(err, "[%s]: ZSK %u not exist\n", __FUNCTION__, key_tag);
        log_server_warn(rte_lcore_id(), "[%s]: ZSK %u not exist\n", __FUNCTION__, key_tag);
        return 0;
    }
    
    // check zsk's active ref count 
    if (zsk->active_ref_cnt != 0) {
        cmd_set_err(err, "[%s]: ZSK %u still in use\n", __FUNCTION__, key_tag);
        log_server_warn(rte_lcore_id(), "[%s]: ZSK %u still in use\n", __FUNCTION__, key_tag);
        return ADNS_ADMIN_DNSSEC_DEL_ZSK_ERROR;
    }

    adns_clear_zsk_by_key_tag(key_tag);
    typedef void (*pfn) (void *);
    ret = call_rcu( (pfn)adns_put_dnssec_key, zsk);
    if (ret < 0) { //hardly go into this branch
        // recover the ZSK
        adns_set_zsk(zsk);
        cmd_set_err(err, "[%s]: Failed to del ZSK %u, call rcu error\n", __FUNCTION__, key_tag);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to del ZSK %u, call rcu error\n", __FUNCTION__, key_tag);
        return ADNS_ADMIN_DNSSEC_DEL_ZSK_ERROR;
    }
    return 0;
}

#if 0
static int __dnssec_quota(struct adns_zonedb *zonedb, char *name, uint32_t dnssec_quota, char *err)
{
    adns_dname_t *zone_dname;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(name, strlen(name));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_DNSSEC_CONVERT_ZONE_ERROR;
    }

    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (NULL == zone) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not existed\n", __FUNCTION__, name);
        return ADNS_ADMIN_DNSSEC_FIND_ZONE_ERROR;
    }

    zone->dnssec_qps_quota = dnssec_quota;
    return 0;
}
#endif

static int __dnssec_cache_flush(char *err)
{
    int ret;
    ret = adns_dnssec_cache_clean_all();
    if ((uint32_t)ret == g_dnssec_cache_num) {
        cmd_set_err(err, "[%s]: DNSSEC cache flush success\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: DNSSEC cache flush success\n", __FUNCTION__);
    } else {
        cmd_set_err(err, "[%s]: %u DNSSEC cache node unflushed\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: %u DNSSEC cache node unflushed\n", __FUNCTION__);
    }
    return 0;
}

static int __dnssec_cache_dump(const adns_dnssec_cache_db *dnssec_cache_db, char *err)
{
    FILE *fp;
    int i, fd;
    adns_dnssec_cache_hash *cache_hash;
    struct list_head *h_list;
    adns_dnssec_cache_node *node, *node_next;

    if (dnssec_cache_db == NULL) {
        cmd_set_err(err, "[%s]: dnssec_cache_db NULL\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: dnssec_cache_db NULL\n", __FUNCTION__);
        return ADNS_ADMIN_DNSSEC_CACHE_DUMP_ERROR;
    }

    fp = fopen(DUMP_PATH_DEF, "w+");
    if (fp == NULL) {
        return ADNS_ADMIN_DNSSEC_CACHE_DUMP_ERROR;
    }

    if (dnssec_cache_db->dnssec_cache_count == 0) {
        log_server_warn(rte_lcore_id(), "[%s]: dnssec_cache_db empty\n", __FUNCTION__);
        fclose(fp);
        return 0;
    }

    setvbuf(fp, NULL, _IONBF, 0);
    fd = fileno(fp);

    for (i = 0; i < ADNS_DNSSEC_CACHE_HASH_SIZE; i ++) {
        cache_hash = &(dnssec_cache_db->dnssec_cache_tbl[i]);
        if (cache_hash != NULL) {
            if (cache_hash->size != 0) {
                h_list = &(cache_hash->list);
                list_for_each_entry_safe(node, node_next, h_list, list) {
                   adns_dnssec_cache_dump_hash(fd, node);
                }
            } 
        }
    }

    fclose(fp);
    return 0;
}

static int __add_route(struct adns_zonedb *zonedb, const char *name, uint8_t *rdata, char *err)
{
    adns_dname_t *zone_name;
    struct adns_zone *zone = NULL;
    int socket_id = 0;

    zone_name = adns_dname_from_str(name, strlen(name));
    if (zone_name == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_ADD_ROUTE_CONVERT_ZONE_ERROR;
    }
    if (unlikely(zonedb == NULL)) {
        adns_dname_free(&zone_name);
        cmd_set_err(err, "[%s]: ZoneDB NULL\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: ZoneDB NULL\n", __FUNCTION__);
        return ADNS_ADMIN_ADD_ROUTE_ZONEDB_NULL;
    } 
    else {
        /* lookup zone */
        zone = adns_zonedb_lookup_exact(zonedb, zone_name);
        if (zone == NULL) {
            adns_dname_free(&zone_name);
            cmd_set_err(err, "[%s]: Zone %s not exist\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Zone %s not exist\n", __FUNCTION__, name);
            return ADNS_ADMIN_ADD_ROUTE_ZONE_NOT_EXIST;
        }
        adns_dname_free(&zone_name);

        /* zone's private route already exist */
        if (zone->ipset != NULL) {
            cmd_set_err(err, "[%s]: Private route of zone %s already exist\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Private route of zone %s already exist\n", __FUNCTION__, name);
            return 0;
        }
        /* allocate ipset for zone */
        zone->ipset = adns_ipset_alloc(socket_id);
        if (zone->ipset == NULL) {
            cmd_set_err(err, "[%s]: Allocate memory for private route of zone %s error\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Allocate memory for private route of zone %s error\n", __FUNCTION__, name);
            return ADNS_ADMIN_ADD_ROUTE_MEMORY_ERROR;
        }

        /* initialize the ipset */
        if (adns_ipset_init(zone->ipset, (char *)rdata) < 0) {
            adns_ipset_free(zone->ipset);
            zone->ipset = NULL;
            cmd_set_err(err, "[%s]: Load iplib file '%s' for private route of zone %s error\n", __FUNCTION__, rdata, name);
            log_server_warn(rte_lcore_id(), "[%s]: Load iplib file '%s' for private route of zone %s error\n", __FUNCTION__, rdata, name);
            return ADNS_ADMIN_ADD_ROUTE_IPLIB_FILE_ERROR;
        }
        
        /* enable private route */
        ZONE_ENABLE_PRIVATE_ROUTE(zone);
    }

    return 0;
}


static int __del_route(struct adns_zonedb *zonedb, char *name, char *err)
{
    int ret;
    adns_dname_t *zone_name;
    struct adns_zone *zone = NULL;

    zone_name = adns_dname_from_str(name, strlen(name));
    if (zone_name == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_DEL_ROUTE_CONVERT_ZONE_ERROR;
    }
    if (unlikely(zonedb == NULL)) {
        adns_dname_free(&zone_name);
        cmd_set_err(err, "[%s]: ZoneDB NULL\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: ZoneDB NULL\n", __FUNCTION__);
        return ADNS_ADMIN_DEL_ROUTE_ZONEDB_NULL;
    } 
    else {
        /* lookup zone */
        zone = adns_zonedb_lookup_exact(zonedb, zone_name);
        if (zone == NULL) {
            adns_dname_free(&zone_name);
            cmd_set_err(err, "[%s]: Zone %s not exist\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Zone %s not exist\n", __FUNCTION__, name);
            return ADNS_ADMIN_DEL_ROUTE_ZONE_NOT_EXIST;
        }
        adns_dname_free(&zone_name);

        /* zone has no private route */
        if (zone->ipset == NULL) {
            cmd_set_err(err, "[%s]: Zone %s has no private route\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Zone %s has no private route\n", __FUNCTION__, name);
            return 0;
        }

        /* disable private route */
        ZONE_DISABLE_PRIVATE_ROUTE(zone);

        /* delete zone's private route, add the ipset to be free in the rcu list, when all queries are finished, 
           free the ipset */
        typedef void (*pfn) (void *);
        ret = call_rcu( (pfn)adns_ipset_free, zone->ipset);
        if ( ret < 0) {
            ZONE_ENABLE_PRIVATE_ROUTE(zone);
            cmd_set_err(err, "[%s]: fail to register rcu event\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s] register rcu event, ret = %d, FAILURE\n", __FUNCTION__);
            return ADNS_ADMIN_DEL_ROUTE_RCU_REGISTER_ERROR;
        }
        /* set ipset to NULL */
        zone->ipset = NULL;
    }

    return 0;
}

static int adns_zone_reload_route(struct adns_zone *zone, const char *name, uint8_t *rdata, char *err)
{
    int ret;
    int socket_id = 0;
    adns_ipset_t *old_ipset, *new_ipset;

    /* prepare the new ipset */
    /* allocate the new ipset */
    new_ipset = adns_ipset_alloc(socket_id);
    if (new_ipset == NULL) {
        cmd_set_err(err, "[%s]: Allocate memory for new private route of zone %s error\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Allocate memory for new private route of zone %s error\n", __FUNCTION__, name);
        return ADNS_ADMIN_RELOAD_ROUTE_MEMORY_ERROR;
    }

    /* initialize the new ipset */
    if (adns_ipset_init(new_ipset, (char *)rdata) < 0) {
        adns_ipset_free(new_ipset);
        cmd_set_err(err, "[%s]: Load new iplib file '%s' for private route of zone %s error\n", __FUNCTION__, rdata, name);
        log_server_warn(rte_lcore_id(), "[%s]: Load new iplib file '%s' for private route of zone %s error\n", __FUNCTION__, rdata, name);
        return ADNS_ADMIN_RELOAD_ROUTE_IPLIB_FILE_ERROR;
    }

    /* zone has no private route */
    if (zone->ipset == NULL) {
        log_server_warn(rte_lcore_id(), "[%s]: Private route of zone %s not exist, update with new private route\n", __FUNCTION__, name);
        zone->ipset = new_ipset;
        ZONE_ENABLE_PRIVATE_ROUTE(zone);
        return 0;
    }
    else {
        /* delete zone's private route */
        old_ipset = zone->ipset;
        typedef void (*pfn) (void *);
        ret = call_rcu( (pfn)adns_ipset_free, old_ipset);
        if ( ret < 0) {
            adns_ipset_free(new_ipset);
            cmd_set_err(err, "[%s]: fail to register rcu event\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s] register rcu event, ret = %d, FAILURE\n", __FUNCTION__);
            return ADNS_ADMIN_REFRESH_ZONE_RCU_REGISTER_ERROR;
        }

        /* replace old ipset by new ipset */
        zone->ipset = new_ipset;
    }

    return 0;
}

static int __reload_route(struct adns_zonedb *zonedb, const char *name, uint8_t *rdata, char *err)
{
    int ret;
    adns_dname_t *zone_name;
    struct adns_zone *zone = NULL;
    

    zone_name = adns_dname_from_str(name, strlen(name));
    if (zone_name == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_RELOAD_ROUTE_CONVERT_ZONE_ERROR;
    }
    if (unlikely(zonedb == NULL)) {
        adns_dname_free(&zone_name);
        cmd_set_err(err, "[%s]: ZoneDB NULL\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: ZoneDB NULL\n", __FUNCTION__);
        return ADNS_ADMIN_RELOAD_ROUTE_ZONEDB_NULL;
    } 
    else {
        /* lookup zone */
        zone = adns_zonedb_lookup_exact(zonedb, zone_name);
        if (zone == NULL) {
            adns_dname_free(&zone_name);
            cmd_set_err(err, "[%s]: Zone %s not exist\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Zone %s not exist\n", __FUNCTION__, name);
            return ADNS_ADMIN_RELOAD_ROUTE_ZONE_NOT_EXIST;
        }
        adns_dname_free(&zone_name);

        ret = adns_zone_reload_route(zone, name, rdata, err);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}


static int __dump_route(struct adns_zonedb *zonedb, char *name, char *err)
{
    adns_dname_t *zone_name;
    struct adns_zone *zone = NULL;
    adns_ipset_t *ipset = NULL;
    FILE *fp;
    int len, fd;
    char buf[ADNS_LINE_MAX_LEN];
    uint16_t i;

    zone_name = adns_dname_from_str(name, strlen(name));
    if (zone_name == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, name);
        return ADNS_ADMIN_DUMP_ROUTE_CONVERT_ZONE_ERROR;
    }
    if (unlikely(zonedb == NULL)) {
        adns_dname_free(&zone_name);
        cmd_set_err(err, "[%s]: ZoneDB NULL\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: ZoneDB NULL\n", __FUNCTION__);
        return ADNS_ADMIN_DUMP_ROUTE_ZONEDB_NULL;
    } 
    else {
        /* lookup zone */
        zone = adns_zonedb_lookup_exact(zonedb, zone_name);
        if (zone == NULL) {
            adns_dname_free(&zone_name);
            cmd_set_err(err, "[%s]: Zone %s not exist\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Zone %s not exist\n", __FUNCTION__, name);
            return ADNS_ADMIN_DUMP_ROUTE_ZONE_NOT_EXIST;
        }
        adns_dname_free(&zone_name);

        ipset = zone->ipset;
        if (ipset == NULL) {
            cmd_set_err(err, "[%s]: Zone %s has no private route\n", __FUNCTION__, name);
            log_server_warn(rte_lcore_id(), "[%s]: Zone %s has no private route\n", __FUNCTION__, name);
            return 0;
        }

        fp = fopen(DUMP_PATH_DEF, "w+");
        if (fp == NULL) {
            return ADNS_ADMIN_DUMP_ROUTE_OPEN_DUMP_FILE_ERROR;
        }

        setvbuf(fp, NULL, _IONBF, 0);
        fd = fileno(fp);

        for (i = 0; i < ipset->ips_num; i ++) {
            len = snprintf(buf, ADNS_LINE_MAX_LEN, "%u %u %u\n", ipset->info4[i].ips_head, ipset->info4[i].ips_tail, ipset->info4[i].id);
            if (len < 0) {
                fclose(fp);
                unlink(DUMP_PATH_DEF);
                cmd_set_err(err, "[%s]: Dump IP segment for Zone %s error\n", __FUNCTION__, name);
                log_server_warn(rte_lcore_id(), "[%s]: Dump IP segment for Zone %s error\n", __FUNCTION__, name);
                return ADNS_ADMIN_DUMP_ROUTE_DUMP_IP_SEG_ERROR;
            }
            if (write(fd, buf, len) == 0) {
                fclose(fp);
                unlink(DUMP_PATH_DEF);
                cmd_set_err(err, "[%s]: Dump IP segment for Zone %s error\n", __FUNCTION__, name);
                log_server_warn(rte_lcore_id(), "[%s]: Dump IP segment for Zone %s error\n", __FUNCTION__, name);
                return ADNS_ADMIN_DUMP_ROUTE_DUMP_IP_SEG_ERROR;
            }
        }

        fclose(fp);
    }

    return 0;
}

/**
 * Internal function of batch/initload
 *
 * This function has two mode, up to is_init_loading.
 * if true: process every batch_entry until the end, sum up the total errors into error_collected
 * if not: exit whenever encounter an error
 * The reason of doing this is in https://aone.alibaba-inc.com/project/401991/req/9870177
 *
 * @param error_collected
 *   only takes effect when is_init_loading, pointer of the buf to collect all the errors
 * @param error_collected_max_len
 *   only takes effect when is_init_loading, the max length of error_collected
 * @return
 *   - 0: All is successful;
 *   - -1: some entry failed in is_init_loading;
 *   - -2: some entry failed in is_init_loading, and exceed the error_collected max length;
 *   - <0: specific ERRNO, not is_init_loading, and some specific entry failed.
 */
static int __batch_process(struct adns_zonedb *zonedb, struct adns_command_entry *ce,  char *err, int log_switch,
                        char *error_collected, int error_collected_max_len, int * p_total_added, int is_init_loading)
{
    int i, ret;
    uint8_t  mode;
    uint16_t opcode;
    struct batch_entry *entry;
    int total_added = 0;
    int failed_once = false;
    int buf_len_not_enough = false;
    char prev_err_zone[DOMAIN_MAX_SIZE];
    uint16_t alt_key_tag = 0;

    entry = (struct batch_entry *)(ce->rdata);

    for (i = 0; i < ce->num_cmds; i++) {
        if (i > 0) {
            entry = (struct batch_entry *) ((uint8_t*)entry + sizeof(struct batch_entry) + entry->rdata_len);
        }
        opcode = entry->opcode;
        
        switch (opcode) {
            case CMD_ADDZONE:
                ret = __add_zone(zonedb, entry->zone, (uint8_t *)entry->rdata, entry->rdata_len,
                        entry->ttl, entry->type, NULL, err);

                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -A --zone %s, ret = %d, FAILURE\n", entry->zone, ret);
                    }
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "A --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -A --zone %s, SUCCESS\n", entry->zone);
                }
                break;
                
            case CMD_EDITZONE:
                ret = __edit_zone(zonedb, entry->zone, (uint8_t *)entry->rdata, entry->rdata_len, 
                        entry->ttl, err);
                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -E --zone %s, ret = %d, FAILURE\n", entry->zone, ret);
                    }
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "E --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -E --zone %s, SUCCESS\n", entry->zone);
                }
                break;
                
            case CMD_DELZONE:
                ret = __del_zone(zonedb, entry->zone, err);
                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -D --zone %s, ret = %d, FAILURE\n", entry->zone, ret);
                    }
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "D --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -D --zone %s, SUCCESS\n", entry->zone);
                }
                break;

            case CMD_ADDRR:
                ret = __add_rr(zonedb, entry->zone, entry->domain, entry->custom_view, entry->view_id,
                        entry->type, entry->ttl, entry->rdata, entry->rdata_len,
                        entry->weight, entry->original_rdata, err);
                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -a --zone %s --domain %s --%sview %d --ttl %d --type %d -r \"%s\" -w %d, ret = %d, FAILURE\n",
                                                         entry->zone, entry->domain, entry->custom_view? CUSTOM_VIEW_PREFIX : "", entry->view_id, entry->ttl, entry->type, entry->original_rdata, entry->weight, ret);
                    }

                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "a --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -a --zone %s --domain %s --%sview %d --ttl %d --type %d -r \"%s\" -w %d, SUCCESS\n",
                                                     entry->zone, entry->domain, entry->custom_view? CUSTOM_VIEW_PREFIX : "", entry->view_id, entry->ttl, entry->type, entry->original_rdata, entry->weight);
                }
                break;
                
            case CMD_EDITRR:
                ret = __edit_rr(zonedb, entry->zone, entry->domain, entry->custom_view, entry->view_id,
                        entry->type, entry->ttl, entry->rdata, entry->rdata_len,
                        entry->weight, entry->original_rdata, err, 1);
                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -e --zone %s --domain %s --%sview %d --ttl %d --type %d -r \"%s\" -w %d, ret = %d, FAILURE\n",
                                                         entry->zone, entry->domain, entry->custom_view? CUSTOM_VIEW_PREFIX : "", entry->view_id, entry->ttl, entry->type, entry->original_rdata, entry->weight, ret);
                    }
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "e --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -e --zone %s --domain %s --%sview %d --ttl %d --type %d -r \"%s\" -w %d, SUCCESS\n",
                                                     entry->zone, entry->domain, entry->custom_view? CUSTOM_VIEW_PREFIX : "", entry->view_id, entry->ttl, entry->type, entry->original_rdata, entry->weight);
                }
                break;

            case CMD_DELRR:
                ret = __del_rr(zonedb, entry->zone, entry->domain, entry->custom_view, entry->view_id, entry->type,
                        entry->rdata, entry->rdata_len, entry->original_rdata, err);
                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -d --zone %s --domain %s --%sview %d --type %d -r \"%s\", ret = %d, FAILURE\n", 
                                                         entry->zone, entry->domain, entry->custom_view? CUSTOM_VIEW_PREFIX : "", entry->view_id, entry->type, entry->original_rdata, ret);   
                    }
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "d --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -d --zone %s --domain %s --%sview %d --type %d -r \"%s\", SUCCESS\n", 
                                                     entry->zone, entry->domain, entry->custom_view? CUSTOM_VIEW_PREFIX : "", entry->view_id, entry->type, entry->original_rdata); 
                }
                break;
                
            case CMD_DELDOMAIN:
                ret = __del_domain(zonedb, entry->zone, entry->domain, entry->custom_view, entry->view_id, err);
                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -x --zone %s --domain %s --%sview %d, ret = %d, FAILURE\n", 
                                                         entry->zone, entry->domain, entry->custom_view? CUSTOM_VIEW_PREFIX : "", entry->view_id, ret);
                    }
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "x --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -x --zone %s --domain %s --%sview %d , SUCCESS\n", 
                                                     entry->zone, entry->domain, entry->custom_view? CUSTOM_VIEW_PREFIX : "", entry->view_id);
                }
                break;
                
            case CMD_DELDOMAIN_ALL:
                ret = __del_domain_all(zonedb, entry->zone, entry->domain, NULL);
                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -O --zone %s --domain %s, ret = %d, FAILURE\n", 
                                                         entry->zone, entry->domain, ret);
                    }
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "O --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -O --zone %s --domain %s, SUCCESS\n", 
                                                      entry->zone, entry->domain);
                }
                break;
                
            case CMD_SCHEDULE_MODE:
                mode = (uint8_t)(entry->rclass);
                ret = __schedule_mode_set(zonedb, entry->zone, entry->domain, entry->type, entry->custom_view, entry->view_id, entry->weight, mode, err);
                if (ret < 0) {
                    if (log_switch) {
                        log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -k --zone %s --domain %s --view %d --mode %d, ret = %d, FAILURE\n", 
                                                         entry->zone, entry->domain, entry->view_id, mode, ret);
                    }
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "k --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm -k --zone %s --domain %s --view %d --mode %d, SUCCESS\n", 
                                                     entry->zone, entry->domain, entry->view_id, mode); 
                }
                break;

            case CMD_SET_CNAME_CASCADE:
                ret = __set_cname_cascade(zonedb, entry->zone, entry->type, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --set-cname-cascade --zone %s --cname-opt %d, ret = %d, FAILURE\n", entry->zone, entry->type, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "c --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --set-cname-cascade --zone %s --cname-opt %d, SUCCESS\n", entry->zone, entry->type);
                }
                break;

            case CMD_SET_WILDCARD_FALLBACK:
                ret = __set_wildcard_fallback(zonedb, entry->zone, entry->type, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --set-wildcard-fallback --zone %s --wildcard-opt %d, ret = %d, FAILURE\n", entry->zone, entry->type, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "w --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --set-wildcard-fallback --zone %s --wildcard-opt %d, SUCCESS\n", entry->zone, entry->type);
                }
                break;

            case CMD_ADDROUTE:
                ret = __add_route(g_datacore_db, entry->zone, (uint8_t *)entry->rdata, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --add-route --zone %s ret = %d, FAILURE\n", entry->zone, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "c --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --add-route --zone %s, SUCCESS\n", entry->zone);
                }
                break;

            case CMD_RELOADROUTE:
                ret =  __reload_route(g_datacore_db, entry->zone, (uint8_t *)entry->rdata, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --reload-route --zone %s ret = %d, FAILURE\n", entry->zone, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "c --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --reload-route --zone %s, SUCCESS\n", entry->zone);
                }
                break;

            case CMD_DELROUTE:
                ret = __del_route(g_datacore_db, entry->zone, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --del-route --zone %s ret = %d, FAILURE\n", entry->zone, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "c --zone %s, has failed, ret = %d, please refresh the zone;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --del-route --zone %s, SUCCESS\n", entry->zone);
                }
                break;

            case CMD_SET_DNSSEC:
                ret = __set_dnssec(g_datacore_db, entry->zone, entry->type, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --set-dnssec --zone %s -dnssec-opt %u ret = %d, FAILURE\n", entry->zone, entry->type, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "n --zone %s, -dnssec-opt %u has failed, ret = %d, please refresh the zone;\n", entry->zone, entry->type, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --set-dnssec --zone %s, -dnssec-opt %d SUCCESS\n", entry->zone, entry->type);
                }
                break;

            case CMD_DNSSEC_ADD_KEY:
                ret = __add_key(entry->rdata, entry->rdata_len, entry->type, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --add-key type %u ret = %d, FAILURE\n", entry->type, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "i type %u has failed, ret = %d;\n", entry->type, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --add-key -t %u, SUCCESS\n", entry->type);
                }
                break;

            case CMD_DNSSEC_DEL_ZSK:
                ret = __del_zsk(entry->type, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --del-zsk %u ret = %d, FAILURE\n", entry->type, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "g %u has failed, ret = %d;\n", entry->type, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --del-zsk %u, SUCCESS\n", entry->type);
                }
                break;

            case CMD_DNSSEC_ADD_DNSKEY_RRSIG:
                if (entry->ttl > 1) {
                    alt_key_tag = (entry->weight == entry->type)? entry->rclass : entry->type;
                }
                ret = __add_dnskeyrrsig(g_datacore_db, entry->zone, (uint8_t *)entry->rdata, entry->rdata_len, entry->ttl, entry->weight, alt_key_tag, err);
                if (ret < 0) {
                    log_server_warn(rte_lcore_id(), "adns_adm --add-dnskeyrrsig --zone %s ret = %d, FAILURE\n", entry->zone, ret);
                    if (is_init_loading) {
                        int append_ret = -1;

                        failed_once = true;
                        append_ret = init_load_append_err(error_collected + total_added, error_collected_max_len - total_added, prev_err_zone, entry->zone,
                                                    "G %s has failed, ret = %d;\n", entry->zone, ret);
                        total_added += (append_ret > 0) ? append_ret : 0;
                        buf_len_not_enough = (append_ret == -1) ? 1 : 0;
                        break;
                    }
                    return ret;
                }

                if (log_switch) {
                    log_server_warn(rte_lcore_id(), "(BATCH) adns_adm --add-dnskeyrrsig --zone %s, SUCCESS\n", entry->zone);
                }
                break;
                
            default:
                break;
        }
    }

    if ( is_init_loading == true ) {
        *p_total_added = total_added;
        if (failed_once == true && buf_len_not_enough == false) {
            return -1;
        }
        if (failed_once == true && buf_len_not_enough == true) {
            return -2;
        }
    }
    return 0;
}

/*
 * refresh a zone, use an new zone to replace the old one
 * @name: zone name, old and new are the same
 * @new_zone: the newly constructed zone
 * @old_zone: the old zone to be replaced
 */
int do_replace_zone(const char * name, struct adns_zone * old_zone, struct adns_zone * new_zone, char *err)
{
    if (old_zone == NULL && new_zone != NULL) {
        return adns_zonedb_add_zone(g_datacore_db, new_zone);
    }

    if (memcmp(old_zone->name, new_zone->name, old_zone->name_len) != 0) {
        return -1;
    }

    list_replace(&(old_zone->list), &(new_zone->list));

    return 0;
}

static int __refresh_zone(struct adns_zonedb *zonedb, struct adns_command_entry *ce, char *err)
{
    int i, ret;
    uint16_t opcode;
    uint8_t sched_mode, cname_cascade_switch, wildcard_fallback_switch, dnssec_enable;
    struct batch_entry * entry;
    struct adns_zone * old_zone = NULL;
    struct adns_zone * new_zone = NULL;
    struct adns_node * node = NULL;
    char * zone_str = NULL;
    struct adns_node * node_hint = NULL;
    uint16_t alt_zsk = 0;

    /* handle the first entry */
    entry = (struct batch_entry *)(ce->rdata);
    if (entry->opcode != CMD_ADDZONE) {
        cmd_set_err(err, "[%s]: the first line of rz-batch should be an entry adding zone", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: the first line of rz-batch should be an entry adding zone, FAILURE\n", __FUNCTION__);
        return ADNS_ADMIN_REFRESH_ZONE_BATCH_SYNTAX_ERROR;
    }
    zone_str = entry->zone;
    ret = adns_zonedb_get_zone(zonedb, zone_str, &old_zone, err);
    if (ret < 0 && ret != -3) {
        /* old_zone == NULL, i.e. ret == -3, is not taken as a mistake, in that case we just add the new zone laterly */
        log_server_warn(rte_lcore_id(), "[%s] find old zone %s, ret = %d, FAILURE\n", __FUNCTION__, zone_str, ret);
        return ADNS_ADMIN_REFRESH_ZONE_CONVERT_ZONE_ERROR;
    }
    /* call __add_zone() with db == NULL to create a dangled new zone struct */
    ret = __add_zone(NULL, zone_str, (uint8_t *)entry->rdata, entry->rdata_len,
                    entry->ttl, entry->type, &new_zone, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s] create dangled new zone %s, ret = %d, FAILURE\n",
                __FUNCTION__, zone_str, ret);
        return ADNS_ADMIN_REFRESH_ZONE_CREATE_NEW_ERROR;
    }

    for (i = 1; i < ce->num_cmds; i++) { // start from 1, not 0
        entry = (struct batch_entry *) ((uint8_t*)entry + sizeof(struct batch_entry) + entry->rdata_len);
        opcode = entry->opcode;

        switch (opcode) {
            case CMD_ADDRR:
                node_hint = NULL;
                if (new_zone == NULL) {
                    goto no_new_zone;
                }
                ret = adns_zone_add_rr(new_zone, entry->domain, entry->custom_view, entry->view_id, entry->type, entry->ttl,
                        entry->rdata, entry->rdata_len, entry->weight, entry->original_rdata, err, &node_hint);
                if (ret < 0) {
                    adns_zone_free(new_zone);
                    log_server_warn(rte_lcore_id(), "[%s] attach record to new zone, ret = %d, FAILURE\n", __FUNCTION__, ret);
                    return ret;
                }
                break;

            case CMD_SCHEDULE_MODE:
                if (new_zone == NULL) {
                    goto no_new_zone;
                }
                ret = adns_zone_get_node(new_zone, entry->domain, &node, err);
                if (ret < 0 || node == NULL) {
                    adns_zone_free(new_zone);
                    cmd_set_err(err, "[%s]: fail to get node %s when set schedule mode, "
                                    "check if a record is added before this entry.\n", __FUNCTION__, entry->domain);
                    log_server_warn(rte_lcore_id(), "[%s]: get node %s when set schedule mode, FAILURE\n", __FUNCTION__, entry->domain);
                    return ADNS_ADMIN_REFRESH_ZONE_SET_SCHED_ERROR;
                }
                sched_mode = (uint8_t)(entry->rclass);
                if (entry->type == ADNS_RRTYPE_AAAA) {
                    node->AAAA_schedule_mode = sched_mode;
                } else {
                    node->A_schedule_mode = sched_mode;
                }
                
                break;

            case CMD_SET_CNAME_CASCADE:
                if (new_zone == NULL) {
                    goto no_new_zone;
                }
                cname_cascade_switch = (uint8_t)entry->type;
                new_zone->enable_cname_cascade = cname_cascade_switch;
                break;

            case CMD_SET_WILDCARD_FALLBACK:
                if (new_zone == NULL) {
                    goto no_new_zone;
                }
                wildcard_fallback_switch = (uint8_t)entry->type;
                new_zone->wildcard_fallback_enable = wildcard_fallback_switch;
                break;

            case CMD_RELOADROUTE:
                if (new_zone == NULL) {
                    goto no_new_zone;
                }
                ret = adns_zone_reload_route(new_zone, entry->zone, (uint8_t *)entry->rdata, err);
                if (ret < 0) {
                    adns_zone_free(new_zone);
                    cmd_set_err(err, "[%s]: fail to reload route for zone '%s'\n", __FUNCTION__, entry->zone);
                    log_server_warn(rte_lcore_id(), "[%s]: fail to reload route for zone '%s'\n", __FUNCTION__, entry->zone);
                    return ADNS_ADMIN_REFRESH_ZONE_RELOAD_ROUTE_ERROR;
                }
                break;

            case CMD_SET_DNSSEC:
                if (new_zone == NULL) {
                    goto no_new_zone;
                }
                dnssec_enable = (uint8_t)entry->type;
                ret = __set_zone_dnssec(new_zone, dnssec_enable, err);
                if (ret < 0) {
                    adns_zone_free(new_zone);
                    cmd_set_err(err, "[%s]: fail to set dnssec opt %u for zone '%s'\n", __FUNCTION__, dnssec_enable, entry->zone);
                    log_server_warn(rte_lcore_id(), "[%s]: fail to set dnssec opt %u for zone '%s'\n", __FUNCTION__, dnssec_enable, entry->zone);
                    return ret;
                }
                break;

            case CMD_DNSSEC_ADD_DNSKEY_RRSIG:
                if (new_zone == NULL) {
                    goto no_new_zone;
                }
                if (entry->ttl > 1) {
                    alt_zsk = (entry->type == entry->weight)? entry->rclass : entry->type;
                }
                ret = __add_zone_dnskeyrrsig(new_zone, (uint8_t *)entry->rdata, entry->rdata_len, entry->ttl, entry->weight, alt_zsk, err);
                if (ret < 0) {
                    adns_zone_free(new_zone);
                    cmd_set_err(err, "[%s]: fail to add dnskeyrrsig for zone '%s'\n", __FUNCTION__, entry->zone);
                    log_server_warn(rte_lcore_id(), "[%s]: fail to add dnskeyrrsig for zone '%s'\n", __FUNCTION__, entry->zone);
                    return ret;
                }
                break;

            default:
                cmd_set_err(err, "[%s]: unsupported cmd type in rz-batch", __FUNCTION__);
                log_server_warn(rte_lcore_id(), "[%s]: unsupported cmd type in rz-batch, FAILURE\n", __FUNCTION__);
                return ADNS_ADMIN_REFRESH_ZONE_BATCH_SYNTAX_ERROR;
        }
    }

    ret = do_replace_zone(zone_str, old_zone, new_zone, err);
    if (ret < 0) {
        // failure conditions include: 1, old_zone is null, adding fails; 2, not the same zone somehow, will not replace
        adns_zone_free(new_zone);
        cmd_set_err(err, "[%s]: fail to replace zone, ret = %d\n", __FUNCTION__, ret);
        log_server_warn(rte_lcore_id(), "[%s]: replace zone, ret = %d\n, FAILURE", __FUNCTION__, ret);
        return ADNS_ADMIN_REFRESH_ZONE_REPLACE_ERROR;
    }

    typedef void (*pfn) (void *);
    ret = call_rcu( (pfn)adns_zone_free, old_zone);
    if (ret < 0) {
        adns_zone_free(old_zone);
        cmd_set_err(err, "[%s]: fail to register rcu event\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s] register rcu event, ret = %d, FAILURE\n", __FUNCTION__);
        return ADNS_ADMIN_REFRESH_ZONE_RCU_REGISTER_ERROR;
    }
    return 0;

no_new_zone:
    cmd_set_err(err, "[%s]: New zone is not constructed, "
                     "check if \"A\" is passed in from the start.\n", __FUNCTION__);
    log_server_warn(rte_lcore_id(), "[%s] no new zone is found, FAILURE\n", __FUNCTION__);
    return ADNS_ADMIN_REFRESH_ZONE_NO_NEW_ERROR;
}

/*
 * Tasks that affect other objects (except the dangled node) are done here.
 * Includes:
 *   (1) link to the zone->tbl
 *   (2) zone->wild_tag[], include NS types
 *   (3) link node_stub to rlist
 *
 * when del a wildcard (child) node, also includes:
 *   (2) parent->wildcard_child
 *   (3) parent->node_tag[]
 *
 * when del a parent node, also includes:
 *   (2) child->parent
 *   (3) node->node_tag[], part of which comes from its wildcard child node
 */
int do_replace_node(struct adns_zone *zone, const char * domain_name, struct adns_node *old_node, struct adns_node *new_node,
                adns_viewid_t ns_view_list[], adns_viewid_t view_list[], char * err_buf)
{
    int ret = -1;
    uint32_t hash;
    int hashed_io_core_id = 0;
    adns_viewid_t view_id;

    if (old_node == NULL || new_node == NULL ) {
        log_server_error(rte_lcore_id(), "[%s]: node structures error, old_node=%p, new_node=%p\n",
                __FUNCTION__, (void*)old_node, (void*)new_node);
        return -1;
    }

    for (view_id = 0; view_id < g_view_max_num + g_private_route_per_zone_max_num; view_id++) {
        if (ns_view_list[view_id] != 0) {
            SET_TAG(zone->wild_tag, view_id);
        }
    }

    /* is a parent node */
    if (old_node->wildcard_child != NULL) {
        struct adns_node * cur_node_child = old_node->wildcard_child;
        /* new_node->wildcard_child is set in __refresh_domain_create_node_dangled() */
        cur_node_child->parent = new_node;
        for (view_id = 0; view_id < g_view_max_num + g_private_route_per_zone_max_num; view_id++) {
            if (GET_TAG(cur_node_child->node_tag, view_id) != 0) {
                SET_TAG(new_node->node_tag, view_id);
            }
        }
    }

    /* is a wildcard (child) node */
    if (adns_dname_is_wildcard(old_node->name)) {
        struct adns_node * parent_node = old_node->parent;

        /* mark node_tag of parent_node using views from the parent node itself */
        parent_node->wildcard_child = NULL; /* set to NULL temporarily to use node_update_tag() */
        for (view_id = 0; view_id < g_view_max_num + g_private_route_per_zone_max_num; view_id++) {
            node_update_tag(parent_node, 0, view_id);
        }
        parent_node->wildcard_child = new_node;

        /* mark node_tag of parent_node using views from the child */
        for (view_id = 0; view_id < g_view_max_num + g_private_route_per_zone_max_num; view_id++) {
            if (view_list[view_id] != 0) {
                SET_TAG(parent_node->node_tag, view_id);
                SET_TAG(zone->wild_tag, view_id);
            }
        }
    }

    /* core replacement part */
    list_replace(&(old_node->list), &(new_node->list));
    ret = adns_domain_replace_hash(zone, old_node->name, new_node);
    if (ret == -1) {
        // -1 means find old domain hash node failure
        ret = adns_domain_add_hash(new_node, new_node->name);
        if (ret < 0) {
            // nothing else better to do
            return -2;
        }
    }

    /* node stub for query statistic reporting */
    hash = mm3_hash((const char *)domain_name, new_node->name_len);
    if (g_syslog_ctl.domain_sta_on != 0 || g_syslog_ctl.domain_sta_log_on != 0) {
        hashed_io_core_id = hash % app.lcore_io_num;
        ret = rlist_add_tail(&(new_node->p_stub->rlist_entry), hashed_io_core_id);
        if (ret != 0) {
            log_server_error(rte_lcore_id(), "[%s]: rlist_add_tail fail\n", __FUNCTION__);
            return -3;
        }
    }

    return 0;
}

/*
 * Create a dangled node struct, relation with other objects are done in do_node_replace()
 * (here we must maintain no visibility to other data structs, visibility is finally constructed in do_replace_node()
 * Notice:
 * if a wildcard child node, the node->parent is assigned here,
 *      but its parent node's pointer to child is set later
 * if a wildcard parent node, the node->wildcard_child is assgined here,
 *      but its child node's pointer to parent is set later
 */
int __refresh_domain_create_node_dangled(struct adns_zone * zone, const char *domain, 
        struct adns_node * old_node_parent, struct adns_node * old_node_child, struct adns_node ** p_node, char *err)
{
    int ret = -1;

    adns_dname_t *dname = NULL;

    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: convert domain %s, FAILURE.\n", __FUNCTION__, domain);
        return ADNS_ADMIN_REFRESH_DOMAIN_CONVERT_DOMAIN_ERROR;
    }

    *p_node = adns_node_new(dname);
    if (*p_node == NULL) {
        adns_dname_free(&dname);
        cmd_set_err(err, "[%s]: Failed to create node %s, g_domain_num = %d\n", __FUNCTION__, domain, g_domain_num);
        log_server_warn(rte_lcore_id(), "[%s]: create node %s, g_domain_num = %d, FAILURE.\n", __FUNCTION__, domain, g_domain_num);
        return ADNS_ADMIN_REFRESH_DOMAIN_CREATE_NEW_DOMAIN_ERROR;
    }

    ret = adns_zone_check_node(zone, *p_node);    // check node is sub-domain of zone.
    if (ret < 0) {
        adns_dname_free(&dname);
        adns_node_free(*p_node);
        log_server_warn(rte_lcore_id(), "[%s]: The node %s is not the subdomain of zone %s\n", __FUNCTION__, dname, zone->name);
        return ADNS_ADMIN_REFRESH_DOMAIN_CREATE_NEW_DOMAIN_ERROR;
    }

    if (old_node_child != NULL) {
        (*p_node)->wildcard_child = old_node_child;
    }

    /* set wildcard parent */
    if ( adns_dname_is_wildcard(dname) ) {
        if (old_node_parent == NULL) {
            adns_dname_free(&dname);
            adns_node_free(*p_node);
            cmd_set_err(err, "[%s]: Wildcard node %s parent pointer is null.\n", __FUNCTION__, domain);
            log_server_warn(rte_lcore_id(), "[%s]: Wildcard node %s parent pointer is null, FAILURE.\n", __FUNCTION__, domain);
            return ADNS_ADMIN_REFRESH_DOMAIN_WILDCARD_NO_PARENT;
        }
        else {
            (*p_node)->parent = old_node_parent;
        }
    }

    (*p_node)->zone = zone;

    adns_dname_free(&dname);

    return 0;
}

static int __refresh_domain_check_batch_consistency(char * curr_zone_str, char * curr_node_str,
        char * orig_zone_str, char * orig_node_str, char * err)
{
    if (strcmp(curr_zone_str, orig_zone_str) != 0) {
        cmd_set_err(err, "[%s]: zone is not consistent, former %s, current %s",
                    __FUNCTION__, orig_zone_str, curr_zone_str);
        log_server_warn(rte_lcore_id(),"[%s]: zone is not consistent, former %s, current %s \n",
                    __FUNCTION__, orig_zone_str, curr_zone_str);
        return ADNS_ADMIN_REFRESH_DOMAIN_ZONE_CONSISTENCY_ERROR;
    }
    if (strcmp(curr_node_str, orig_node_str) != 0) {
        cmd_set_err(err, "[%s]: domain is not consistent, former %s, current %s",
                    __FUNCTION__, orig_node_str, curr_node_str);
        log_server_warn(rte_lcore_id(),"[%s]: domain is not consistent, former %s, current %s \n",
                    __FUNCTION__, orig_node_str, curr_node_str);
        return ADNS_ADMIN_REFRESH_DOMAIN_NODE_CONSISTENCY_ERROR;
    }
    return 0;
}

static int __refresh_domain(struct adns_zonedb *zonedb, struct adns_command_entry *ce, char *err)
{
    int i, ret;
    uint8_t sched_mode;
    struct batch_entry * entry;
    uint16_t total_view_num = g_view_max_num + g_private_route_per_zone_max_num;
    adns_viewid_t ns_view_list[total_view_num], view_list[total_view_num];
    memset(ns_view_list, 0, sizeof(adns_viewid_t) * total_view_num);
    memset(view_list, 0, sizeof(adns_viewid_t) * total_view_num);

    char * orig_zone_str = NULL;
    struct adns_zone * zone = NULL;

    char * orig_node_str = NULL;
    struct adns_node * old_node = NULL;
    struct adns_node * new_node = NULL;
    uint8_t zone_apex = 0;

    // the first entry is used to decide the zone and domain to refresh, so handle it in first place
    // later entries should be of the same zone and domain with this first entry
    entry = (struct batch_entry *)(ce->rdata);
    if (entry->opcode != CMD_ADDRR) {
        cmd_set_err(err, "[%s]: the first line of rd-batch should be an entry adding rr", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: the first line of rd-batch should be an entry adding rr, FAILURE\n", __FUNCTION__);
        return ADNS_ADMIN_REFRESH_DOMAIN_BATCH_SYNTAX_ERROR;
    }

    orig_zone_str = entry->zone;
    ret = adns_zonedb_get_zone(zonedb, orig_zone_str, &zone, err);
    if (ret < 0 || zone == NULL) {
        log_server_warn(rte_lcore_id(), "[%s] find zone %s, ret = %d, FAILURE\n", __FUNCTION__, orig_zone_str, ret);
        return ADNS_ADMIN_REFRESH_DOMAIN_FIND_ZONE_ERROR;
    }

    orig_node_str = entry->domain;
    ret = adns_zone_get_node(zone, orig_node_str, &old_node, err);
    if (ret < 0 && ret != -3) {
        // find internal error
        return ADNS_ADMIN_REFRESH_DOMAIN_FIND_NODE_ERROR;
    } else if (ret == -3) {
        // old node does not exist, just use the normal adding.
        for (i = 0; i < ce->num_cmds; i++) {
            // reuse __batch_process(), only checking the formality here
            switch (entry->opcode) {
                case CMD_ADDRR:
                case CMD_SCHEDULE_MODE:
                    ret = __refresh_domain_check_batch_consistency(entry->zone, entry->domain, orig_zone_str, orig_node_str, err);
                    if (ret < 0) {
                        return ret;
                    }
                    break;
                default:
                    cmd_set_err(err, "[%s]: unsupported cmd type in rd-batch", __FUNCTION__);
                    log_server_warn(rte_lcore_id(), "[%s]: unsupported cmd type in rd-batch, FAILURE\n", __FUNCTION__);
                    return ADNS_ADMIN_REFRESH_DOMAIN_BATCH_SYNTAX_ERROR;
            }
            entry = (struct batch_entry *) ((uint8_t*)entry + sizeof(struct batch_entry) + entry->rdata_len);
        }
        return __batch_process(zonedb, ce, err, 1, NULL, 0, NULL, 0);
    } else {
        // find old node succeed, old node exists. Attach rr to the dangled node, replace and call rcu to free.
        ret = __refresh_domain_create_node_dangled(zone, orig_node_str, old_node->parent, old_node->wildcard_child, &new_node, err);
        if (ret < 0 || new_node == NULL) {
            return ret;
        }

        for (i = 0; i < ce->num_cmds; i++) {
            switch (entry->opcode) {
                case CMD_ADDRR:
                    ret = __refresh_domain_check_batch_consistency(entry->zone, entry->domain, orig_zone_str, orig_node_str, err);
                    if (ret < 0) {
                        adns_node_free(new_node);
                        return ret;
                    }
                    /* if the domain name equals to the zone name, the domain is zone apex */
                    if (new_node->name_len == zone->name_len) {
                        zone_apex = 1;
                    }
                    ret = adns_node_add_rr(new_node, entry->domain, entry->custom_view, entry->view_id, entry->type, entry->ttl, entry->rdata,
                                entry->rdata_len, entry->weight, entry->original_rdata, err, zone_apex);
                    if (ret < 0) {
                        adns_node_free(new_node);
                        return ret;
                    }
                    if (entry->type == ADNS_RRTYPE_NS) {
                        ns_view_list[entry->custom_view? entry->view_id + g_view_max_num : entry->view_id] = 1;
                    }
                    view_list[entry->custom_view? entry->view_id + g_view_max_num : entry->view_id] = 1;
                    break;

                case CMD_SCHEDULE_MODE:
                    ret = __refresh_domain_check_batch_consistency(entry->zone, entry->domain, orig_zone_str, orig_node_str, err);
                    if (ret < 0) {
                        adns_node_free(new_node);
                        return ret;
                    }
                    sched_mode = (uint8_t)(entry->rclass);
                    if (entry->type == ADNS_RRTYPE_AAAA) {
                        new_node->AAAA_schedule_mode = sched_mode;
                    } else {
                        new_node->A_schedule_mode = sched_mode;
                    }

                    break;

                default:
                    cmd_set_err(err, "[%s]: unsupported cmd type in rd-batch", __FUNCTION__);
                    log_server_warn(rte_lcore_id(), "[%s]: unsupported cmd type in rd-batch, FAILURE\n", __FUNCTION__);
                    adns_node_free(new_node);
                    return ADNS_ADMIN_REFRESH_DOMAIN_BATCH_SYNTAX_ERROR;
            }
            entry = (struct batch_entry *) ((uint8_t*)entry + sizeof(struct batch_entry) + entry->rdata_len);
        }

        ret = do_replace_node(zone, orig_node_str, old_node, new_node, ns_view_list, view_list, err);
        if (ret < 0) {
            if (ret == -1 || ret == -2) {
                adns_node_free(new_node); // repalce node internal error, new node not added
            }
            cmd_set_err(err, "[%s]: fail to replace node %s\n", __FUNCTION__, orig_node_str);
            log_server_warn(rte_lcore_id(), "[%s]: replace zone, ret = %d\n, FAILURE", __FUNCTION__, ret);
            ret = ADNS_ADMIN_REFRESH_DOMAIN_REPLACE_ERROR;
        }

        typedef void (*pfn) (void *);
        ret = call_rcu( (pfn)adns_node_free, old_node);
        if (ret < 0) {
            adns_node_free(old_node);
            cmd_set_err(err, "[%s]: fail to register rcu event\n", __FUNCTION__);
            log_server_warn(rte_lcore_id(), "[%s] register rcu event, ret = %d, FAILURE\n", __FUNCTION__);
            return ADNS_ADMIN_REFRESH_DOMAIN_RCU_REGISTER_ERROR;
        }
        return ret;
    }
}

static void master_refresh_domain(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_REFRESH_DOMAIN;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    log_server_warn(rte_lcore_id(), "adns_adm -M, START SUCCESS\n");
    ret = __refresh_domain(g_datacore_db, ce, cmd_resp->err_msg);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "adns_adm -M, STOP FAILURE\n");
        cmd_resp->ret_val = ret;
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -M, FINISH SUCCESS\n");
}

static void master_batch(ioClient *c)
{
    int ret;     
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;    
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_BATCH;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    log_server_warn(rte_lcore_id(), "adns_adm -b, START SUCCESS\n");
    ret = __batch_process(g_datacore_db, ce, cmd_resp->err_msg, 1, NULL, 0, NULL, 0);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "adns_adm -b, STOP FAILURE\n");
        cmd_resp->ret_val = ret;
        return;
    }    
    
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -b, FINISH SUCCESS\n");
}

static void master_refresh_zone(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_REFRESH_ZONE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    log_server_warn(rte_lcore_id(), "adns_adm -R, START SUCCESS\n");
    ret = __refresh_zone(g_datacore_db, ce, cmd_resp->err_msg);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "adns_adm -R, STOP FAILURE\n");
        cmd_resp->ret_val = ret;
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -R, FINISH SUCCESS\n");
}

static void master_initload(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    int total_added = 0;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_INITLOAD;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    log_server_warn(rte_lcore_id(), "adns_adm --initload, START SUCCESS\n");
    ret = __batch_process(g_datacore_db, ce, cmd_resp->err_msg, 1, c->buf + c->buf_size, ADNS_ADM_MAX_REPLY_LEN - c->buf_size, &total_added, 1);
    if (ret < 0) {
        c->buf_size += total_added;
        *len = htons(sizeof(struct cmd_resp) + total_added);

        g_init_done = 1;
        cmd_resp->init_done = g_init_done;

        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --initload, STOP FAILURE\n");

        return;
    }

    g_init_done = 1;
    cmd_resp->init_done = g_init_done;

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --initload, FINISH SUCCESS\n");
}


static void master_get_info(ioClient *c)
{
    char *buf;
    int i;
    struct adns_info info;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
        
    *len = htons(sizeof(struct cmd_resp) + sizeof(struct adns_info));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_SHOW;
    c->bufpos = c->query_size;
    c->buf_size = sizeof(uint16_t) + sizeof(struct cmd_resp) + sizeof(struct adns_info);
    buf = c->buf + sizeof(struct cmd_resp) + 2;
    
    info.zone_max_num = g_zone_max_num;
    if (info.zone_max_num == 0){
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_ZONE_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.zone_num = g_zone_num;

    info.private_route_zone_max_num = g_private_route_zone_max_num;
    if (info.private_route_zone_max_num == 0){
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_PRIVATE_ROUTE_ZONE_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.private_route_zone_num = g_private_route_zone_num;

    info.dnssec_zone_max_num = g_dnssec_zone_max_num;
    if (info.dnssec_zone_max_num == 0){
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_DNSSEC_ZONE_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.dnssec_zone_num = g_dnssec_zone_num;

    info.dnssec_cache_max_num = g_dnssec_cache_max_num;
    if (info.dnssec_cache_max_num == 0){
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_DNSSEC_CACHE_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.dnssec_cache_num = g_dnssec_cache_num;

    info.domain_max_num = g_domain_max_num;
    if (info.domain_max_num == 0){
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_DOMAIN_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.domain_num = g_domain_num;

    info.rr_max_num = g_rr_max_num;
    if (info.rr_max_num == 0){
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_RR_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.rr_num = g_rr_num;
    memcpy(&(info.rr_detail_num), &g_rr_detail_num, sizeof(struct rr_detail_num_t));

    info.rdata_ctl_max_num = g_rdata_ctl_max_num;
    if (info.rdata_ctl_max_num == 0){
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_DOMAIN_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.rdata_ctl_num = g_rdata_ctl_num;

    info.private_rdata_ctl_max_num = g_private_rdata_ctl_max_num;
    if (info.private_rdata_ctl_max_num == 0) {
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_DOMAIN_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.private_rdata_ctl_num = g_private_rdata_ctl_num;

    info.rrset_memory_max_num = g_rrset_memory_max_num;
    if(info.rrset_memory_max_num == 0){
        cmd_resp->ret_val = ADNS_ADMIN_SHOW_MAX_DOMAIN_NUM_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --SHOW, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }
    info.rrset_memory_num = g_rrset_memory_num;

    for (i = 0; i < NAME_LEN_TYPE_NUM; ++i) {
        info.domain_name_max_num[i] = g_domain_name_max_num[i];
        info.domain_name_used_num[i] = g_domain_name_used_num[i];
        info.zone_name_max_num[i] = g_zone_name_max_num[i];
        info.zone_name_used_num[i] = g_zone_name_used_num[i];
    }

    memcpy(buf, &info, sizeof(struct adns_info));
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --show, zone_num = %d, domain_num = %d, rr_num = %d, SUCCESS\n", g_zone_num, g_domain_num, g_rr_num);
}

static void master_get_dpdk_heap(ioClient *c)
{
	int socket;
    char *buf;
	struct rte_malloc_socket_stats sock_stats;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_malloc_socket_stats tmp_stats[RTE_MAX_NUMA_NODES];

    memset(tmp_stats, 0, sizeof(tmp_stats));

    *len = htons(sizeof(struct cmd_resp) + sizeof(tmp_stats));
    
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_SHOW_DPDK_HEAP;
    c->bufpos = c->query_size;
    c->buf_size = sizeof(uint16_t) + sizeof(struct cmd_resp) + sizeof(tmp_stats);
    buf = c->buf + sizeof(struct cmd_resp) + 2;

	/* Iterate through all initialised heaps */
	for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
		if ((rte_malloc_get_socket_stats(socket, &sock_stats) < 0))
			continue;

        tmp_stats[socket].heap_totalsz_bytes = sock_stats.heap_totalsz_bytes;
        tmp_stats[socket].heap_freesz_bytes = sock_stats.heap_freesz_bytes;
        tmp_stats[socket].heap_allocsz_bytes = sock_stats.heap_allocsz_bytes;
        tmp_stats[socket].greatest_free_size = sock_stats.greatest_free_size;
        tmp_stats[socket].alloc_count = sock_stats.alloc_count;
        tmp_stats[socket].free_count = sock_stats.free_count;
	}

    memcpy(buf, tmp_stats, sizeof(tmp_stats));
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --show-dpdk-heap, SUCCESS\n");
	return;
}

static void master_status(ioClient *c)
{
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;

    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_STATUS;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    cmd_resp->init_done = g_init_done;
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --status, SUCCESS\n"); 
}


static void master_stats(ioClient *c)
{
    char *buf;
    struct adns_stats st;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
  
    *len = htons(sizeof(struct cmd_resp) + sizeof(struct adns_stats));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_STATS;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp) + sizeof(struct adns_stats);
    buf = c->buf + sizeof(struct cmd_resp) + 2;
    
    adns_stats_sum(&st);
    memcpy(buf, &st, sizeof(struct adns_stats));

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --stats, qps = %llu, query = %llu, answer = %llu, SUCCESS\n", st.qps, st.query, st.answer);
}

static void master_tcpstats(ioClient *c)
{
    char *buf;
    struct adns_stats st;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
  
    *len = htons(sizeof(struct cmd_resp) + sizeof(struct adns_stats));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_TCPSTATS;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp) + sizeof(struct adns_stats);
    buf = c->buf + sizeof(struct cmd_resp) + 2;
    
    adns_tcpstats_sum(&st);
    memcpy(buf, &st, sizeof(struct adns_stats));

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --stats, qps = %llu, query = %llu, answer = %llu, SUCCESS\n", st.qps, st.query, st.answer);
}

static void master_get_counter_value(ioClient *c)
{       
    int ret, i;
    char *buf;
    uint64_t value = 0;
    uint64_t counter_value[ADNS_PKT_DROP_COUNTER_MAX];
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    
    *len = htons(sizeof(struct cmd_resp) + sizeof(uint64_t) * ADNS_PKT_DROP_COUNTER_MAX);
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_COUNTER;
    c->bufpos = c->query_size;
    c->buf_size = sizeof(uint16_t) + sizeof(struct cmd_resp) + sizeof(uint64_t) * ADNS_PKT_DROP_COUNTER_MAX;
    buf = c->buf + sizeof(struct cmd_resp) + 2;

    for(i = 0; i < ADNS_PKT_DROP_COUNTER_MAX; i++){
        ret = adns_counter_sum_get(g_adns_pkt_drop_counter[i], &value);
        if (ret != 0) {
            cmd_resp->ret_val = ADNS_ADMIN_COUNTER_ERROR;
            log_server_warn(rte_lcore_id(), "adns_adm --counter, ret = %d, FAILURE\n", cmd_resp->ret_val);
            return;
        }
        counter_value[i] = value;
    }

    memcpy(buf, counter_value, sizeof(counter_value));
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --counter, SUCCESS\n");
}


static void master_get_rcode_stats(ioClient *c)
{
    int ret, i;
    char *buf;
    uint64_t value = 0;
    uint64_t counter_value[ADNS_RCODE_COUNTER_MAX];
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
  
    *len = htons(sizeof(struct cmd_resp) + sizeof(uint64_t) * ADNS_RCODE_COUNTER_MAX);
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_RCODE_STATS;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp) + sizeof(uint64_t) * ADNS_RCODE_COUNTER_MAX;
    buf = c->buf + sizeof(struct cmd_resp) + 2;

    for (i = 0; i < ADNS_RCODE_COUNTER_MAX; i++){
        ret = adns_counter_sum_get(g_adns_pkt_rcode_counter[i], &value);
        if (ret != 0) {
            cmd_resp->ret_val = ADNS_ADMIN_RCODE_STATS_ERROR;
            log_server_warn(rte_lcore_id(), "adns_adm --rcode-stats, ret = %d, FAILURE\n", cmd_resp->ret_val);
            return;
        }
        counter_value[i] = value;
    } 
  
    memcpy(buf, counter_value, sizeof(counter_value));
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --rcode-stats, SUCCESS\n");
}


static void master_get_dev_stats(ioClient *c)
{   
    int i, j, port_num;
    char *buf;
    struct rte_eth_stats dev_stats[RTE_MAX_ETHPORTS]; 
    struct adns_dpdk_port_stats tmp_stats[RTE_MAX_ETHPORTS];
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
        
    memset(dev_stats, 0, sizeof(dev_stats));
    memset(tmp_stats, 0, sizeof(tmp_stats));

    port_num = rte_eth_dev_count();
    *len = htons(sizeof(struct cmd_resp) + sizeof(struct adns_dpdk_port_stats) * port_num);
    cmd_resp = (struct cmd_resp *)(c->buf + sizeof(uint16_t));
    cmd_resp->cmd = CMD_PORT_STATS;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp) + sizeof(struct adns_dpdk_port_stats) * port_num;
    buf = c->buf + sizeof(struct cmd_resp) + 2;
    
    for (i = 0; i < port_num; i++) {
        rte_eth_stats_get(i, &dev_stats[i]);

        tmp_stats[i].ipackets = dev_stats[i].ipackets;
        tmp_stats[i].opackets = dev_stats[i].opackets;
        tmp_stats[i].ibytes = dev_stats[i].ibytes;
        tmp_stats[i].obytes = dev_stats[i].obytes;
        tmp_stats[i].ierrors = dev_stats[i].ierrors;
        tmp_stats[i].oerrors = dev_stats[i].oerrors;
        tmp_stats[i].rx_nombuf = dev_stats[i].rx_nombuf;
       
        for(j = 0; j < RTE_ETHDEV_QUEUE_STAT_CNTRS; j++){
            tmp_stats[i].q_ipackets[j] = dev_stats[i].q_ipackets[j];
            tmp_stats[i].q_errors[j] = dev_stats[i].q_errors[j];
            tmp_stats[i].q_opackets[j] = dev_stats[i].q_opackets[j];
        }
    }

    memcpy(buf, tmp_stats, sizeof(struct adns_dpdk_port_stats) * port_num);
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --dpdk-port, SUCCESS\n");
}


static void master_utili(ioClient *c)
{
    char *buf;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
  
    *len = htons(sizeof(struct cmd_resp) + sizeof(struct adns_utili));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_UTILI;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp) + sizeof(struct adns_utili);
    buf = c->buf + sizeof(struct cmd_resp) + 2;

    memcpy(buf, &g_adns_utili, sizeof(struct adns_utili));

    cmd_resp->ret_val = 0; 
    log_server_warn(rte_lcore_id(), "adns_adm --utili, SUCCESS\n"); 
}


static int __zonedb_clear(struct adns_zonedb *zonedb, char *err)
{   
    int i;
    struct adns_zone *zone, *zone_nxt;
    struct list_head *h_list;
    struct zone_hash *zone_tbl, *h_node;

    if (zonedb == NULL) {
        cmd_set_err(err, "[%s]: Zonedb does not existed\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: Zonedb does not existed\n", __FUNCTION__);
        return ADNS_ADMIN_CLEAR_ZONEDB_NULL_ERROR;
    }

    zone_tbl = zonedb->zone_tbl;
    if (zone_tbl == NULL) {
        cmd_set_err(err, "[%s]: Zone table does not existed\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: Zone table does not existed\n", __FUNCTION__);
        return ADNS_ADMIN_CLEAR_ZONEDB_TABLE_NULL_ERROR;
    }

    for (i = 0; i < ADNS_ZONEDB_HASH_SIZE; ++i) {
        h_node = &zone_tbl[i];
        h_list = &(h_node->list);

        list_for_each_entry_safe(zone, zone_nxt, h_list, list) {
            list_del(&zone->list);
            h_node->size--;
            zonedb->zone_count--;
            adns_zone_free(zone);
        }
    }

    return 0;

}


static void master_clear(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_CLEAR;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __zonedb_clear(g_datacore_db, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --clear, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --clear, SUCCESS\n");
}


static void master_log(ioClient *c)
{
    char unit = 'B';
    size_t log_rotate_size;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_LOG;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    switch (ce->rclass) {
        case ADNS_LOG_SWITCH: 
            adns_log_switch = ce->type;
            if (adns_log_switch == ADNS_LOG_SWITCH_UP) {
                log_server_warn(rte_lcore_id(), "adns_adm --log --switch UP, SUCCESS\n");             
            } else {
                log_server_warn(rte_lcore_id(), "adns_adm --log --switch DOWN, SUCCESS\n");
            }
            break;
            
        case ADNS_LOG_LEVEL: 
            adns_log_level = ce->type;
            if (adns_log_level == ADNS_LOG_LEVEL_ERROR) {
                log_server_warn(rte_lcore_id(), "adns_adm --log --level ERROR, SUCCESS\n");               
            } else if (adns_log_level == ADNS_LOG_LEVEL_WARN) {
                log_server_warn(rte_lcore_id(), "adns_adm --log --level WARN, SUCCESS\n");
            } else if (adns_log_level == ADNS_LOG_LEVEL_INFO) {
                log_server_warn(rte_lcore_id(), "adns_adm --log --level INFO, SUCCESS\n");
            } else {
                log_server_warn(rte_lcore_id(), "adns_adm --log --level DEBUG, SUCCESS\n");
            }
            break;
            
        case ADNS_LOG_ROTATE_SIZE: 
            g_log_rotate_max_size = parse_log_rotate_max_size(ce->rdata);
            log_server_warn(rte_lcore_id(), "adns_adm --log --rotate-size %zdB, SUCCESS\n", g_log_rotate_max_size);
            break;
            
        case ADNS_LOG_ROTATE_COUNT: 
            g_log_rotate_max_count = parse_log_rotate_max_count(ce->rdata);
            log_server_warn(rte_lcore_id(), "adns_adm --log --rotate-count %u, SUCCESS\n", g_log_rotate_max_count);
            break;

        default:
            log_server_warn(rte_lcore_id(), "adns_adm --log, SUCCESS\n");
            break;
    }

    if (g_log_rotate_max_size >= 1024 * 1024 * 1024) {
        log_rotate_size = g_log_rotate_max_size >> 30;
        unit = 'G';
    } else if (g_log_rotate_max_size >= 1024 * 1024) {
        log_rotate_size = g_log_rotate_max_size >> 20;
        unit = 'M';
    } else if (g_log_rotate_max_size >= 1024) {
        log_rotate_size = g_log_rotate_max_size >> 10;
        unit = 'K';
    } else {
        log_rotate_size =  g_log_rotate_max_size;
        unit = 'B';
    }
    
    cmd_set_err(cmd_resp->err_msg , "log status {\n\tlog switch: %s,\n\tlog level: %s,\n\tlog_rotate_max_size: %zd%c,\n\tlog_rotate_max_count: %u\n}\n", 
                                    log_switch_maps[adns_log_switch].name, 
                                    log_level_maps[adns_log_level].name, 
                                    log_rotate_size, 
                                    unit, 
                                    g_log_rotate_max_count);   
    cmd_resp->ret_val = 0; 
}

static void master_53(ioClient *c)
{
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_53;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    switch (ce->rclass) {
        case ADNS_DROP53: 
            sysctl_tcp_in_53_drop = ce->ttl;
            break;
            
        case ADNS_RATE53: 
            sysctl_tcp_in_53_rate= ce->ttl;
            break;
            
        case ADNS_SIP53: 
            sysctl_tcp_in_53_quota = ce->ttl;
            break;
            
        case ADNS_TOTAL53: 
            sysctl_tcp_in_53_total_quota = ce->ttl;
            break;
            
        case ADNS_PPS53: 
            sysctl_tcp_in_53_total_pps_quota = ce->ttl;
            break;
            
        default:
            log_server_warn(rte_lcore_id(), "adns_adm --sys53, SUCCESS\n");
            break;
    }

    cmd_set_err(cmd_resp->err_msg , "{\n\tdrop53: %s,\n\trate53: %s,\n\tsip53: %d,\n\ttotal53: %d,\n\tpps53: %d\n}\n", 
                                    (0==sysctl_tcp_in_53_drop)?"off":"on", 
                                    (0==sysctl_tcp_in_53_rate)?"off":"on", 
                                    sysctl_tcp_in_53_quota,
                                    sysctl_tcp_in_53_total_quota,
                                    sysctl_tcp_in_53_total_pps_quota);
    cmd_resp->ret_val = 0; 
}

static void master_reload_iplib(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_RELOAD_IPLIB;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    iplib_cleanup();
    ret = iplib_load_init();
    if (ret < 0) {
        cmd_resp->ret_val = ADNS_ADMIN_RELOAD_IPLIB_ERROR;
        cmd_set_err(cmd_resp->err_msg, "[%s]: Failed to reload iplib\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to reload iplib, ret = %d\n", __FUNCTION__, ret);
        log_server_warn(rte_lcore_id(), "adns_adm --reload-iplib, FAILURE\n");
        return;
    }
    
    cmd_resp->ret_val = 0; 
    log_server_warn(rte_lcore_id(), "adns_adm --reload-iplib, SUCCESS\n"); 
}


static void master_reload_vm(ioClient *c)
{
    int ret;   
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;

    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_RELOAD_VM;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    view_map_cleanup();
    ret = parse_view_map(g_view_map_file, g_view_max_num, g_view_map_tbl, g_p_view_nums);
    if (ret < 0) {
        cmd_set_err(cmd_resp->err_msg, "[%s]: Failed to reload view map\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to reload view map, ret = %d\n", __FUNCTION__, ret);
        log_server_warn(rte_lcore_id(), "adns_adm --reload-vm, FAILURE\n");
        cmd_resp->ret_val = ADNS_ADMIN_RELOAD_VM_ERROR;
        return;
    }
    
    cmd_resp->ret_val = 0;  
    log_server_warn(rte_lcore_id(), "adns_adm --reload-vm, SUCCESS\n");
}

static void master_reload_nslist(ioClient *c)
{
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    int ret;

    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_RELOAD_NSLIST;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    struct adns_ns_list_hash *new_ns_tbl = NULL, *old_ns_tbl = NULL;
    
    /* reload default NS list */
    new_ns_tbl = ns_list_load(1);
    if (new_ns_tbl == NULL) {
        cmd_set_err(cmd_resp->err_msg, "[%s]: New default NS list load error\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: New default NS list load error\n", __FUNCTION__);
        cmd_resp->ret_val = ADNS_ADMIN_RELOAD_NSLIST_ERROR;
        return;
    }

    old_ns_tbl = g_ns_tbl;
    ret = ns_list_tbl_merge(old_ns_tbl, new_ns_tbl);
    if (ret != 0) {
        cmd_set_err(cmd_resp->err_msg, "[%s]: Merge default NS list error\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s]: Merge default NS list error\n", __FUNCTION__);
        if (ret < -1) {
            /* adns_adm is synchronized, so it is safe to free the freshly added NS */
            ns_list_recover(old_ns_tbl);
        }
        ns_list_deep_free(new_ns_tbl);
        cmd_resp->ret_val = ADNS_ADMIN_RELOAD_NSLIST_ERROR;
        return;
    }
    
    ns_list_deep_free(new_ns_tbl);

    cmd_resp->ret_val = 0;  
    log_server_warn(rte_lcore_id(), "adns_adm --reload-nslist, SUCCESS\n");
}

static void master_show_nslist(ioClient *c)
{
    int i, j = 0, k;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_rrset *rrset;
    struct list_head *h_list;
    struct adns_rdata *elem;
    char *buf, *ns_name;

    *len = htons(sizeof(struct cmd_resp) + 4 + (uint16_t)(g_ns_group_max_num * sizeof(struct adns_ns_group_info)));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_RELOAD_VM;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp) + 4 + g_ns_group_max_num * sizeof(struct adns_ns_group_info);

    uint32_t *ns_group_count = (uint32_t *)(c->buf + sizeof(struct cmd_resp) + 2);
    *ns_group_count = g_ns_group_max_num;
    buf = c->buf + sizeof(struct cmd_resp) + 2 + 4;
    struct adns_ns_group_info *ns_info_tbl = (struct adns_ns_group_info *)buf;

    for (i = 0; i < g_ns_group_max_num; i ++) {
        rrset = g_ns_rrsets[i];
        if (rrset != NULL && rrset->default_ns == 1) {
            ns_info_tbl[j].group_id = i;
            ns_info_tbl[j].ns_count = rrset->default_rdata.rdata_count;
            ns_info_tbl[j].ref_count = rrset->ref_count;

            h_list = &(rrset->default_rdata.list);
            k = 0;
            list_for_each_entry(elem, h_list, list) {
                ns_name = adns_dname_to_str(elem->data);
                strcpy((char *)ns_info_tbl[j].ns[k ++], ns_name);
                free(ns_name);
            }
            j ++;
        }
    }

    cmd_resp->ret_val = 0;  
    log_server_warn(rte_lcore_id(), "adns_adm --show-nslist, SUCCESS\n");
}


static void master_ip2view(ioClient *c)
{
    int view_id = 0;
    char address[64];
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;    
    struct adns_command_entry *ce;
#ifdef __IPV6_SUPPORT
    struct in6_addr ip;
#endif

    ce = (struct adns_command_entry *)g_req_buf;

    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_IP2VIEW;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    if (ce->rdata_len == 4) {
        // IPV4
        view_id = ip_bitmap_get(*((uint32_t *)(ce->rdata)), rte_socket_id());
    }
#ifdef __IPV6_SUPPORT
    else if (ce->rdata_len == 16) {
        // IPV6
        memcpy(&ip, ce->rdata, 16);
        view_id = ipv6_bitmap_get(*((struct in6_addr *)(ce->rdata)), rte_socket_id());
    }
#endif
    else {
        cmd_resp->ret_val = -1;
        log_server_warn(rte_lcore_id(), "adns_adm not support the cmd\n");
        return;
    }
    cmd_resp->init_done = view_id;
    cmd_resp->ret_val = 0;

    if (inet_ntop(AF_INET, ce->rdata, address, sizeof(address)) != NULL) {
        log_server_warn(rte_lcore_id(), "adns_adm --ip2view %s, view_id = %d, SUCCESS\n", address, view_id);           
    }
}


static int __lookup(struct adns_zonedb *zonedb, char *zone_str, char *domain, uint8_t custom_view, adns_viewid_t view_id, char *err)
{
    int ret, i, flag;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;
    struct adns_node *node = NULL;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        ret = ADNS_ADMIN_LOOKUP_CONVERT_ZONE_ERROR;
        return ret;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        cmd_set_err(err, "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str); 
        ret = 0;
        goto done_lookup_zone;
    }
    
    if (strlen(domain) == 0) {
        cmd_set_err(err, "[%s]: Zone %s exist, cname cascade is %s, wildcard fallback is %s.\n",
                        __FUNCTION__, zone_str, zone->enable_cname_cascade ? "on" : "off", zone->wildcard_fallback_enable ? "on" : "off");
        ret = 0;
        goto done_lookup_zone;
    }  
             
    dname = adns_dname_from_str(domain, strlen(domain));
    if (dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
        ret = ADNS_ADMIN_LOOKUP_DOMAIN_ERROR;
        goto done_lookup_zone;
    }
    
    node = adns_domain_hash_lookup(zone, dname); 
    if (node == NULL) {
        cmd_set_err(err, "[%s]: Zone %s, Node %s does not exist\n", __FUNCTION__, zone_str, domain);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s, Node %s does not exist\n", __FUNCTION__, zone_str, domain); 
        ret = 0;                                           
        goto done_lookup_node;        
    }
    
    flag = 0;
    for (i = 0; i < ADNS_RRSET_NUM; i++) {
        rrset = node->rrsets[i];
        if (rrset == NULL) {
            continue; 
        }
        
        if (custom_view) {
            rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
        }
        else {
            rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
        }

        if (rdata_ctl == NULL) {
            continue; 
        }
        
        if (rdata_ctl->rdata_count == 0) {
            continue; 
        }
        
        flag = 1;
        break;               
    }
    
    if (flag == 0) {
        cmd_set_err(err, "[%s]: Zone %s, Node %s, %sView_id %d does not exist\n", __FUNCTION__, zone_str, domain, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s, Node %s, %sView_id %d does not exist\n", __FUNCTION__, zone_str, domain, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);  
    } else {
        cmd_set_err(err, "[%s]: Zone %s, Node %s, %sView_id %d exist\n", __FUNCTION__, zone_str, domain, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s, Node %s, %sView_id %d exist\n", __FUNCTION__, zone_str, domain, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);  
    }
                  
    adns_dname_free(&dname);
    adns_dname_free(&zone_dname);
    return 0;
            
done_lookup_node:
    adns_dname_free(&dname);

done_lookup_zone:  
    adns_dname_free(&zone_dname);
    return ret; 
}


static void master_lookup(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_LOOKUP;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    
    ret = __lookup(g_datacore_db, ce->zone, ce->domain, ce->custom_view, ce->view_id, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --lookup, ret = %d, FAILURE\n", cmd_resp->ret_val);
        return;     
    }
    
    cmd_resp->ret_val = 0;      
    log_server_warn(rte_lcore_id(), "adns_adm --lookup, SUCCESS\n");
}

static void master_quota(ioClient *c)
{
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_QUOTA;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    if (ce->type == ADNS_RRTYPE_A) {
        g_zone_qps_quota = *((uint64_t *)&(ce->zone[0]));
        g_zone_bps_quota = *((uint64_t *)&(ce->zone[8]));
        g_domain_qps_quota = *((uint64_t *)&(ce->zone[16]));
        g_domain_bps_quota = *((uint64_t *)&(ce->zone[24]));
        g_time_interval = *((uint64_t *)&(ce->zone[32]));

        g_cycles_defense_sec = 1L * g_time_interval * rte_get_timer_hz();
        g_data_flush_sec = g_cycles_defense_sec + rte_get_timer_hz()/100000; // g_cycles_defense_sec + 0.01ms. 1ms = 2300000cysles.
        g_zone_qps_defense_quota = 1L * g_time_interval * g_zone_qps_quota;
        g_zone_bps_defense_quota = 1L * g_time_interval * g_zone_bps_quota;
        g_domain_qps_defense_quota = 1L * g_time_interval * g_domain_qps_quota;
        g_domain_bps_defense_quota = 1L * g_time_interval * g_domain_bps_quota;
    } else {
        cmd_set_err(cmd_resp->err_msg , "defense quota {\n\tg_zone_qps_quota\t: %llu\n\tg_zone_bps_quota\t: %llu\n\tg_domain_qps_quota\t: %llu\n\tg_domain_bps_quota\t: %llu\n\tg_time_interval : %llu\n}\n",
                g_zone_qps_quota,
                g_zone_bps_quota,
                g_domain_qps_quota,
                g_domain_bps_quota,
                g_time_interval);
    } 
    cmd_resp->ret_val = 0;      
    log_server_warn(rte_lcore_id(), "adns_adm --quota, SUCCESS\n");
}

static void master_syslog(ioClient *c)
{
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    char ipaddr[32] = {0};
    struct adns_utili *sta_nodes;
    int i, idx;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_SYSLOG;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    switch (ce->rclass) {
        case ADNS_SYSLOG_IP:
            g_syslog_ctl.ipv4_dst_addr = *(uint32_t *)ce->rdata;            
            inet_ntop(AF_INET, ce->rdata, ipaddr, 32);
            log_server_warn(rte_lcore_id(), "adns_adm --syslog --server-ip %s, SUCCESS\n", ipaddr);
            break;
        case ADNS_SYSLOG_SHOW:
            sta_nodes = (struct adns_utili *)(cmd_resp + 1);
            for (i = 0, idx = app.lcore_io_start_id; i < app.lcore_io_num; i++, idx++) {
                sta_nodes->cpu[i].lcore = idx;
                sta_nodes->cpu[i].usage = g_sta_list[i].node_num;
            }
            sta_nodes->cpu_num = i;
            *len = htons(sizeof(struct cmd_resp) + sizeof(struct adns_utili));
            c->buf_size += sizeof(struct adns_utili);
            log_server_warn(rte_lcore_id(), "adns_adm --syslog --show-sta, SUCCESS\n");
            break;
        default:
            log_server_warn(rte_lcore_id(), "adns_adm --syslog, SUCCESS\n");
            break;
    }

    inet_ntop(AF_INET, &g_syslog_ctl.ipv4_dst_addr, ipaddr, 32);
    cmd_set_err(cmd_resp->err_msg , "Syslog server ip %s\n", ipaddr);
    cmd_resp->ret_val = 0; 
}

static void master_memory_info(ioClient *c)
{
    char *buf;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;

    *len = htons(sizeof(struct cmd_resp) + (uint16_t)sizeof(struct mem_info_t));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_MEMORY_INFO;
    c->bufpos = c->query_size;
    c->buf_size = sizeof(uint16_t) + sizeof(struct cmd_resp) + sizeof(struct mem_info_t);
    buf = c->buf + sizeof(struct cmd_resp) + 2;

    get_memory_info();

    memcpy(buf, &g_mem_info, sizeof(struct mem_info_t));
    cmd_resp->ret_val = 0;

    log_server_warn(rte_lcore_id(), "adns_adm --memory-info, SUCCESS\n");
}


static void master_set_cname_cascade(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_SET_CNAME_CASCADE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __set_cname_cascade(g_datacore_db, ce->zone, ce->type, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --set-cname-cascade --zone %s --cname-opt %d, ret = %d, FAILURE\n", ce->zone, ce->type, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --set-cname-cascade --zone %s --cname-opt %d, SUCCESS\n", ce->zone, ce->type);
    return;
}

static void master_set_wildcard_fallback(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_SET_WILDCARD_FALLBACK;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __set_wildcard_fallback(g_datacore_db, ce->zone, ce->type, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --set-wildcard-fallback --zone %s --wildcard-opt %d, ret = %d, FAILURE\n", ce->zone, ce->type, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --set-wildcard-fallback --zone %s --wildcard-opt %d, SUCCESS\n", ce->zone, ce->type);
    return;
}

static void master_set_dnssec(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_SET_DNSSEC;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __set_dnssec(g_datacore_db, ce->zone, ce->type, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --set-dnssec --zone %s --dnssec-opt %d, ret = %d, FAILURE\n", ce->zone, ce->type, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --set-dnssec --zone %s --dnssec-opt %d, SUCCESS\n", ce->zone, ce->type);
    return;
}

static void master_dnssec_add_key(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DNSSEC_ADD_KEY;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __add_key(ce->rdata, ce->rdata_len, ce->type, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --add-ksk, FAILURE\n");
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --add-ksk, SUCCESS\n");
    return;
}

static void master_dnssec_del_zsk(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DNSSEC_DEL_ZSK;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __del_zsk(ce->type, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --del-zsk, FAILURE\n");
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --del-zsk, SUCCESS\n");
    return;
}

static void master_dnssec_add_dnskey_rrsig(ioClient *c)
{
    int ret;
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DNSSEC_ADD_DNSKEY_RRSIG;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    uint16_t alt_zsk_tag = 0;

    if (ce->ttl > 1) {
        alt_zsk_tag = (ce->type == ce->weight)? ce->rclass : ce->type;
    }
    ret = __add_dnskeyrrsig(g_datacore_db, ce->zone, (uint8_t *)ce->rdata, ce->rdata_len, ce->ttl, ce->weight, alt_zsk_tag, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --add-dnskeyrrsig, --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return;
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --add-dnskeyrrsig --zone %s, SUCCESS\n", ce->zone);
    return;
}

static void master_dnssec_quota(ioClient *c)
{
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DNSSEC_QUOTA;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    switch (ce->rclass) {
        case ADNS_SIP53: 
            g_dnssec_ip_qps_quota = ce->ttl;
            break;
            
        case ADNS_TOTAL53: 
            g_dnssec_qps_quota = ce->ttl;
            break;

        case ADNS_ZONE53:
            g_dnssec_zone_qps_quota = ce->ttl;
            break;

        default:
            log_server_warn(rte_lcore_id(), "adns_adm --dnssec-quota success\n");
            break;
    }

    cmd_set_err(cmd_resp->err_msg , "{\n\tDNSSEC sip qos: %u,\n\tDNSSEC total qos: %u, \n\tDNSSEC zone qos: %u\n}\n", 
                                    g_dnssec_ip_qps_quota,
                                    g_dnssec_qps_quota,
                                    g_dnssec_zone_qps_quota);

    cmd_resp->ret_val = 0; 
    return;
}

static void master_dnssec_cache(ioClient *c)
{
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    int ret = 0;

    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DNSSEC_CACHE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    switch (ce->rclass) {
        case DNSSEC_CACHE_ADM_SWITCH:
            *g_p_dnnssec_cache_switch = ce->type;
            break;
        case DNSSEC_CACHE_ADM_DUMP:
            ret = __dnssec_cache_dump(g_dnssec_cache_db, cmd_resp->err_msg);
            break;
        case DNSSEC_CACHE_ADM_FLUSH:
            ret = __dnssec_cache_flush(cmd_resp->err_msg);
            break;
        default:
            log_server_warn(rte_lcore_id(), "adns_adm --dnssec-cache success\n");
            break;
    }

    if (ce->rclass != DNSSEC_CACHE_ADM_FLUSH) {
        cmd_set_err(cmd_resp->err_msg , "{\n\tDNSSEC cache: %s,\n\tDNSSEC cache node num: %u\n}\n", 
                                *g_p_dnnssec_cache_switch == 1? "ON" : "OFF",
                                g_dnssec_cache_num);
    }

    cmd_resp->ret_val = ret; 
    return;
}

static void master_add_route(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_ADDROUTE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    /* iplib content parsed by command mismatch */  
    if (unlikely(ce->rdata_len != (strlen(ce->rdata) + 1)) ) {
        cmd_resp->ret_val = ADNS_ADMIN_ADD_ROUTE_IPLIB_FILE_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --add-route --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return;
    }

    ret = __add_route(g_datacore_db, ce->zone, (uint8_t *)ce->rdata, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --add-route --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return; 
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --add-route --zone %s, SUCCESS\n", ce->zone); 
}

static void master_del_route(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DELROUTE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __del_route(g_datacore_db, ce->zone, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --del-route --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return; 
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --del-route --zone %s, SUCCESS\n", ce->zone);
}

static void master_reload_route(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_RELOADROUTE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    /* iplib content parsed by command mismatch */  
    if (unlikely(ce->rdata_len != (strlen(ce->rdata) + 1)) ) {
        cmd_resp->ret_val = ADNS_ADMIN_RELOAD_ROUTE_IPLIB_FILE_ERROR;
        log_server_warn(rte_lcore_id(), "adns_adm --reload-route --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return;
    }

    ret = __reload_route(g_datacore_db, ce->zone, (uint8_t *)ce->rdata, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --reload-route --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return; 
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --reload-route --zone %s, SUCCESS\n", ce->zone);
}

static void master_dump_route(ioClient *c)
{
    int ret;    
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_DUMPROUTE;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    ret = __dump_route(g_datacore_db, ce->zone, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        log_server_warn(rte_lcore_id(), "adns_adm --dump-route --zone %s, ret = %d, FAILURE\n", ce->zone, cmd_resp->ret_val);
        return; 
    }

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --dump-route --zone %s, SUCCESS\n", ce->zone);
}

static int node_qps_to_str(struct adns_node *node, char *buf, size_t maxlen)
{
    char *dname_str;
    int len = 0;
    uint32_t node_counter_id;
    uint64_t curr_node_queries = 0, curr_node_bytes = 0;
    uint64_t curr_node_qps = 0, curr_node_bps = 0;
    uint64_t sum_total = 0, sum_noerror = 0, sum_nxdomain = 0;
    uint64_t cur_time, hz_per_sec;
    double   time_interval;

    if (node == NULL || buf == NULL) {
        return -1;
    }

    cur_time = rte_get_timer_cycles();
    hz_per_sec = rte_get_timer_hz();
    time_interval = (cur_time - node->pre_timestamp) / (1.0 * hz_per_sec);

    node_counter_id = node->counter_id;
    adns_counter_sum_get_queries_bytes(node_counter_id, &curr_node_queries, &curr_node_bytes);
        if(likely((curr_node_queries >= node->pre_node_queries) && (curr_node_bytes >= node->pre_node_bytes))){
            curr_node_qps = (curr_node_queries - node->pre_node_queries)/time_interval;
            curr_node_bps = (curr_node_bytes - node->pre_node_bytes)/time_interval;
        }else{
            return -1;
        }

    dname_str = adns_dname_to_str(node->name);
    sum_total = curr_node_qps;
    sum_noerror = curr_node_qps;
    sum_nxdomain = 0;   //nxdomain can't be counted in domain

    len = snprintf(buf, maxlen, "%s\n", dname_str);
    len += snprintf(buf + len, maxlen, "\ttotal qps:     %lu\n", sum_total);
    len += snprintf(buf + len, maxlen, "\tnoerror qps:   %lu\n", sum_noerror);
    len += snprintf(buf + len, maxlen, "\tnxdomain qps:  %lu\n", sum_nxdomain);

    free(dname_str);

    if (len < 0) {
        return -1;
    }

    return len;
}

static int __list_domain_qps(struct adns_zonedb *zonedb, char *zone_str, char *domain_str, char *buf, 
    size_t maxlen, char *err)
{
    int ret, len = 0, total = 0;
    adns_dname_t *zone_dname = NULL, *dname = NULL;
    struct adns_node *node = NULL;
    struct adns_zone *zone = NULL;

    zone_dname = adns_dname_from_str(zone_str, strlen(zone_str));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "%s: Failed to convert zone %s\n", __FUNCTION__, zone_str);
        return ADNS_ADMIN_LIST_DOMAIN_CONVERT_ZONE_ERROR;
    }
    
    zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
    if (zone == NULL) {
        cmd_set_err(err, "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str);
        log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_str); 
        ret = ADNS_ADMIN_LIST_DOMAIN_FIND_ZONE_ERROR;
        goto err_zone;
    }
        
    dname = adns_dname_from_str(domain_str, strlen(domain_str));
    if (dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain_str);
        log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain_str);
        ret = ADNS_ADMIN_LIST_DOMAIN_DOMAIN_ERROR;
        goto err_dname;
    }
    
    node = adns_domain_hash_lookup(zone, dname); 
    if (node == NULL) {
        cmd_set_err(err, "[%s]: Node %s does not exist\n", __FUNCTION__, domain_str);
        log_server_warn(rte_lcore_id(), "[%s]: Node %s does not exist\n", __FUNCTION__, domain_str); 
        ret = ADNS_ADMIN_LIST_DOMAIN_FIND_NODE_ERROR;                                           
        goto err_node;        
    }
        
    /* list schedule */
    len = node_qps_to_str(node, buf + total, maxlen - total);
    if (len < 0) {
        goto err_qps;
    }
    total += len;

    adns_dname_free(&dname);
    adns_dname_free(&zone_dname);
    return total;
      
err_node:
err_qps:
    adns_dname_free(&dname);

err_zone:
err_dname:    
    adns_dname_free(&zone_dname);
    return ret;   
}


static void master_list_domain_qps(ioClient *c)
{
    int ret, maxlen, total = 0;  
    char *buf;  
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;
    
    ce = (struct adns_command_entry *)g_req_buf;
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_LISTDOMAIN_QPS;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);
    maxlen = ADNS_ADM_MAX_REPLY_LEN - c->buf_size;
    buf = c->buf + 2 + sizeof(struct cmd_resp);

    ret = __list_domain_qps(g_datacore_db, ce->zone, ce->domain, buf, maxlen, cmd_resp->err_msg);
    if (ret < 0) {
        cmd_resp->ret_val = ret;
        c->buf_size = 2 + sizeof(struct cmd_resp);
        *len = htons(sizeof(struct cmd_resp));
        log_server_warn(rte_lcore_id(), "adns_adm -q --zone %s --domain %s, ret = %d, FAILURE\n", 
                                         ce->zone, ce->domain, cmd_resp->ret_val);
        return;
    }
    
    total = ret;
    buf[total++] = '\0';
    c->buf_size = 2 + sizeof(struct cmd_resp) + total;
    *len = htons(sizeof(struct cmd_resp) + total);
    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm -q --zone %s --domain %s, SUCCESS\n", 
                                     ce->zone, ce->domain);
}

static void master_exit(ioClient *c)
{
    uint16_t *len = (uint16_t *)c->buf;
    struct cmd_resp *cmd_resp;

    *len = htons(sizeof(struct cmd_resp));
    cmd_resp = (struct cmd_resp *)(c->buf + 2);
    cmd_resp->cmd = CMD_QUIT;
    c->bufpos = c->query_size;
    c->buf_size = 2 + sizeof(struct cmd_resp);

    g_exit_now = 1;

    cmd_resp->ret_val = 0;
    log_server_warn(rte_lcore_id(), "adns_adm --quit, SUCCESS\n");
}

int update_master(ioClient *c, struct adnsCommand *cmd)
{
    cmd->proc(c);
    return 0;
}


struct adnsCommand *adns_lookup_cmd(int opcode)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(adnsCommandTable); i++) {
        if (adnsCommandTable[i].opcode == opcode)
            return &adnsCommandTable[i];
    }

    return NULL;
}


/* Admin Init Function */
int adns_rcode_counter_init()
{
    int i;
  
    for (i = 0; i < ADNS_RCODE_COUNTER_MAX; i++){
        g_adns_pkt_rcode_counter[i] = i;
    }

    return 0;
}



int adns_drop_pkt_counter_init()
{
    int i;

    for (i = 0; i < ADNS_PKT_DROP_COUNTER_MAX; i++) {
        g_adns_pkt_drop_counter[i] = i + ADNS_RCODE_COUNTER_MAX;
    }

    return 0;
}


static int admin_server_init(void)
{
    admin.el = aeCreateEventLoop(EVENT_SET_SIZE);
    if (admin.el == NULL) {
        return -1;
    }

    return 0;
}


static int admin_listenToPort(void)
{
    int i;

    for (i = 0; i < IO_BINDADDR_NUM; i++) {
        if (admin.bindaddr[i].addr == NULL) {
            goto err;
        }

        if (i != IO_BIND_UDP) {
            admin.ipfd[i] = anetTcpServer(admin.neterr, admin.bindaddr[i].port,
                    admin.bindaddr[i].addr);
            if (admin.ipfd[i] == ANET_ERR) {
                goto err;
            }
            
        } else {
            admin.ipfd[i] = anetUdpServer(admin.neterr, admin.bindaddr[i].port,
                    admin.bindaddr[i].addr);
            if (admin.ipfd[i] == ANET_ERR) {
                goto err;
            }
            
        }
    }
    return 0;
    
err:
    return -1;
}


int admin_init()
{
    int ret;

    ret = admin_server_init();  
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to init event\n", __FUNCTION__);
        goto err;
    }

    INIT_LIST_HEAD(&admin.clients);

    /* init bind addr and port */
    admin.bindaddr[IO_BIND_TCP].addr = admin.bind_addr;
    admin.bindaddr[IO_BIND_TCP].port = DNS_BIND_PORT;    
    admin.bindaddr[IO_BIND_UDP].addr = admin.bind_addr;
    admin.bindaddr[IO_BIND_UDP].port = DNS_BIND_PORT;    
    admin.bindaddr[IO_BIND_CMD].addr = admin.bind_addr;
    admin.bindaddr[IO_BIND_CMD].port = admin.bind_port;

    /* Open the TCP listening socket for DNS. */
    if (admin_listenToPort() < 0) {
        goto err;
    }

    /* Create an event handler for accepting new connections in TCP */
    if (aeCreateFileEvent(admin.el, admin.ipfd[IO_BIND_TCP], AE_READABLE,
                acceptTcpDns, NULL) == AE_ERR) { // for adnsapi
        goto err;
    }

    if (aeCreateFileEvent(admin.el, admin.ipfd[IO_BIND_CMD], AE_READABLE,
                acceptTcpCmd, NULL) == AE_ERR) { // for adns_adm
        goto err;
    }

    if (aeCreateFileEvent(admin.el, admin.ipfd[IO_BIND_UDP], AE_READABLE,
                UdpDnsProc, NULL) == AE_ERR) { // unused for now
        goto err;
    }

    /* Alloc memory for cmd request buffer */
    g_req_buf = malloc(REQ_MAX_LEN);
    if (g_req_buf == NULL) {
        goto err;
    }

    g_cycles_defense_sec = 1L * g_time_interval * rte_get_timer_hz();
    g_data_flush_sec = g_cycles_defense_sec + rte_get_timer_hz()/100000; // g_cycles_defense_sec + 0.01ms. 1ms = 2300000cysles.
    g_zone_qps_defense_quota = 1L * g_time_interval * g_zone_qps_quota;
    g_zone_bps_defense_quota = 1L * g_time_interval * g_zone_bps_quota;
    g_domain_qps_defense_quota = 1L * g_time_interval * g_domain_qps_quota;
    g_domain_bps_defense_quota = 1L * g_time_interval * g_domain_bps_quota;

    return 0;

err:
    return -1;
}


void admin_cleanup(void)
{
    free(g_req_buf);
    g_req_buf = NULL;
}


static struct rte_mempool *g_client_extbuf_pools[ADNS_MAX_SOCKETS] = {NULL};

int admin_init_client_extbuf_pool(void)
{
    const int EXTBUF_CNT = 30;
    adns_socket_id_t socket_id;
    char name[64];

    for (socket_id = 0; socket_id < ADNS_MAX_SOCKETS; socket_id++) {
        g_client_extbuf_pools[socket_id] = NULL;
    }

    for (socket_id = 0; socket_id < ADNS_MAX_SOCKETS; socket_id++) {
        snprintf(name, sizeof(name), "g_client_extbuf_pools_%d", socket_id);
        g_client_extbuf_pools[socket_id] = rte_mempool_create(name, EXTBUF_CNT,
                EXTBUF_MAX_LEN, 10, 0, NULL, NULL, NULL,
                NULL, socket_id, 0);
        if (g_client_extbuf_pools[socket_id] == NULL) {
            return -1;
        }
        fprintf(stdout, "[%s]: Finish to alloc g_client_extbuf_pools %s\n", __FUNCTION__, name);
    }
    return 0;
}

char * admin_client_extbuf_get()
{
    adns_socket_id_t socket_id;
    void *data;
    char * extbuf;

    socket_id = rte_socket_id();
    if (socket_id >= ADNS_MAX_SOCKETS){
        return NULL;
    }

    if (rte_mempool_get(g_client_extbuf_pools[socket_id], &data) < 0) {
        log_server_error(rte_lcore_id(),
                "[%s]: rte_mempool_get failed, pool name = g_client_extbuf_pools, socket id = %d\n", 
                __FUNCTION__, socket_id);
        return NULL;
    }
    extbuf = (char *)data;

    return extbuf;
}

void admin_client_extbuf_put(char * extbuf)
{
    adns_socket_id_t socket_id;

    if (extbuf == NULL) {
        return;
    }

    socket_id = rte_socket_id();
    if (socket_id >= ADNS_MAX_SOCKETS){
        return;
    }

    rte_mempool_put(g_client_extbuf_pools[socket_id], (void *)extbuf);
}

