#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_core.h>
#include <rte_kni.h>
#include <rte_ip.h>
#include <rte_ethdev.h>

#include "ae.h"
#include "admin.h"
#include "adns.h"
#include "msg.h"
#include "cfg_file.h"
#include "iplib.h"
#include "log.h"
#include "view_maps.h"
#include "init_zone.h"
#include "descriptor.h"
#include "utili_base.h"
#include "adns_stats.h"
#include "adns_conf.h"
#include "syslog.h"
#include "mbuf.h"
#include "adns_counter.h"
#include "networking.h"
#include "rcu.h"
#include "common_value.h"
#include "qps_limit.h"
#include "dnssec.h"
#include "dnssec_cache.h"
#include "dnssec_cache_msg.h"

#if 1
//adns_counter_init todo fake
/*
 * get_xxx from var, read  shm
 * set_xxx to   var, write shm
 */

//int g_adns_pkt_drop_counter[ADNS_PKT_DROP_COUNTER_MAX];
//int g_adns_pkt_rcode_counter[ADNS_RCODE_COUNTER_MAX];
int * g_adns_pkt_drop_counter;
int * g_adns_pkt_rcode_counter;

extern struct adns_rrset** g_ns_rrsets;
extern struct adns_zonedb *g_datacore_db;
extern int * g_p_zone_lbs_max;  //动态变化的，转换成指针  
extern int * g_p_view_nums;     //动态变化的，转成成指针
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
extern uint32_t g_dnssec_qps_limit_on;
extern uint32_t g_dnssec_zone_qps_quota;
extern uint32_t g_dnssec_ip_qps_quota;
extern uint32_t g_dnssec_qps_quota;
extern uint32_t g_dnssec_cache_max_num;
extern uint8_t *g_p_dnnssec_cache_switch;
extern char *g_hostname;
extern uint8_t g_hostname_len;

extern uint64_t TSC_HZ;
extern uint64_t TSC_100MS;
extern qps_limit_st_t *dnssec_zone_limit_tbl;
extern qps_limit_st_t *dnssec_ip_limit_tbl;
extern qps_limit_st_t *dnssec_global_limit;
extern qps_limit_st_t *ip_limit_tbl;
extern adns_dnssec_key **g_dnssec_ksk;
extern adns_nsec_bitmap_list *g_nsec_bm_table;
extern adns_dnssec_key **zsk_p_table;
extern struct rte_mempool *g_dnssec_key_pools[ADNS_MAX_SOCKETS];
extern struct rte_mempool *g_zone_zsk_ctrl_pools[ADNS_MAX_SOCKETS];
extern struct adns_view_map *g_view_map_tbl;
extern struct adns_view_map *g_custom_view_map_tbl;
extern adns_weight_t g_large_weight;
extern adns_viewid_t * g_mp_ip_infos[ADNS_NB_SOCKETS];
extern struct rte_mempool *g_rrset_pools[ADNS_MAX_SOCKETS];
extern struct rte_mempool *g_rdata_ctl_pools[ADNS_MAX_SOCKETS];
extern struct rte_mempool *g_rdata_pools[ADNS_MAX_SOCKETS];
extern struct rte_mempool *g_private_rdata_ctl_pools[ADNS_MAX_SOCKETS];
extern struct rte_mempool *g_private_route_pools[ADNS_MAX_SOCKETS];
extern struct adns_domaindb *g_domain_db;
extern struct rte_memzone *g_adns_counter_table[RTE_MAX_NUMA_NODES][RTE_MAX_LCORE];
extern uint32_t g_adns_counter_num;
extern uint16_t g_io_lcore_id_start;
extern uint16_t g_io_lcore_num;
extern struct adns_stats * gstats;
#if 1
extern adns_viewid_t *ip_infos[ADNS_NB_SOCKETS];
extern struct ipv6_bitmap_index *ipv6_ipmap_key[ADNS_NB_SOCKETS];
extern struct id_ipmap_list *ipv6_infos[ADNS_NB_SOCKETS];
extern const struct rte_memzone *ip_mzs[ADNS_NB_SOCKETS];
extern const struct rte_memzone *ipv6_key_mzs[ADNS_NB_SOCKETS];
extern const struct rte_memzone *ipv6_mzs[ADNS_NB_SOCKETS];
#endif

int ndns_adns_allloc_g_zone_lbs_max() {
	g_p_zone_lbs_max = rte_malloc(NULL, sizeof(int), 0);
	g_p_view_nums = rte_malloc(NULL, sizeof(int), 0);
    g_dnssec_ksk = rte_malloc(NULL, sizeof(void *), 0);
    if (g_dnssec_ksk == NULL) {
        return -1;
    }
    *g_dnssec_ksk = NULL;

    g_p_dnnssec_cache_switch = (uint8_t *)rte_zmalloc(NULL, sizeof(uint8_t), 0);
    if (g_p_dnnssec_cache_switch == NULL) {
        return -1;
    }
    // Switch DNSSEC cache by default
    *g_p_dnnssec_cache_switch = 1;

    g_adns_pkt_drop_counter = rte_malloc(NULL, sizeof(int)*ADNS_PKT_DROP_COUNTER_MAX, 0);
    g_adns_pkt_rcode_counter = rte_malloc(NULL, sizeof(int)*ADNS_RCODE_COUNTER_MAX, 0);

    g_hostname = rte_malloc(NULL, MAX_HOSTNAME_LEN, 0);
	return 0;
}

int ndns_adns_alloc_init()
{
	ndns_adns_allloc_g_zone_lbs_max();	
	return 0;
}

/*宏，调用set_函数*/
#define SH_MP_SET(n)   set_##n(n)
/*宏，调用get_函数*/
#define SH_MP_GET(n)   n = get_##n()
/*宏，添加一个数据项*/
#define SH_MP_DATA(n)  typeof(n) sh_##n;

/*
 *这个数据结构，是共享内存区
 *现在对于每个非临时变量，都在这个数据结构中，添加一个备份变量，
 *假设 int g_a, 需要在这里面，添加 int sh_g_a,
 *实现时，通过SH_MP_DATA来实现。
 *主进程启动后，把主进程全部变量的值，拷贝到这个数据结构中的备份变量中。
 *每个副进程启动后，是可以访问这个共享内存区的
 *副进程把共享内存区的备份变量，赋值给对应的数据结构。
 *这样，副进程，就可以直接通过主进程相同的函数，访问主进程保存在dpdk内存中的数据了。
 * */
struct mp_data {
SH_MP_DATA(g_ns_rrsets);
SH_MP_DATA(g_datacore_db);
SH_MP_DATA(g_p_zone_lbs_max);
SH_MP_DATA(g_adns_pkt_drop_counter);
SH_MP_DATA(g_adns_pkt_rcode_counter);
SH_MP_DATA(g_p_view_nums);
SH_MP_DATA(g_zone_max_num);
SH_MP_DATA(g_private_route_zone_max_num);
SH_MP_DATA(g_private_route_per_zone_max_num);
SH_MP_DATA(g_ip_segment_per_route_max_num);
SH_MP_DATA(g_view_max_num);
SH_MP_DATA(g_domain_max_num);
SH_MP_DATA(g_rr_max_num);
SH_MP_DATA(g_rrset_memory_max_num);
SH_MP_DATA(g_rdata_ctl_max_num);
SH_MP_DATA(g_private_rdata_ctl_max_num);
SH_MP_DATA(g_response_answer_max_record_num);
SH_MP_DATA(g_response_authority_max_record_num);
SH_MP_DATA(g_response_additional_max_record_num);
SH_MP_DATA(g_ns_group_max_num);
SH_MP_DATA(g_dnssec_zone_max_num);
SH_MP_DATA(g_dnssec_qps_limit_on);
SH_MP_DATA(g_dnssec_zone_qps_quota);
SH_MP_DATA(g_dnssec_ip_qps_quota);
SH_MP_DATA(g_dnssec_qps_quota);
SH_MP_DATA(g_dnssec_cache_max_num);
SH_MP_DATA(g_p_dnnssec_cache_switch);
SH_MP_DATA(g_hostname);
SH_MP_DATA(g_hostname_len);

SH_MP_DATA(TSC_HZ);
SH_MP_DATA(TSC_100MS);
SH_MP_DATA(dnssec_zone_limit_tbl);
SH_MP_DATA(dnssec_ip_limit_tbl);
SH_MP_DATA(dnssec_global_limit);
SH_MP_DATA(ip_limit_tbl);
SH_MP_DATA(g_dnssec_ksk);
SH_MP_DATA(g_nsec_bm_table);
SH_MP_DATA(zsk_p_table);
struct rte_mempool *sh_g_dnssec_key_pools[ADNS_MAX_SOCKETS];
struct rte_mempool *sh_g_zone_zsk_ctrl_pools[ADNS_MAX_SOCKETS];
SH_MP_DATA(g_view_map_tbl);
SH_MP_DATA(g_custom_view_map_tbl);
SH_MP_DATA(g_large_weight);
SH_MP_DATA(g_domain_db);
adns_viewid_t * sh_g_mp_ip_infos[ADNS_NB_SOCKETS];
struct rte_mempool *sh_g_rrset_pools[ADNS_MAX_SOCKETS];
struct rte_mempool *sh_g_rdata_ctl_pools[ADNS_MAX_SOCKETS];
struct rte_mempool *sh_g_rdata_pools[ADNS_MAX_SOCKETS];
struct rte_mempool *sh_g_private_rdata_ctl_pools[ADNS_MAX_SOCKETS];
struct rte_mempool *sh_g_private_route_pools[ADNS_MAX_SOCKETS];
#if 1
adns_viewid_t *sh_ip_infos[ADNS_NB_SOCKETS];
struct ipv6_bitmap_index *sh_ipv6_ipmap_key[ADNS_NB_SOCKETS];
struct id_ipmap_list *sh_ipv6_infos[ADNS_NB_SOCKETS];
const struct rte_memzone *sh_ip_mzs[ADNS_NB_SOCKETS];
const struct rte_memzone *sh_ipv6_key_mzs[ADNS_NB_SOCKETS];
const struct rte_memzone *sh_ipv6_mzs[ADNS_NB_SOCKETS];
#endif
#if 1 
const struct rte_memzone *sh_g_adns_counter_table[RTE_MAX_NUMA_NODES][RTE_MAX_LCORE];
SH_MP_DATA(g_adns_counter_num);
SH_MP_DATA(g_io_lcore_id_start);
SH_MP_DATA(g_io_lcore_num);
SH_MP_DATA(gstats);
#endif
};

/* 
 * set_, 把全局变量拷贝到共享内存区
 * get_, 从共享内存区拷贝值到全局变量
 * */
#define SH_MP_SET_GET_FUNC(n,g)  void set_##n (typeof(n) n){\
g->sh_##n = n;}\
typeof(n) get_##n (){\
return g->sh_##n;}

struct mp_data * g_mp_data;

void arry_setshm_master() {
	int i = 0;
	for (i=0; i<ADNS_MAX_SOCKETS; i++) {
		g_mp_data->sh_g_rrset_pools[i]				= g_rrset_pools[i];
		g_mp_data->sh_g_rdata_ctl_pools[i] 			= g_rdata_ctl_pools[i];
		g_mp_data->sh_g_rdata_pools[i] 				= g_rdata_pools[i];
		g_mp_data->sh_g_private_rdata_ctl_pools[i] 	= g_private_rdata_ctl_pools[i];
		g_mp_data->sh_g_private_route_pools[i] 		= g_private_route_pools[i];
        g_mp_data->sh_ip_infos[i]                   = ip_infos[i]; 
        g_mp_data->sh_ipv6_ipmap_key[i]             = ipv6_ipmap_key[i];
        g_mp_data->sh_ipv6_infos[i]                 = ipv6_infos[i];
        g_mp_data->sh_ip_mzs[i]                     = ip_mzs[i];
        g_mp_data->sh_ipv6_key_mzs[i]               = ipv6_key_mzs[i];
        g_mp_data->sh_ipv6_mzs[i]                   = ipv6_mzs[i];
        g_mp_data->sh_g_dnssec_key_pools[i]         = g_dnssec_key_pools[i];
        g_mp_data->sh_g_zone_zsk_ctrl_pools[i]      = g_zone_zsk_ctrl_pools[i];
	}
    memcpy(g_mp_data->sh_g_adns_counter_table, g_adns_counter_table, sizeof(struct rte_memzone*)*RTE_MAX_NUMA_NODES*RTE_MAX_LCORE);

}

void arry_getshm_tcp() {
	int i = 0;
	for (i=0; i<ADNS_MAX_SOCKETS; i++) {
		g_rrset_pools[i] 				= g_mp_data->sh_g_rrset_pools[i];
		g_rdata_ctl_pools[i] 			= g_mp_data->sh_g_rdata_ctl_pools[i];
		g_rdata_pools[i] 				= g_mp_data->sh_g_rdata_pools[i];
		g_private_rdata_ctl_pools[i] 	= g_mp_data->sh_g_private_rdata_ctl_pools[i];
		g_private_route_pools[i]		= g_mp_data->sh_g_private_route_pools[i];
        ip_infos[i]                     = g_mp_data->sh_ip_infos[i];
        ipv6_ipmap_key[i]               = g_mp_data->sh_ipv6_ipmap_key[i];
        ipv6_infos[i]                   = g_mp_data->sh_ipv6_infos[i];
        ip_mzs[i]                       = g_mp_data->sh_ip_mzs[i];
        ipv6_key_mzs[i]                 = g_mp_data->sh_ipv6_key_mzs[i];
        ipv6_mzs[i]                     = g_mp_data->sh_ipv6_mzs[i];
        g_dnssec_key_pools[i]           = g_mp_data->sh_g_dnssec_key_pools[i];
        g_zone_zsk_ctrl_pools[i]        = g_mp_data->sh_g_zone_zsk_ctrl_pools[i];
	}
    memcpy(g_adns_counter_table, g_mp_data->sh_g_adns_counter_table, sizeof(struct rte_memzone*)*RTE_MAX_NUMA_NODES*RTE_MAX_LCORE);
}


SH_MP_SET_GET_FUNC(g_ns_rrsets, g_mp_data);
SH_MP_SET_GET_FUNC(g_datacore_db, g_mp_data);
SH_MP_SET_GET_FUNC(g_p_zone_lbs_max, g_mp_data);
SH_MP_SET_GET_FUNC(g_adns_pkt_drop_counter, g_mp_data);
SH_MP_SET_GET_FUNC(g_adns_pkt_rcode_counter, g_mp_data);
SH_MP_SET_GET_FUNC(g_p_view_nums, g_mp_data);
SH_MP_SET_GET_FUNC(g_zone_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_private_route_zone_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_private_route_per_zone_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_ip_segment_per_route_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_view_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_domain_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_rr_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_rrset_memory_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_rdata_ctl_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_private_rdata_ctl_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_response_answer_max_record_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_response_authority_max_record_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_response_additional_max_record_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_ns_group_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_dnssec_zone_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_dnssec_qps_limit_on, g_mp_data);
SH_MP_SET_GET_FUNC(g_dnssec_zone_qps_quota, g_mp_data);
SH_MP_SET_GET_FUNC(g_dnssec_ip_qps_quota, g_mp_data);
SH_MP_SET_GET_FUNC(g_dnssec_qps_quota, g_mp_data);
SH_MP_SET_GET_FUNC(g_dnssec_cache_max_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_p_dnnssec_cache_switch, g_mp_data);
SH_MP_SET_GET_FUNC(g_hostname, g_mp_data);
SH_MP_SET_GET_FUNC(g_hostname_len, g_mp_data);

SH_MP_SET_GET_FUNC(TSC_HZ, g_mp_data);
SH_MP_SET_GET_FUNC(TSC_100MS, g_mp_data);
SH_MP_SET_GET_FUNC(dnssec_zone_limit_tbl, g_mp_data);
SH_MP_SET_GET_FUNC(dnssec_ip_limit_tbl, g_mp_data);
SH_MP_SET_GET_FUNC(dnssec_global_limit, g_mp_data);
SH_MP_SET_GET_FUNC(ip_limit_tbl, g_mp_data);
SH_MP_SET_GET_FUNC(g_dnssec_ksk, g_mp_data);
SH_MP_SET_GET_FUNC(g_nsec_bm_table, g_mp_data);
SH_MP_SET_GET_FUNC(zsk_p_table, g_mp_data);
SH_MP_SET_GET_FUNC(g_view_map_tbl, g_mp_data);
SH_MP_SET_GET_FUNC(g_custom_view_map_tbl, g_mp_data);
SH_MP_SET_GET_FUNC(g_large_weight, g_mp_data);
SH_MP_SET_GET_FUNC(g_domain_db, g_mp_data);

SH_MP_SET_GET_FUNC(g_adns_counter_num, g_mp_data);
SH_MP_SET_GET_FUNC(g_io_lcore_id_start, g_mp_data);
SH_MP_SET_GET_FUNC(g_io_lcore_num, g_mp_data);
SH_MP_SET_GET_FUNC(gstats, g_mp_data);

int g_set_init_master() {
	const struct rte_memzone *mz;
	mz = rte_memzone_reserve("g_mp_data", sizeof(*g_mp_data), 0, 0);
	if (mz == NULL) {
		rte_errno = ENOMEM;
		return -1;
	}

	g_mp_data = mz->addr;
	
	arry_setshm_master();

    SH_MP_SET(g_ns_rrsets);
    SH_MP_SET(g_datacore_db);
    SH_MP_SET(g_p_zone_lbs_max);
    SH_MP_SET(g_adns_pkt_drop_counter);
    SH_MP_SET(g_adns_pkt_rcode_counter);
    SH_MP_SET(g_p_view_nums);
    SH_MP_SET(g_zone_max_num);
    SH_MP_SET(g_private_route_zone_max_num);
    SH_MP_SET(g_private_route_per_zone_max_num);
    SH_MP_SET(g_ip_segment_per_route_max_num);
    SH_MP_SET(g_view_max_num);
    SH_MP_SET(g_domain_max_num);
    SH_MP_SET(g_rr_max_num);
    SH_MP_SET(g_rrset_memory_max_num);
    SH_MP_SET(g_rdata_ctl_max_num);
    SH_MP_SET(g_private_rdata_ctl_max_num);
    SH_MP_SET(g_response_answer_max_record_num);
    SH_MP_SET(g_response_authority_max_record_num);
    SH_MP_SET(g_response_additional_max_record_num);
    SH_MP_SET(g_ns_group_max_num);
    SH_MP_SET(g_dnssec_zone_max_num);
    SH_MP_SET(g_dnssec_qps_limit_on);
    SH_MP_SET(g_dnssec_zone_qps_quota);
    SH_MP_SET(g_dnssec_ip_qps_quota);
    SH_MP_SET(g_dnssec_qps_quota);
    SH_MP_SET(g_dnssec_cache_max_num);
    SH_MP_SET(g_p_dnnssec_cache_switch);
    SH_MP_SET(g_hostname);
    SH_MP_SET(g_hostname_len);
    

    SH_MP_SET(TSC_HZ);
    SH_MP_SET(TSC_100MS);
    SH_MP_SET(dnssec_zone_limit_tbl);
    SH_MP_SET(dnssec_ip_limit_tbl);
    SH_MP_SET(dnssec_global_limit);
    SH_MP_SET(ip_limit_tbl);
    SH_MP_SET(g_dnssec_ksk);
    SH_MP_SET(g_nsec_bm_table);
    SH_MP_SET(zsk_p_table);
    SH_MP_SET(g_view_map_tbl);
    SH_MP_SET(g_custom_view_map_tbl);
    SH_MP_SET(g_large_weight);
    SH_MP_SET(g_domain_db);
    SH_MP_SET(g_adns_counter_num);
    SH_MP_SET(g_io_lcore_id_start);
    SH_MP_SET(g_io_lcore_num);
    SH_MP_SET(gstats);

    return 0;
}

int g_get_init_tcp() {
	const struct rte_memzone *mz;
	mz = rte_memzone_lookup("g_mp_data");
	if (!mz) {
		printf("No g_mp_data!\n");
		return -1;
	}
	g_mp_data = mz->addr;

    adns_log_switch = ADNS_LOG_SWITCH_DOWN;
	arry_getshm_tcp();

    SH_MP_GET(g_ns_rrsets);
    SH_MP_GET(g_datacore_db);
    SH_MP_GET(g_p_zone_lbs_max);
    SH_MP_GET(g_adns_pkt_drop_counter);
    SH_MP_GET(g_adns_pkt_rcode_counter);
    SH_MP_GET(g_p_view_nums);
    SH_MP_GET(g_zone_max_num);
    SH_MP_GET(g_private_route_zone_max_num);
    SH_MP_GET(g_private_route_per_zone_max_num);
    SH_MP_GET(g_ip_segment_per_route_max_num);
    SH_MP_GET(g_view_max_num);
    SH_MP_GET(g_domain_max_num);
    SH_MP_GET(g_rr_max_num);
    SH_MP_GET(g_rrset_memory_max_num);
    SH_MP_GET(g_rdata_ctl_max_num);
    SH_MP_GET(g_private_rdata_ctl_max_num);
    SH_MP_GET(g_response_answer_max_record_num);
    SH_MP_GET(g_response_authority_max_record_num);
    SH_MP_GET(g_response_additional_max_record_num);
    SH_MP_GET(g_ns_group_max_num);
    SH_MP_GET(g_dnssec_zone_max_num);
    SH_MP_GET(g_dnssec_qps_limit_on);
    SH_MP_GET(g_dnssec_zone_qps_quota);
    SH_MP_GET(g_dnssec_ip_qps_quota);
    SH_MP_GET(g_dnssec_qps_quota);
    SH_MP_GET(g_dnssec_cache_max_num);
    SH_MP_GET(g_p_dnnssec_cache_switch);
    SH_MP_GET(g_hostname);
    SH_MP_GET(g_hostname_len);
    

    SH_MP_GET(TSC_HZ);
    SH_MP_GET(TSC_100MS);
    SH_MP_GET(dnssec_zone_limit_tbl);
    SH_MP_GET(dnssec_ip_limit_tbl);
    SH_MP_GET(dnssec_global_limit);
    SH_MP_GET(ip_limit_tbl);
    SH_MP_GET(g_dnssec_ksk);
    SH_MP_GET(g_nsec_bm_table);
    SH_MP_GET(zsk_p_table);
    SH_MP_GET(g_view_map_tbl);
    SH_MP_GET(g_custom_view_map_tbl);
    SH_MP_GET(g_large_weight);
    SH_MP_GET(g_domain_db);
    SH_MP_GET(g_adns_counter_num);
    SH_MP_GET(g_io_lcore_id_start);
    SH_MP_GET(g_io_lcore_num);
    SH_MP_GET(gstats);
    
    return 0;
}

#else //todo or not
//./libadns/iplib.h:extern char *g_ipfile_path;   //no need
//./libadns/iplib.h:extern char *g_ipv6file_path; //no need
//./libadns/rrset.h:extern char *g_ns_list_file;  //no need
//./libadns/rrset.h:extern struct adns_ns_list_hash *g_ns_tbl; //no need
//./libadns/view_maps.h:extern char *g_view_map_file;  //todo 
//./libadns/syslog.h:extern struct rte_mempool *g_syslogmbuf_pool;  ???
//./libadns/syslog.h:extern struct adns_syslog g_syslog_ctl; //no need
//./libadns/node.h:extern struct adnsTypeConvertIndex g_type2index_tbl[]; //ok
//./libadns/node.h:extern uint16_t g_type2index_size;  //ok
//./adns/adns_log.h:extern char log_level_str[4][10];  //ok
//./adns/adns_utili.h:extern struct cycle_use g_cycle_usage[RTE_MAX_LCORE]; //no need
//./adns/admin.h:extern char *g_req_buf;                //no need
//./adns/admin.h:extern uint32_t g_req_len;             // no need
//./adns/admin.h:extern int g_init_done;                //no need
//./adns/mbuf.h:extern struct rte_mempool *g_pktmbuf_pool; //no need
#endif

