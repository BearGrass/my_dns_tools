#ifndef __LDNS_USER_CONFIG_DEF_
#define __LDNS_USER_CONFIG_DEF_

#include<stdint.h>

#include "common.h"


#define QTYPE_MAX_H 65536

extern uint32_t goversea_view_id;
extern int g_forwarder_retry;
extern int g_forwarder_retry_interval;
extern int g_timer_exec_interval;
extern int g_ttl_expire_clean_exec_interval;
extern int g_ttl_expire_clean_hash_size;
extern uint32_t g_lcore_node_max;
extern uint32_t g_view_hash_table_size;
extern int g_edns_on;
extern int g_httpdns_on;
extern int g_forwarder_fail_down;
extern int g_forwarder_up_after_down;
extern int g_charge_file_interval;
extern int g_white_state;
extern int g_man_white_state;
extern int g_man_black_state;
extern int g_black_state;
extern int g_oversea_state;
extern int g_view_nodes_ttl_threshold;
extern int g_share_lcore_data;

extern int g_qtype_fwd[QTYPE_MAX_H];
extern char * g_bind_addr;
extern uint16_t g_bind_port;
extern uint32_t g_port_ip[256];
extern uint32_t g_rec_vip[VIP_IPADDR_NUM_MAX];
extern uint32_t g_auth_vip[VIP_IPADDR_NUM_MAX];
extern uint32_t g_sec_vip[VIP_IPADDR_NUM_MAX];
extern uint8_t g_rec_vip6[VIP_IPADDR_NUM_MAX][16];
extern uint8_t g_auth_vip6[VIP_IPADDR_NUM_MAX][16];
extern uint8_t g_sec_vip6[VIP_IPADDR_NUM_MAX][16];

static inline uint32_t __attribute__ ((always_inline))
get_port_ip_net(uint8_t port)
{
    return g_port_ip[port];
}

static inline int __attribute__ ((always_inline))
get_qtype_view_fwd(int qtype)
{
    return g_qtype_fwd[qtype];
}

/* set number */
extern void set_forwarder_retry(int x);
extern void set_forwarder_retry_interval(int x);
extern void set_timer_exec_interval(int x);
extern void set_ttl_expire_clean_exec_interval(int x);
extern void set_ttl_expire_clean_hash_size(int x);
extern void set_lcore_node_max(uint32_t x);
extern void set_view_hash_table_size(uint32_t x);
extern void set_edns_on(int x);
extern void set_httpdns_on(int x);
extern void set_forwarder_fail_down(int x);
extern void set_forwarder_up_after_down(int x);
extern void set_charge_file_interval(int x);
extern void set_charge_topn_interval(int x);

/* set network address */
extern void set_bind_addr(char *x);
extern void set_bind_port(uint16_t x);
extern void set_port_ip_net(uint32_t ip,uint8_t port);

extern void set_white_state(int x);
extern void set_man_white_state(int x);
extern void set_man_black_state(int x);
extern void set_black_state(int x);
extern void set_oversea_state(int x);
extern void set_view_nodes_ttl_threshold(int x);
extern void set_share_lcore_data(int x);
extern void init_qtype_view_fwd();
extern void clean_qtype_view_fwd(int qtype);

#endif
