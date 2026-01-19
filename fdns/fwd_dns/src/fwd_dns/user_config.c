#include "rte_core.h"
#include "common.h"
#include "user_config.h"

/*later may be can config when run time,but we do not use atomic ,casue this config does mater*/
int g_forwarder_retry;
int g_forwarder_retry_interval;
int g_timer_exec_interval;
int g_ttl_expire_clean_exec_interval;
int g_ttl_expire_clean_hash_size;
uint32_t g_lcore_node_max;
uint32_t g_view_hash_table_size;
int g_edns_on;
int g_httpdns_on;
int g_forwarder_fail_down;
int g_forwarder_up_after_down;
int g_charge_file_interval;
int g_white_state;
int g_man_white_state;
int g_man_black_state;
int g_black_state;
int g_oversea_state;
int g_view_nodes_ttl_threshold;
int g_share_lcore_data;

int g_qtype_fwd[QTYPE_MAX_H];
char * g_bind_addr;
uint16_t g_bind_port;
uint32_t g_port_ip[256];
uint32_t g_rec_vip[VIP_IPADDR_NUM_MAX];
uint32_t g_auth_vip[VIP_IPADDR_NUM_MAX];
uint32_t g_sec_vip[VIP_IPADDR_NUM_MAX];
uint8_t g_rec_vip6[VIP_IPADDR_NUM_MAX][16];
uint8_t g_auth_vip6[VIP_IPADDR_NUM_MAX][16];
uint8_t g_sec_vip6[VIP_IPADDR_NUM_MAX][16];

void init_qtype_view_fwd()
{
    int i;
    for(i = 0 ; i < QTYPE_MAX_H ;i ++){
        g_qtype_fwd[i] = 1;
    }
}

void set_share_lcore_data(int x)
{
    g_share_lcore_data = x;
    RTE_LOG(INFO,LDNS,"Set share lcore data to %d\n",g_share_lcore_data);
}

void set_forwarder_retry(int x)
{
    g_forwarder_retry = x;
    RTE_LOG(INFO, LDNS, "Set forwarder_retry to %d\n", g_forwarder_retry);
}

void set_forwarder_retry_interval(int x)
{
    g_forwarder_retry_interval = x;
    RTE_LOG(INFO, LDNS, "Set forwarder_retry_interval to %d s\n",
            g_forwarder_retry_interval);
}

void set_timer_exec_interval(int x)
{
    g_timer_exec_interval = x;
    RTE_LOG(INFO, LDNS, "Set timer_exec_interval to %d ms\n",
            g_timer_exec_interval);
}

void set_ttl_expire_clean_exec_interval(int x)
{
    g_ttl_expire_clean_exec_interval = x;
    RTE_LOG(INFO, LDNS, "Set ttl_expire_clean_exec_interval to %d ms\n",
            g_ttl_expire_clean_exec_interval);
}

void set_ttl_expire_clean_hash_size(int x)
{
    g_ttl_expire_clean_hash_size = x;
    RTE_LOG(INFO, LDNS, "Set ttl_expire_clean_hash_size to %d\n",
            g_ttl_expire_clean_hash_size);

}

void set_lcore_node_max(uint32_t x)
{
    g_lcore_node_max = x;
    RTE_LOG(INFO, LDNS, "Set lcore_node_max to %u\n", g_lcore_node_max);
}

void set_view_hash_table_size(uint32_t x)
{
    g_view_hash_table_size = x;
    RTE_LOG(INFO, LDNS, "Set  view_hash_table_size to %u\n",
            g_view_hash_table_size);
}

void set_edns_on(int x)
{
    g_edns_on = x;
    RTE_LOG(INFO, LDNS, "Set edns_on to %d\n", g_edns_on);
}

void set_httpdns_on(int x)
{
    g_httpdns_on = x;
    RTE_LOG(INFO, LDNS, "Set httpdns_on to %d\n", g_httpdns_on);
}

void set_forwarder_fail_down(int x)
{
    g_forwarder_fail_down = x;
    RTE_LOG(INFO, LDNS, "Set forwarder_fail_down to %d\n", g_forwarder_fail_down);
}

void set_forwarder_up_after_down(int x)
{
    g_forwarder_up_after_down = x;
}

void set_charge_file_interval(int x)
{
    g_charge_file_interval = x;
}

void set_bind_addr(char *x)
{
    g_bind_addr = x;
    RTE_LOG(INFO, LDNS, "Set admin control ip to %s\n", g_bind_addr);
}

void set_bind_port(uint16_t x)
{
    g_bind_port = x;
    RTE_LOG(INFO, LDNS, "Set admin control port to %d\n", g_bind_port);
}

void set_port_ip_net(uint32_t ip, uint8_t port)
{
    g_port_ip[port] = ip;
    RTE_LOG(INFO, LDNS, "Set port %d ip to %d.%d.%d.%d\n", port, NIP_STR(ip));
}

#define PRINT_MAC(addr) \
    ((const uint8_t *)addr)[0], \
    ((const uint8_t *)addr)[1], \
    ((const uint8_t *)addr)[2], \
    ((const uint8_t *)addr)[3], \
    ((const uint8_t *)addr)[4], \
    ((const uint8_t *)addr)[5]

void set_black_state(int x)
{
    g_black_state = x;
    RTE_LOG(INFO, LDNS, "Set balcklist to %d\n", g_black_state);
}

void set_white_state(int x)
{
    g_white_state = x;
    RTE_LOG(INFO, LDNS, "Set whitelist to %d\n", g_white_state);
}

void set_man_white_state(int x)
{
    g_man_white_state = x;
    RTE_LOG(INFO, LDNS, "Set whitelist to %d\n", g_man_white_state);
}

void set_man_black_state(int x)
{
    g_man_black_state = x;
    RTE_LOG(INFO, LDNS, "Set blacklist to %d\n", g_man_black_state);
}


void set_oversea_state(int x)
{
    g_oversea_state = x;
    RTE_LOG(INFO, LDNS, "Set oversealist to %d\n", g_oversea_state);
}

void set_view_nodes_ttl_threshold(int x)
{
    g_view_nodes_ttl_threshold = x;
    RTE_LOG(INFO, LDNS, "Set view_nodes_ttl_threshold to %d\n",
            g_view_nodes_ttl_threshold);
}
void clean_qtype_view_fwd(int qtype)
{
    g_qtype_fwd[qtype] = 0;
    RTE_LOG(INFO,LDNS,"Clean qtype [%d] forwarder to different view,qtype [%d] will forward to view default\n",qtype,qtype);
}

