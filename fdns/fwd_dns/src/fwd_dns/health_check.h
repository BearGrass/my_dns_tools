#ifndef __HEALTH_CHECK__
#define __HEALTH_CHECK__
#define HEALTH_CHECK_DNS_ID 0x3a92 

#include <stdint.h>

struct hc_node_t{
	uint32_t ip;
	uint16_t port;
	dkey *key;
	struct rte_mbuf *mbuf;
	struct list_head timer_list;
	struct list_head node_list;
	struct list_head hash_list;
	uint64_t ctime;
	uint32_t last_send;
};
typedef struct hc_node_t hc_node;

struct 	hc_nodes_mgr_t{
	uint8_t if_port;
	hash_table *hash_table;
	struct list_head node_head;
	struct list_head timer_head;
	int node_nums;
	int timer_nums;
	hc_node *next_hc;
	
};
typedef struct hc_nodes_mgr_t hc_nodes_mgr;

extern int health_check_manage();
extern int health_check_timer_manage(uint64_t timeout,int batch);
extern int health_check_init(int lcore_id); 
extern void set_active_port(uint8_t port);
extern int health_check_add(int lcore_id, uint32_t ip, uint16_t port, uint8_t srv_type);
extern void charge_health_check(uint32_t ip, uint16_t port, const uint8_t * key, int klen);

#endif
