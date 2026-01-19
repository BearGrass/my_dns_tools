#ifndef _REQUEST_DEF_H
#define _REQUEST_DEF_H

#include <netinet/ip6.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "rte_core.h"
#include "list.h"
#include "common.h"
#include "dns_pkt.h"
#include "storage.h"

#define LCORE_FWD_PORTS_MAX 30
#define MAX_ETHPORTS 8

#define FWD_NOTIFY 1
#define RDS_NOTIFY 2

struct request_t{
    struct ether_hdr ether;
    union common_ip_head ip_head;
    //struct ipv4_hdr ipv4_hdr;
    union common_l4_head l4_head;
    uint16_t l4_len;
    uint16_t id;
    union common_ip real_ip;
    uint8_t i_port;
    uint8_t flags1;
    uint8_t flags2;
    char ori_name[NAME_MAX_LEN+10];
    uint16_t ori_name_size;
    struct list_head list;
    int is_ipv6;
    int is_tcp;
    int is_from_kni;
    int has_ecs;
    struct adns_opt_ecs ecs;
    uint16_t answer_max_size;
};

typedef struct lcore_fwd_port_t{
    uint16_t ports[LCORE_FWD_PORTS_MAX];
    uint16_t ava_port_idx;
}lcore_fwd_port;

typedef struct request_t request;
typedef struct request_tcp_t request_tcp;

extern lcore_fwd_port fwd_port_mgr[RTE_MAX_LCORE][MAX_ETHPORTS];
extern struct rte_mempool *request_pool;
extern struct rte_mempool *request_tcp_pool[RTE_MAX_LCORE];
extern request *get_request(struct ether_hdr * ether,
        union common_ip_head *ip_head, union common_l4_head * l4_hdr, uint16_t l4_len,
        struct dns_packet * pkt, uint8_t i_port, int is_ipv6, int is_tcp, int is_dot);
extern int assign_lcore_forward_ports();
extern uint16_t find_forward_port(uint8_t o_if);
extern void forward_port_down(uint8_t o_if);

extern void put_request(request *r);
extern void put_request_tcp(request_tcp *r);
#endif
