#include "request.h"
#include "storage.h"
#include "stats.h"
#include "log.h"
#include "dns_pkt.h"
#include "json.h"
#include "bit.h"

lcore_fwd_port fwd_port_mgr[RTE_MAX_LCORE][MAX_ETHPORTS];

request *get_request(struct ether_hdr *ether, union common_ip_head *ip_head,
                     union common_l4_head *l4_hdr, uint16_t l4_len, struct dns_packet *pkt,
                     uint8_t i_port, int is_ipv6, int is_tcp, int is_from_kni)
{
    request *r;
    //RTE_LOG(INFO,LDNS,"get request free %u\n",rte_mempool_count(request_pool));
    struct rte_mempool *mp = request_pool;
    if (rte_mempool_get(mp, (void **)&r) < 0) {
        STATS(MP_GET_FAIL_DROP);
/*        ALOG(SERVER, WARN, "Cannot get obj from request_pools in %s",
             __func__);*/
        return NULL;
    }

    rte_memcpy(r->ori_name, (uint8_t *)pkt->wire + sizeof(struct dns_header) , pkt->qname_size);
    r->ori_name_size = pkt->qname_size;

    INIT_LIST_HEAD((&r->list));
    r->id = pkt->header.id;
    r->i_port = i_port;
    if (is_ipv6) {
        memcpy(&(r->real_ip.client_ipv6), &(pkt->client_ipv6), sizeof(struct in6_addr));
    } else {
        r->real_ip.client_ip = pkt->client_ip;
    }
    r->flags1 = pkt->header.flags1;
    r->flags2 = pkt->header.flags2;
    r->is_ipv6 = is_ipv6;
    r->is_tcp = is_tcp;
    r->is_from_kni = is_from_kni;
    r->has_ecs = pkt->has_ecs;
    if (r->has_ecs) {
        r->ecs = pkt->opt_rr.opt_ecs;
    }
    r->answer_max_size = pkt->answer_max_size;


    struct ether_hdr *l2 = &r->ether;
    *l2 = *ether;

    union common_ip_head *l3 = &r->ip_head;
    *l3 = *ip_head;

    union common_l4_head *l4 = &r->l4_head;
    *l4 = *l4_hdr;
    r->l4_len = l4_len;

    return r;
}

void put_request(request * r)
{
    rte_mempool_put(request_pool, r);
}

int assign_lcore_forward_ports()
{
    int lcore_id, if_id, port_id;
    int base = 10000;
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        for (if_id = 0; if_id < MAX_ETHPORTS; if_id++) {
            int tbase = base;
            for (port_id = 0; port_id < LCORE_FWD_PORTS_MAX; port_id++) {
                if (tbase > 65535) {
                    printf
                        ("Error,port assign bigger than 65535,exit,RTE_MAX_LCORE=%d,MAX_ETHPORTS=%d,LCORE_FWD_PORTS_MAX=%d\n",
                         RTE_MAX_LCORE, MAX_ETHPORTS, LCORE_FWD_PORTS_MAX);
                    return -1;
                }
                fwd_port_mgr[lcore_id][if_id].ports[port_id] = tbase++;
            }
            fwd_port_mgr[lcore_id][if_id].ava_port_idx = 0;
        }
        base += LCORE_FWD_PORTS_MAX;
    }

    return 0;
}

uint16_t find_forward_port(uint8_t o_if)
{
    uint16_t lcore_id = rte_lcore_id();
    uint16_t ava_port_idx = fwd_port_mgr[lcore_id][o_if].ava_port_idx;
    return fwd_port_mgr[lcore_id][o_if].ports[ava_port_idx];
}

void forward_port_down(uint8_t o_if)
{
    uint16_t lcore_id = rte_lcore_id();
    fwd_port_mgr[lcore_id][o_if].ava_port_idx =
        (fwd_port_mgr[lcore_id][o_if].ava_port_idx + 1) % LCORE_FWD_PORTS_MAX;
}
