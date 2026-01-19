#include "request.h"
#include "storage.h"
#include"health_check.h"
#include "ldns.h"
#include "log.h"
#define LCORE_HC_MAX 10240
static hc_nodes_mgr nodes_mgr[RTE_MAX_LCORE];

static uint32_t hash_val(const uint8_t * p, int size)
{
    return (rte_jhash(p, size, JHASH_INITVAL) & (LCORE_HC_MAX - 1));
}

static void stop_timer(hc_node * n)
{
    if (!list_empty(&n->timer_list)) {
        list_del_init(&n->timer_list);
        nodes_mgr[rte_lcore_id()].timer_nums--;
    }
}

static void health_check_timeout(hc_node * n)
{
    int lcore_id = rte_lcore_id();
    set_forwarder_state(n->ip, n->port, DOWN);
    //ALOG(SERVER,WARN,"Lcore %d (%s)Set forwarder %d.%d.%d.%d:%d %s\n",rte_lcore_id(),n->key->buf.base,HIP_STR(n->ip),n->port,"DOWN");
    forward_port_down(nodes_mgr[lcore_id].if_port);
    assert(!list_empty(&n->timer_list));
    assert(nodes_mgr[lcore_id].timer_nums > 0);
    stop_timer(n);

}

static void enqueue_timer(hc_node * n)
{
    int lcore_id = rte_lcore_id();
    assert(list_empty(&n->timer_list));
    n->ctime = NOW64;
    n->last_send = NOW;
    list_add_tail(&n->timer_list, &nodes_mgr[lcore_id].timer_head);
    nodes_mgr[lcore_id].timer_nums++;
}

static hc_node *dequeue_timer(uint64_t timeout)
{
    hc_node *n = NULL;
    hc_node *tmp;
    int lcore_id = rte_lcore_id();
    uint64_t now = NOW64;
    if (!list_empty(&nodes_mgr[lcore_id].timer_head)) {
        assert(nodes_mgr[lcore_id].timer_nums > 0);
        tmp =
            list_first_entry(&nodes_mgr[lcore_id].timer_head, hc_node,
                             timer_list);
        if (tmp->ctime + timeout < now) {
            //ALOG(QUERY,INFO,"ctime %ld,timeout %ld,now %ld timeout",tmp->ctime,timeout,now);
            n = tmp;
        }
    } else {
        assert(nodes_mgr[lcore_id].timer_nums == 0);
    }
    return n;
}

int health_check_timer_manage(uint64_t timeout, int batch)
{
    int i;
    for (i = 0; i < batch; i++) {
        hc_node *n = dequeue_timer(timeout);
        if (n == NULL)
            return -1;
        health_check_timeout(n);
    }
    return 0;
}

int health_check_manage()
{

    int lcore_id = rte_lcore_id();
    if (nodes_mgr[lcore_id].if_port == 0xff) {
        return -1;
    }

    hc_node *cur = nodes_mgr[lcore_id].next_hc;
    if (&cur->node_list == &nodes_mgr[lcore_id].node_head) {
        goto out;
    }

    if (!list_empty(&cur->timer_list)) {
        //health_check timeout process
        goto out;
    }

    uint32_t now = NOW;
    if (now - cur->last_send < 1)
        goto out;

    enqueue_timer(cur);

    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(cur->mbuf, struct ether_hdr *);
    ether_addr_copy(&nic[nodes_mgr[lcore_id].if_port].nic_mac,
                    &eth_hdr->s_addr);
    ether_addr_copy(&nic[nodes_mgr[lcore_id].if_port].gw_mac, &eth_hdr->d_addr);

    struct ipv4_hdr *ipv4_hdr =
        (struct ipv4_hdr *)(rte_pktmbuf_mtod(cur->mbuf, unsigned char *) +
                            sizeof(struct ether_hdr));
    if (ipv4_hdr->src_addr != nic[nodes_mgr[lcore_id].if_port].ip) {
        ipv4_hdr->src_addr = nic[nodes_mgr[lcore_id].if_port].ip;
        ipv4_hdr->hdr_checksum = 0;
    }
    rte_mbuf_refcnt_update(cur->mbuf, 1);
    send_single_frame(cur->mbuf, nodes_mgr[lcore_id].if_port);
    STATS(HEALTH_CHECK_REQ);
    /*
     ALOG(SERVER, DEBUG,
     "Lcore %d (%s)sendto forwarder from %d.%d.%d.%d to %d.%d.%d.%d:%d",
     lcore_id, cur->key->buf.base, NIP_STR(ipv4_hdr->src_addr),
     HIP_STR(cur->ip), cur->port);
     */
    //rte_pktmbuf_dump(cur->mbuf,ETH_HLEN + IP_HLEN +UDP_HLEN + DNS_HLEN + 50);
    return 0;

out:
    nodes_mgr[lcore_id].next_hc =
        list_entry(cur->node_list.next, hc_node, node_list);
    return -1;
}

void set_active_port(uint8_t port)
{
    nodes_mgr[rte_lcore_id()].if_port = port;
}

uint8_t get_active_port()
{
    return nodes_mgr[rte_lcore_id()].if_port;
}

void charge_health_check(uint32_t ip, uint16_t port, const uint8_t * key, int klen)
{
    hc_node n;
    memset(&n, 0, sizeof(n));
    n.ip = ip;
    n.port = port;
    uint32_t idx = hash_val((uint8_t *) & n, 6);
    hash_table *tb = nodes_mgr[rte_lcore_id()].hash_table + idx;
    hc_node *tmp;
    list_for_each_entry(tmp, &tb->list, hash_list) {
        dkey *_dk = tmp->key;
        if (match_key(_dk, key, klen)) {
            stop_timer(tmp);
            //ALOG(SERVER,WARN,"Lcore %d (%s)Set forwarder %d.%d.%d.%d:%d %s\n",rte_lcore_id(),key,HIP_STR(ip),port,"UP");
        }
    }
}

int health_check_init(int lcore_id)
{
    nodes_mgr[lcore_id].if_port = 0xff;
    INIT_LIST_HEAD(&nodes_mgr[lcore_id].node_head);
    INIT_LIST_HEAD(&nodes_mgr[lcore_id].timer_head);
    nodes_mgr[lcore_id].node_nums = 0;
    nodes_mgr[lcore_id].timer_nums = 0;
    nodes_mgr[lcore_id].next_hc =
        list_entry(&nodes_mgr[lcore_id].node_head, hc_node, node_list);
    hash_table *tb =
        rte_zmalloc_socket(NULL, LCORE_HC_MAX * sizeof(hash_table), 0,
                           rte_lcore_to_socket_id(lcore_id));
    nodes_mgr[lcore_id].hash_table = tb;
    if (nodes_mgr[lcore_id].hash_table == NULL) {
        RTE_LOG(ERR, LDNS, "Cannot create hc_nodes_mgr_hash_table[%u]\n",
                lcore_id);
        return -1;
    }

    int i;
    for (i = 0; i < LCORE_HC_MAX; i++) {
        hash_table *t = nodes_mgr[lcore_id].hash_table + i;
        INIT_LIST_HEAD((&t->list));
        t->size = 0;
    }

    return 0;
}

static int __health_check_add(int lcore_id, uint32_t ip, uint16_t port,
                              const uint8_t * key, int klen, int port_offset)
{

    hc_node *n = rte_zmalloc_socket(NULL, sizeof(hc_node), 0,
                                    rte_lcore_to_socket_id(lcore_id));
    if (n == NULL) {
        RTE_LOG(ERR, LDNS, "Lcore %d : Cannot rte_zmalloc health node\n",
                lcore_id);
        return -1;
    }

    n->key =
        rte_zmalloc_socket(NULL, sizeof(dkey) + klen, 0,
                           rte_lcore_to_socket_id(lcore_id));
    if (n->key == NULL) {
        RTE_LOG(ERR, LDNS, "Lcore %d : Cannot rte_zmalloc health node key\n",
                lcore_id);
        return -1;
    }

    dkey *dk = n->key;
    rte_memcpy(dk->data, key, klen);
    dk->len = klen;
    dk->ref = 1;
    n->ip = ip;
    n->port = port;
    INIT_LIST_HEAD(&n->node_list);
    INIT_LIST_HEAD(&n->timer_list);
    INIT_LIST_HEAD(&n->hash_list);
    n->mbuf = rte_pktmbuf_alloc(app.lcore_params[lcore_id].pool);
    if (n->mbuf == NULL) {
        RTE_LOG(ERR, LDNS, "Lcore %d : Cannot alloc health check mbuf\n",
                lcore_id);
        return -2;
    }

    int if_port = 0;

    uint16_t udlen = UDP_HLEN + DNS_HLEN + dk->len - SERVER_TYPE_LEN + 2;
    if (unlikely(rte_pktmbuf_append(n->mbuf, ETH_HLEN + IP_HLEN + udlen) < 0)) {
        RTE_LOG(ERR, LDNS, "Lcore %d : health check mbuf append Fail\n",
                lcore_id);
        rte_pktmbuf_free(n->mbuf);
        return -3;
    }

    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(n->mbuf, struct ether_hdr *);
    ether_addr_copy(&nic[if_port].nic_mac, &eth_hdr->s_addr);
    ether_addr_copy(&nic[if_port].gw_mac, &eth_hdr->d_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    struct ipv4_hdr *ipv4_hdr =
        (struct ipv4_hdr *)(rte_pktmbuf_mtod(n->mbuf, unsigned char *) +
                            sizeof(struct ether_hdr));
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->packet_id = 0x3f1f;
    ipv4_hdr->fragment_offset = Lhtons(0 | (2 << 13));
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->src_addr = nic[if_port].ip;
    ipv4_hdr->dst_addr = Lhtonl(ip);
    ipv4_hdr->hdr_checksum = 0;

    struct udp_hdr *udh = dns_udp_hdr(n->mbuf, ipv4_hdr);
    udh->dst_port = Lhtons(port);
    uint16_t s_port = fwd_port_mgr[lcore_id][if_port].ports[port_offset];
    udh->src_port = Lhtons(s_port);
    udh->dgram_cksum = 0;

    struct dns_header *dnh = (struct dns_header *)((uint8_t *) udh + UDP_HLEN);
    dnh->id = HEALTH_CHECK_DNS_ID;
    dnh->flags1 = 0x01;
    dnh->flags2 = 0;
    dnh->qdcount = Lhtons(1);
    dnh->ancount = 0;
    dnh->nscount = 0;
    dnh->arcount = 0;

    uint8_t *wire = ((uint8_t *) ipv4_hdr) + IP_HLEN + UDP_HLEN + DNS_HLEN;
    rte_memcpy(wire, dk->data, dk->len - QUERY_TYPE_LEN - SERVER_TYPE_LEN);
    wire += dk->len - QUERY_TYPE_LEN - SERVER_TYPE_LEN;

    uint8_t *w = ((uint8_t *) dk->data)
            + dk->len- QUERY_TYPE_LEN - SERVER_TYPE_LEN;
    uint16_t qtype = *((uint16_t *) w);
    uint16_t *q = (uint16_t *) wire;
    *q = Lhtons(qtype);
    wire += 2;

    uint16_t *class = (uint16_t *) wire;
    *class = Lhtons(1);

    udh->dgram_len = Lhtons(udlen);
    ipv4_hdr->total_length = Lhtons(IP_HLEN + udlen);
    n->mbuf->ol_flags |= PKT_TX_IP_CKSUM;
    n->mbuf->l2_len = sizeof(struct ether_hdr);
    n->mbuf->l3_len = sizeof(struct ipv4_hdr);

    uint32_t idx = hash_val((uint8_t *) n, 6);
    hash_table *tb = nodes_mgr[lcore_id].hash_table + idx;
    hc_node *tmp;
    list_for_each_entry(tmp, &tb->list, hash_list) {
        dkey *_dk = tmp->key;
        if (match_key(_dk, key, klen)) {
            return 0;
        }
    }

    list_add_tail(&n->hash_list, &tb->list);
    tb->size++;

    list_add_tail(&n->node_list, &nodes_mgr[lcore_id].node_head);
    nodes_mgr[lcore_id].node_nums++;
    ALOG(SERVER, WARN, "Lcore %d (%s)Add forwarder %d.%d.%d.%d:%d from port %d", lcore_id,
         n->key->data, HIP_STR(n->ip), n->port, s_port);

    return 0;
}

int health_check_add(int lcore_id, uint32_t ip, uint16_t port, uint8_t srv_type)
{
    const int M = 5;
    char entry[M][300];
    memset(entry, 0, sizeof(entry));
    strcpy(entry[0], "a.root-servers.net./1");
    strcpy(entry[1], "a.gtld-servers.net./1");
    strcpy(entry[2], "www.taobao.com./1");
    strcpy(entry[3], "www.baidu.com./1");
    strcpy(entry[4], "www.qq.com./1");
    int i;
    char *p;
    for (i = 0; i < M; i++) {
        char *type = strstr(entry[i], "/");
        int qtype = atoi(type + 1);
        type[0] = '\0';

        char *name = entry[i];
        char tkey[300];
        int idx = 0;

        while (name[0] && ((p = strstr(name, ".")) != NULL)) {
            uint8_t len = p - name;
            if (len == 0 && name[0] == '.') {
                name++;
                continue;
            }
            tkey[idx++] = len;
            rte_memcpy(tkey + idx, name, len);
            idx += len;
            name = p;
        }

        tkey[idx++] = '\0';
        uint16_t *ttype = (uint16_t *) (tkey + idx);
        *ttype = (uint16_t) qtype;
        idx += 2;
        *(tkey + idx) = srv_type;
        idx++;
        if (__health_check_add(lcore_id, ip, port, (const uint8_t *)tkey, idx, i) < 0)
            return -1;
    }

    return 0;
}
