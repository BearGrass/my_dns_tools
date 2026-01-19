
#ifndef _ADNS_MSG_H_
#define _ADNS_MSG_H_
#include <stdint.h>

#include "dns_pkt.h"
#include "stats.h"

#define LCORE_MSG_MAX_LEN 2048
#define MSG_QUEUE_SIZE 32


struct lcore_msg_fwd {
    struct rte_mbuf *m;
    struct ether_hdr *eth_hdr;
    union common_ip_head *ip_head;
    union common_l4_head *l4_head;
    uint16_t l4_len;
    struct dns_header *dns_hdr;
    int port_id;
    int support_ecs;
    int is_ipv6;
    int is_tcp;
    int is_from_kni;
    uint32_t idx;
    struct dns_packet packet;
};

struct lcore_msg_kni {
    struct rte_mbuf *m;
    struct ether_hdr *eth_hdr;
    union common_ip_head *ip_head;
    union common_l4_head *l4_head;
    int need_swap;
    int port_id;
};

struct lcore_msg_prefetch {
    struct node_t *node;
    struct list_head *tb_head;
};

struct lcore_msg_cmd {
    int len;
    rte_atomic16_t ref;
    char data[LCORE_MSG_MAX_LEN];
};

struct lcore_msg_info {
    int opcode;
    union {
        struct lcore_msg_cmd pcmd;
        struct lcore_msg_prefetch pnode;
        struct lcore_msg_fwd pfwd;
        struct lcore_msg_kni pkni;
    };
};

enum{
    MSG_DEL_KEY,
    MSG_DEL_REG_KEYS,
    MSG_DEL_ALL_KEY,
    MSG_PRO_START,
    MSG_PRO_STOP,
    MSG_FORWARDER_STATE,
    MSG_PREFETCH_NODE,
    MSG_REQ_FWD,
    MSG_RESP_KNI,
    MSG_TYPE_MAX
};

extern struct rte_ring *lcore_msg_ring[RTE_MAX_LCORE];
extern struct rte_mempool *g_lcore_msg_pool;

static inline struct lcore_msg_info *lcore_msg_alloc(int opcode) {
    struct lcore_msg_info *m = NULL;

    if (rte_mempool_get(g_lcore_msg_pool, (void **) (&m)) < 0) {
        STATS(MSG_MALLOC_FAIL);
        return NULL;
    }
    m->opcode = opcode;

    return m;
}

static inline void lcore_msg_free(struct lcore_msg_info *msg) {
    rte_mempool_put(g_lcore_msg_pool, (void *)msg);
}

static inline int lcore_msg_send(struct lcore_msg_info *msg, int lcore_id) {
    if (rte_ring_mp_enqueue(lcore_msg_ring[lcore_id], (void *)msg) < 0) {
        STATS(MSG_ENQUEUE_FAIL);
        lcore_msg_free(msg);
        return -1;
    }
    return 0;
}

static inline struct lcore_msg_info *lcore_msg_recv(void) {
    void *msg;
    if (rte_ring_sc_dequeue(lcore_msg_ring[rte_lcore_id()], &msg) < 0)
        return NULL;
    return (struct lcore_msg_info *)msg;
}

static inline int lcore_msg_bulk_recv(struct lcore_msg_info **msg_queue) {
    int num = MSG_QUEUE_SIZE;
    int lcore_id = rte_lcore_id();
    int rc = rte_ring_count(lcore_msg_ring[lcore_id]);
    if (rc <= 0)
        return 0;
    if (rc < num)
        num = rc;

    if (rte_ring_sc_dequeue_bulk(lcore_msg_ring[lcore_id], (void **)msg_queue, num) == 0) {
        return num;
    }
    return 0;
}

static inline struct lcore_msg_info* get_fwd_msg_info(struct rte_mbuf *m,
        struct ether_hdr *eth_hdr, union common_ip_head *ip_head,
        union common_l4_head *l4_head, uint16_t l4_len,
        struct dns_header *dns_hdr, int port, int is_ipv6, int is_tcp,
        int is_from_kni, struct dns_packet *packet, uint32_t idx, uint8_t support_ecs) {
    struct lcore_msg_info *entry = NULL;


    entry = lcore_msg_alloc(MSG_REQ_FWD);
    if (m == NULL) {
        return NULL;
    }

    entry->pfwd.m = m;
    entry->pfwd.eth_hdr = eth_hdr;
    entry->pfwd.ip_head = ip_head;
    entry->pfwd.l4_head = l4_head;
    entry->pfwd.l4_len = l4_len;
    entry->pfwd.dns_hdr = dns_hdr;
    entry->pfwd.port_id = port;
    entry->pfwd.support_ecs = support_ecs;
    entry->pfwd.is_ipv6 = is_ipv6;
    entry->pfwd.is_tcp = is_tcp;
    entry->pfwd.is_from_kni = is_from_kni;
    entry->pfwd.idx = idx;
    rte_memcpy(&entry->pfwd.packet, packet, sizeof(struct dns_packet));
    return entry;
}

static inline struct lcore_msg_info* get_kni_msg_info(struct rte_mbuf *m,
        struct ether_hdr *eth_hdr, union common_ip_head *ip_head,
        union common_l4_head *l4_head, int need_swap, int port) {
    struct lcore_msg_info *entry = NULL;


    entry = lcore_msg_alloc(MSG_RESP_KNI);
    if (m == NULL) {
        return NULL;
    }

    entry->pkni.m = m;
    entry->pkni.eth_hdr = eth_hdr;
    entry->pkni.ip_head = ip_head;
    entry->pkni.l4_head = l4_head;
    entry->pkni.need_swap = need_swap;
    entry->pkni.port_id = port;
    return entry;
}

int lcore_msg_init(void);

struct lcore_msg_info *get_cmd_msg_info(int opcode,int len,void *data);
struct lcore_msg_info* get_del_key_msg_info(char *name, int qtype,
		uint8_t stype);
int send_cmd_msg(struct lcore_msg_info *msg,int lcore_id);
void put_cmd_msg(struct lcore_msg_info *msg);
void get_cmd_msg(struct lcore_msg_info *msg);

#endif

