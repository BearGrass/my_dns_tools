#ifndef _H_STORAGE_DEF
#define _H_STORAGE_DEF
#include "rte_core.h"
#include "user_config.h"
#include "request.h"
#include "view.h"
#include "list.h"
#include "common.h"
#include "edns.h"
#include "msg.h"
#include "stats.h"

#define MAX_KEY_LEN 265 //256+8+1
#define MAX_VAL_LEN 1025 //1024 + 1 
#define KEY_GAP 8
#define ANSWER_MAX 80
#define ALINK_MAX 6
#define VAL_GAP 32 //step length
#define MIN_TTL 30
#define MAX_TTL 3600
#define PROTECTED_TTL (MIN_TTL - 5)
#define NXDOMAIN_MAX_TTL 600
#define COMMON_VIEW_NAME "-"
#define FAIL_NOTIFY_VIEW_MAX 30
#define COMMON_VIEW_ID 255
//7 days
#define STOLEN_TTL 604800 
#define STOLEN_RESP_TTL 600
#define MAX_RDS_PAYLOAD 1800 
#define DVAL_KEN_TYPE_NUM 6

enum{
    F_TIMER ,
    TIMER_TYPE_MAX
};

typedef struct key_t{
    struct rte_mempool *mp;
    int ref;
    uint8_t view_bit_map[VIEW_BITMAP_SIZE];
    uint32_t idx;
    uint16_t len;
    uint8_t data[0];
}dkey;

struct node_ttl_t {
    struct list_head list;
    int pos;
};

typedef struct node_ttl_t node_ttl;

struct node_share_t{
    uint8_t top;
    uint8_t lcore;
    uint8_t o_port;
    int klen;
    int vlen;
    char key[MAX_KEY_LEN];
    char val[MAX_VAL_LEN];
    uint32_t hash;
    uint32_t ttl;
    uint32_t ip;
    uint32_t view_id;
    uint16_t port;
};



struct adjust_node_t{
    char key[MAX_KEY_LEN] ;
    int klen;
    uint32_t ttl;
    uint32_t hash;
    uint32_t vid;
};
typedef struct adjust_node_t adjust_node;

struct anode_t{
    dkey *key;
    struct list_head node_list; //associate hash table node
    struct list_head hash_list;
    uint32_t count;
    hash_table *tb;
};

typedef struct anode_t anode;

struct link_t{
    int link_id;
    struct list_head list;
    anode *anode_owner;
};
typedef struct link_t alink;

typedef struct node_val{
    struct rte_mempool *mp;
    int ref;
    uint16_t ttl_pos[ANSWER_MAX]; /* node with the same TTL on a list */
    uint8_t ttl_pos_size;
    uint16_t len;
    uint8_t data[0];
}dval;

typedef struct _node_view_tbl {
    struct list_head view_hash[VIEW_MAX_COUNT];
    uint32_t size;
} __rte_cache_aligned node_view_tbl;

struct node_t{
    uint8_t try;
    uint8_t prefetch_try;
    uint8_t stry; //servFail try
    uint8_t o_port;

    dkey *key;
    dval *val;

    node_view_tbl *tbl;
    uint32_t ttl;
    uint64_t ctime;

    uint16_t dns_id;
    uint16_t forward_port;
    uint32_t forward_vid; //match_org_ip_view_id
    uint32_t forward_rvid;//real_fwd_view_id
    uint32_t forward_ip;
    uint8_t support_ecs;
    uint8_t anode_count;

    uint32_t last_prefetch_time;
#ifdef JMEM_MGR
    struct list_head jkey_list;
    struct list_head jval_list;
#endif
    struct list_head node_list;
    struct list_head wait_list;
    struct list_head timer_list[TIMER_TYPE_MAX];
    alink anode_link[ALINK_MAX]; //link to associate anode;

    int wait_size; /* how many DNS query received from client */
    int lcore_id;
    vstats_type node_state;
    uint8_t srv_type;
    struct dnscache_node *cnode;
};

typedef struct nic_port_info_t{
    struct ether_addr nic_mac;
    struct ether_addr gw_mac;
    uint32_t ip;
    int ready;
}nic_info;

typedef struct node_t node;
typedef struct node_share_t node_share;
extern uint32_t ganode_view_id ; // used to share dkey memory with normal view dkey
extern nic_info nic[8];
extern const char *g_obj_name[DVAL_KEN_TYPE_NUM];
extern uint8_t g_dval_obj_ratio[DVAL_KEN_TYPE_NUM];
extern uint32_t g_ids_per_core;
extern struct rte_mempool *node_pool;
extern struct rte_mempool *mbuf_pool[RTE_MAX_LCORE];
extern struct rte_mempool *dkey_pool;
extern struct rte_mempool *dval_pool;

extern struct rte_mempool *fctx_pool[RTE_MAX_LCORE];

extern struct rte_mempool *timer_pool[RTE_MAX_LCORE];


extern hash_table *key_space[RTE_MAX_LCORE];
extern hash_table *view_hash[VIEW_MAX_COUNT];
extern int view_nodes[RTE_MAX_LCORE][VIEW_MAX_COUNT];

static inline int  __attribute__ ((always_inline))
get_query_key(struct dns_packet *pkt, uint8_t * key)
{
    int len = pkt->qname_size;
    rte_memcpy(key, pkt->qname, len);
    rte_memcpy(key + len, &pkt->qtype, QUERY_TYPE_LEN);
    len += QUERY_TYPE_LEN;
    *(key + len) = pkt->srv_type;
    return ++len;

}

static inline void  __attribute__ ((always_inline))
set_node_vstate(node * n, vstats_type nstate) {
    if (n->node_state != nstate) {
        DVSTATS(n->forward_vid, n->node_state);
        n->node_state = nstate;
        VSTATS(n->forward_vid, nstate);
    }
}

static inline void fix_qname(struct dns_header *dnh, char *ori_name, uint16_t ori_name_size) {
    uint8_t *pos;
    pos = (uint8_t *)dnh + LDNS_WIRE_HEADER_SIZE;
    rte_memcpy(pos, ori_name, ori_name_size);
}

static inline int
match_key(const dkey * dk, const uint8_t * key, uint16_t klen)
{
    if(dk->ref <= 0) {
        return 0;
    }

    if (dk->len != klen)
        return 0;

    if (memcmp(dk->data, key, klen) != 0)
        return 0;
    /*
    int pass = klen - 2;
    if (memcmp(buf->base + pass, key + pass, 2) != 0)
        return 0;
    */
    return 1;
}

static inline int
match_node(const node * n, const uint8_t * k, uint16_t klen) {
    if(n->key == NULL) {
        return 0;
    }

    return match_key(n->key, k, klen);
}

static inline uint32_t
node_hash_val(const uint8_t *p, uint16_t size) {
    return (rte_jhash(p, size, JHASH_INITVAL) & (g_view_hash_table_size - 1));
}

static inline uint32_t
get_core_by_idx(uint32_t idx) {
    return gio_id[idx/g_ids_per_core];
}

/*
extern struct list_head *task_pending[RTE_MAX_LCORE];
static inline void
add_task_pending(struct list_head *task) {
    task_pending[rte_lcore_id()] = task;
}
static inline void
reset_task_pending() {
    task_pending[rte_lcore_id()] = NULL;
}

extern void task_work(struct list_head *task);
static inline int
charge_task_pending() {
    struct list_head *task = task_pending[rte_lcore_id()];
    if (task == NULL)
        return 0;
    task_work(task);

    return 1;
}
*/

extern hash_table * create_hash_table(const char *name,int size,int socket_id);
extern void del_key(const uint8_t *name,int qtype);
extern void del_all_key();

extern void adjust_node_ttl(const uint8_t *msg , int len);
extern void get_query_dname(uint8_t *key,int klen,char *target);
//extern int  query_find_tcp(const uint8_t *qkey,int klen, struct ether_hdr *eth_hdr, struct ipv4_hdr *iph,struct dns_packet *pkt,uint8_t port,node **tnode,node **tfind, struct tcp_pcb *pcb, struct pbuf *p);
extern inline int dns_input(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        union common_ip_head *ip_head, union common_l4_head *l4_hdr, uint16_t l4_len,
        struct dns_header *dns_hdr, uint8_t port, int is_ipv6, int is_tcp, int is_from_kni);
extern int query_find(uint8_t * qkey, int klen, uint32_t idx,
        struct ether_hdr *eth_hdr, union common_ip_head *ip_head,
        union common_l4_head *l4_head, uint16_t l4_len, struct dns_packet *pkt,
        uint8_t port, node ** tfind, int is_ipv6, int is_tcp, int is_from_kni,
        uint8_t support_ecs);
extern int query_find_diff_core(uint8_t * qkey, int klen, uint32_t idx,
        node ** tfind, uint32_t view_id, int new_core_id, uint8_t support_ecs,
        view_db_t *views);
extern void cache_packet(struct dns_packet *pkt, uint32_t ip, uint16_t port);
extern int socket_init();
extern int lcore_io_init();
extern int node_db_init();
extern int g_pool_init();
extern int lcore_misc_init(int lcore_id);
extern void ttl_expire_check(int size);
extern void  node_timer_manage(uint64_t timeout,int batch);
extern void fix_ttl(struct dns_header *dnh, node *n);
extern void fix_flag(struct dns_header *dnh, uint8_t flags1, uint8_t flag2);
extern int add_edns_client_subnet(struct rte_mbuf *m, union common_ip_head *ip_head,
        union common_l4_head *l4_head, uint16_t l4_len, struct dns_header *dnh,
        union common_ip *real_ip, int is_ipv6, int is_tcp,
        struct adns_opt_ecs *ecs, uint16_t buf_size);
extern void del_reg_keys(char *regStr,int len);

extern void build_protect_regex(char *data, int len);
extern void clean_protect_regex();
extern void rds_pkt_hander(struct ipv4_hdr *iph, struct udp_hdr *udh);

extern void specified_node_prefetch(struct lcore_msg_prefetch *p);

#endif
