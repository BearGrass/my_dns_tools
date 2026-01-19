#define _GNU_SOURCE
#include <sys/socket.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <assert.h>
#include <sys/types.h>
#include <regex.h>


#include <rte_random.h>
#include <rte_hexdump.h>

#include "descriptor.h"
#include "request.h"
#include "health_check.h"
#include "user_config.h"
#include "bit.h"
#include "log.h"
#include "dns_pkt.h"
#include "wire.h"
#include "view.h"
#include "ldns.h"
#include "msg.h"
#include "qtype.h"
#include "stats.h"
#include "gen_pkt.h"
#include "tolower.h"
#include "common.h"
#include "net_debug.h"
#include "ipv6_fwd.h"
#include "edns.h"
#include "view_maps.h"
#include "adns_log.h"
#include "dnscache_tbl.h"
#include "qos.h"


#define SERVFAIL_TRY_MAX 3
#define TASK_BATCH 30

#define NODE_STATE_NONE (0x00000002)
#define NODE_STATE_STALE (0)
#define NODE_STATE_OK (1)
#define PREFETCH_DNS_ID 0x1f3f
#define MAX_PREFETCH_TRY 5
#define TTL_DELAY 600
#define TTL_PREFETCH 30
#define TTL_DELAY_ADJ 120
#define EDNS_MASK 0x1820

#define REGEX_OFF 0
#define REGEX_ON 1

#define TTL_INIT (0x00000001)
#define TTL_MAX STOLEN_TTL
#define ANODE_LIST_MAX 10000

#define DKEY_KEN_TYPE_NUM 3
static uint16_t dkey_buff_max_lens[DKEY_KEN_TYPE_NUM] = { 64, 128, 256+3 };
static uint8_t dkey_obj_ratio[DKEY_KEN_TYPE_NUM] = {6, 3, 1};
#define DVAL_KEN_TYPE_NUM 6
static uint16_t dval_buff_max_lens[DVAL_KEN_TYPE_NUM] = { 64, 128, 256, 512, 1024, 1408 };
uint8_t g_dval_obj_ratio[DVAL_KEN_TYPE_NUM] = {48, 48, 16, 4, 2, 1};
const char *g_obj_name[DVAL_KEN_TYPE_NUM] = {
    "obj_len64",
    "obj_len128",
    "obj_len256",
    "obj_len512",
    "obj_len1024",
    "obj_len1408",
};

/*
#define ECHECK(p0,cur,n) do{ \
        if(cur - p0 >= g_obj_max_lens[OBJ_MAX_LEN-1]){ \
            ALOG(QUERY,ERROR,"EdnsCheck[%d],offset %d > %d error",n,cur-p0,g_obj_max_lens[OBJ_MAX_LEN-1]); \
            assert(0); \
            return 0; \
        } \
    }while(0)
 */
#define ECHECK(p0,cur,n) do{ \
        if(cur - p0 >= dval_buff_max_lens[DVAL_KEN_TYPE_NUM-1]){ \
            STATS(EDNS_PACK_ERR); \
            return 0; \
        } \
    }while(0)

static RTE_DEFINE_PER_LCORE(uint32_t, ttl_expire_hash_idx);
//struct list_head *task_pending[RTE_MAX_LCORE];

struct lcore_regex_t{
    regex_t oRegex;
    int view_id;
    int work;
};

static struct lcore_regex_t lcore_regex[RTE_MAX_LCORE];
//static __thread uint32_t ttl_expire_hash_idx;
struct rte_ring *io_input_ring[RTE_MAX_LCORE];
struct rte_mempool *node_pool;
struct rte_mempool *anode_pool;
static struct rte_mempool *dkey_pools[DKEY_KEN_TYPE_NUM];
static struct rte_mempool *dval_pools[DVAL_KEN_TYPE_NUM];
struct rte_mempool *request_pool;
int view_nodes[RTE_MAX_LCORE][VIEW_MAX_COUNT];
static int anode_max_count=1000000;
uint32_t g_ids_per_core;

typedef struct _lcore_timer_mgr {
    struct list_head list;
    int nums;
} lcore_timer_mgr;
static lcore_timer_mgr timer_mgr[RTE_MAX_LCORE][TIMER_TYPE_MAX];
#ifdef JMEM_MGR
#define JMEM_FREE_SIZE 100
typedef struct _used_jmem {
    struct list_head list;
    struct list_head *iter; // now first can drop pos
} used_jmem;

used_jmem jmem_mgr[RTE_MAX_LCORE][JMEM_MAX_TYPE][DVAL_KEN_TYPE_NUM];

typedef enum{
    KEY,
    VAL,
    JMEM_MAX_TYPE,
}jmem_type;
static inline void unmark_used_jmem(jmem_type type, int size, node * n);
static inline void mark_used_jmem(jmem_type type, int size, node * n);
static inline char *get_jmem_type_str(jmem_type type);
static void jmem_try_free(int len, jmem_type type, int size)
static inline int can_free_node(node * n);
#endif
hash_table *anode_hash[RTE_MAX_LCORE];
node_view_tbl *g_node_db;

static inline void free_node(node * n);

static inline void flush_wait_list(node * n);
static inline void put_dkey(node * n);
static inline dval *get_dval(int size, const uint8_t * ptr);
static inline void put_dval(node * n);
static inline void replace_dval(node *n, dval *dv, int dvlen);
static inline int check_fetch_cond(node * n);
static inline void get_query_aname(uint8_t *key, int size, char *target);

static inline int servFail_node(node * n);
static inline int servFail_node_try_fix(node * n);
static inline void servFail_node_send_fix(node * n);

static inline void init_all_timer(node * n);
static inline void init_node_link(node * n);
static inline void init_alink(alink *link);
static inline void add_anode_to_hash(anode *an,hash_table *tb);
static inline void del_anode_from_hash(anode *an);


static inline int get_anode(anode **tan);
static inline void put_anode(anode **tan);
static inline alink *__link_anode(node *n, anode *an);
static inline int __node_link_key(uint32_t idx, uint8_t *key, int klen, node *n);
static inline int __node_link_val(uint8_t *key, int klen, node *n, uint8_t index);
static inline void stop_timer(node *n,int type);
static inline void stop_all_timer(node *n);
static inline node * dequeue_timer(uint64_t timeout,int type);
static inline void enqueue_timer(node *n,int type);
static inline void forward_timeout(node *n);

static inline void node_prefetch(node *n, uint32_t now);
static inline int node_prefetch_try(node *n, uint32_t now);
static inline void forward_send_pkt(node *n);


static inline int isMatchRegex(const char *key, const regex_t * oRegex, int regCount);
static inline void __del_reg_str_keys(int view_id, char *regStr);
static inline void __del_reg_keys(int view_id, char **regStr, int regCount);
static inline void __del_view_key(int vid, regex_t * reg, int regCount);

int (*socket_linux)(int domain, int type, int protocol);

char gw_ethaddr[6] = { 0x12, 0x23, 0x34, 0x45, 0x56, 0x6c };

static inline int
get_obj_num(uint64_t tot_num, uint8_t *obj_ratio,
        uint8_t type_num, uint8_t type_idx) {
    uint64_t i;
    uint64_t rsum = 0;

    if (type_idx >= type_num) {
        RTE_LOG(ERR, LDNS,
                "Fail to alloc obj_count, as type_idx(%d) >= type_num(%d)\n",
                type_idx, type_num);
        assert(0);
    }

    for (i = 0; i < type_num; i++) {
        rsum += obj_ratio[i];
    }
    if (rsum == 0) {
        RTE_LOG(ERR, LDNS, "Fail to alloc obj_count, as rsum = 0\n");
        assert(0);
    }

    return (obj_ratio[type_idx] * tot_num) / rsum;
}

static inline dkey *dkey_new(int size, const uint8_t * ptr, int view_id, uint32_t idx) {
    dkey *dk;
    void *data = NULL;
    uint32_t i;

    for (i = 0; i < DKEY_KEN_TYPE_NUM; ++i) {
        if (dkey_buff_max_lens[i] >= size) {
            if (unlikely(
                    rte_mempool_get(dkey_pools[i], &data) < 0 || data == NULL)) {
                ALOG(SERVER, WARN,
                        "Lcore %d : dkey_new failed, len: %d, len index: %d in %s",
                        rte_lcore_id(), size, i, __func__);
                STATS(MP_GET_FAIL_DROP);
                // try to get a dkey buffer from next pool
                continue;
            }
            dk = (dkey *) data;
            dk->ref = 1;
            set_bit(dk->view_bit_map, view_id);
            dk->idx = idx;
            dk->len = size;
            rte_memcpy(dk->data, ptr, size);

            return dk;
        }
    }

#ifdef JMEM_MGR
    jmem_try_free(size, KEY, JMEM_FREE_SIZE);
#endif
    STATS(DKEY_MP_GET_FAIL);
    return NULL;
}

static inline void
__task_work(struct list_head *task)
{
    int i = 0;
    alink *link;
    node *n;

    //while(!list_empty(task)){
    list_for_each_entry(link, task, list) {
        n = list_entry(&link->list,node,anode_link[link->link_id].list);

        if (n->ttl != TTL_INIT && n->val != NULL) {
            uint32_t now = NOW;

            node_prefetch(n, now);
            n->ttl = now;
        }
        //free_node(n);
        i ++;

        if(i == TASK_BATCH){
            //add_task_pending(task);
            STATS(DEL_CACHE_DROP);
            return;
        }
    }
    //reset_task_pending();
}

/*
void task_work(struct list_head *task) {
    return __task_work(task);
}
*/

hash_table * create_hash_table(const char *name,int size,int socket_id)
{
    hash_table *tb =  rte_zmalloc_socket(name,size*sizeof(hash_table),0,socket_id);
    if(tb == NULL){
        RTE_LOG(ERR,LDNS,"Fail to create %s",name);
        return NULL;
    }

    int i;
    for (i = 0; i < size; i++) {
        hash_table *t = tb + i;
        INIT_LIST_HEAD((&t->list));
        t->size = 0;
    }

    RTE_LOG(INFO, LDNS, "%s hash table created, size %d ,socket %d\n", name, size, socket_id);
    return tb;
}

static inline int
match_akey(dkey *dk, const uint8_t *key,int klen)
{
    if (dk->len != klen)
        return 0;
    if (memcmp(dk->data, key, klen/* - 2*/) != 0)
        return 0;
    return 1;
}

static inline int
encapsulate_query_pkt(uint8_t o_port, dkey *dk, uint32_t dip,
        uint16_t dport, uint16_t dns_id, int16_t udlen, uint8_t flag1,
        uint8_t flag2, uint8_t **wire_p, struct rte_mbuf **m_p) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(app.lcore_params[rte_lcore_id()].pool);
    if (m == NULL) {
        STATS(MP_GET_FAIL_DROP);
        //ALOG(SERVER, ERROR, "rte_pktmbuf_alloc fail in %s", __func__);
        return -1;
    }
    *m_p = m;

    if (unlikely(rte_pktmbuf_append(m, ETH_HLEN + IP_HLEN + udlen) < 0)) {
        //ALOG(SERVER, ERROR, "rte_pktmbuf_append error in %s", __func__);
        rte_pktmbuf_free(m);
        STATS(MBUF_APPEND_DROP);
        return -1;
    }

    struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    eth_hdr->d_addr = nic[o_port].gw_mac;
    eth_hdr->s_addr = app.eth_addrs[o_port];
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);

    struct ipv4_hdr *ipv4_hdr =
            (struct ipv4_hdr *) (rte_pktmbuf_mtod(m, unsigned char *)
                    + sizeof(struct ether_hdr));
    uint32_t sip = Lntohl(get_port_ip_net(o_port));
    gen_ipv4_hdr(ipv4_hdr, FWD_COMMON_IP_PKT_ID, IPPROTO_UDP, sip,
            dip, IP_HLEN + udlen);

    struct udp_hdr *udh = dns_udp_hdr(m, ipv4_hdr);
    uint16_t sport = find_forward_port(o_port);
    gen_udp_hdr(udh, sport, dport, udlen);

    struct dns_header *dnh = (struct dns_header *) ((uint8_t *) udh + UDP_HLEN);
    gen_query_dns_hdr(dnh, dns_id, flag1, flag2);

    uint8_t *wire = ((uint8_t *) ipv4_hdr) + IP_HLEN + UDP_HLEN + DNS_HLEN;
    rte_memcpy(wire, dk->data, dk->len - QUERY_TYPE_LEN - SERVER_TYPE_LEN);
    wire += dk->len - QUERY_TYPE_LEN - SERVER_TYPE_LEN;

    uint8_t *w = ((uint8_t *) dk->data)
            + dk->len- QUERY_TYPE_LEN - SERVER_TYPE_LEN;
    uint16_t qtype = *((uint16_t *) w);
    uint16_t *q = (uint16_t *) wire;
    *q = Lhtons(qtype);
    wire += QUERY_TYPE_LEN;

    uint16_t *class = (uint16_t *) wire;
    *class = Lhtons(1);
    wire += 2;
    *wire_p = wire;

    return 0;
}

static inline void send_dns_query(node * n, struct rte_mbuf *m) {
    m->ol_flags |= PKT_TX_IP_CKSUM;
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = sizeof(struct ipv4_hdr);

    VSTATS(n->forward_rvid, VFWD_REQ);
    //net_pkt_dump(m);
    send_single_frame(m, n->o_port);
}

static const uint8_t edns0_data[] =
//  |-name-|---type---|payload size|----------ttl---------|-rdata len-|
    { 0x00, 0x00, 0x29, 0x05, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //1408
static const uint8_t ecs_data[] =
//  |-name-|---type---|payload size|----------ttl---------|-rdata len-|- opt code-|- opt len -| - family -|-mask-|-scope-|-    src ip         -|
    { 0x00, 0x00, 0x29, 0x05, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x20,  0x00,  0x08, 0x08, 0x08, 0x08}; //1408 32mask
  // { 0x00, 0x00, 0x29, 0x05, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x18,  0x00,  0x08, 0x08, 0x08}; //1408 24mask
static const uint8_t src_data[] =
//  |-name-|---type---|payload size|----------ttl---------|-rdata len-|--opt code-|--opt len--|----num----|----------tag----------|--------serials--------|---------src ip--------|
    { 0x00, 0x00, 0x29, 0x05, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0xbc, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,}; //1408

static inline int forward_send_fwd_query(node * n, uint16_t dns_id) {

    int16_t udlen;
    struct rte_mbuf *m;
    uint8_t *wire;

    // add ECS for default view
    if (/*n->support_ecs && */n->forward_rvid == 0) {
        udlen = UDP_HLEN + DNS_HLEN + n->key->len - SERVER_TYPE_LEN + 2
                + sizeof(ecs_data);

        if (unlikely(
                encapsulate_query_pkt(n->o_port, n->key, n->forward_ip,
                        n->forward_port, dns_id, udlen, 0x01, 0x00, &wire, &m)
                        < 0)) {
            return -1;
        }
        rte_memcpy(wire, ecs_data, sizeof(ecs_data));
        wire += (sizeof(ecs_data) - 4);
        /* FDNS not really support ECS, so we use one ipv4 address in
         * the same view instant to fill into ECS section
         */
        *(uint32_t *) wire = g_recs_views->view_list[n->forward_vid].ecs_ip;
        //wire += 4;
        // add EDNS0 only if select default view
    } else {
        udlen = UDP_HLEN + DNS_HLEN + n->key->len - SERVER_TYPE_LEN + 2
                + sizeof(edns0_data);

        if (unlikely(
                encapsulate_query_pkt(n->o_port, n->key, n->forward_ip,
                        n->forward_port, dns_id, udlen, 0x01, 0x00, &wire, &m)
                        < 0)) {
            return -1;
        }
        rte_memcpy(wire, edns0_data, sizeof(edns0_data));
        //wire += sizeof(edns0_1232);
    }

    //rte_pktmbuf_dump(m,ETH_HLEN + IP_HLEN +udlen);
    send_dns_query(n, m);

    return 0;
}

static inline int
forward_send_src_query(node * n, uint16_t dns_id) {

    int16_t udlen, src_num, i;
    struct rte_mbuf *m;
    uint8_t *wire;
    uint8_t idx;
    struct dnscache_source_info *src_info;

    // add ECS if AUTH support
    if (n->support_ecs) {
        udlen = UDP_HLEN + DNS_HLEN + n->key->len - SERVER_TYPE_LEN + 2
                + sizeof(ecs_data);

        if (unlikely(
                encapsulate_query_pkt(n->o_port, n->key, n->forward_ip,
                        n->forward_port, dns_id, udlen, 0x00, 0x10, &wire, &m)
                        < 0)) {
            return -1;
        }
        rte_memcpy(wire, ecs_data, sizeof(ecs_data));
        wire += (sizeof(ecs_data) - 4);
        /* FDNS not really support ECS, so we use one ipv4 address in
         * the same view instant to fill into ECS section
         */
        *(uint32_t *) wire = g_auth_views->view_list[n->forward_vid].ecs_ip;
        //wire += 4;
        // add EDNS0 OUTBOUND
    } else {
		src_info = n->cnode->src_info;
        if(src_info->src_len > MAX_SOURCE_IN_OPT) {
            src_num = MAX_SOURCE_IN_OPT;
        } else {
            src_num = src_info->src_len;
        }
        uint16_t rd_len = sizeof(edns0_opt_ob_t) + src_num * sizeof(opt_dst_node_t);
        udlen = UDP_HLEN + DNS_HLEN + n->key->len - SERVER_TYPE_LEN + 2
                + sizeof(edns0_data) + rd_len;

        if (unlikely(
                encapsulate_query_pkt(n->o_port, n->key, n->forward_ip,
                        n->forward_port, dns_id, udlen, 0x00, 0x10, &wire, &m)
                        < 0)) {
            return -1;
        }
        rte_memcpy(wire, edns0_data, sizeof(edns0_data));
        edns0_hdr_t *ehdr = (edns0_hdr_t *)wire;
        ehdr->rdata_len =Lhtons(rd_len);
        edns0_opt_ob_t *opt_ob = (edns0_opt_ob_t *)(wire + sizeof(edns0_hdr_t));
        opt_ob->opt_code = EDNS_OPT_OB_BE;
        opt_ob->opt_len = Lhtons(rd_len - 4);
        opt_ob->dst_num = Lhtons(src_num);
        opt_ob->tag = Lhtonl(src_info->zone_id);
        opt_ob->serials = Lhtonl(src_info->serials);
        opt_ob->src_ip = get_port_ip_net(n->o_port);
        opt_dst_node_t *dst_nodes = (opt_dst_node_t *) (opt_ob + 1);
        idx = src_info->src_ptr;

        for(i = 0; i < src_num; i++) {
            dst_nodes[i].dst_ip = Lhtonl(src_info->source[idx].ip_addr);
            dst_nodes[i].dst_port = Lhtons(src_info->source[idx].port);
            idx = (idx + 1) % src_info->src_len;
        }
        src_info->src_ptr = idx;
        //wire += sizeof(edns0_data);
    }

    //rte_pktmbuf_dump(m,ETH_HLEN + IP_HLEN +udlen);
    send_dns_query(n, m);

    return 0;
}

static inline int forward_send_query(node * n, uint16_t dns_id) {
    if (n->srv_type == SRV_TYPE_AUTH) {
        return forward_send_src_query(n, dns_id);
    } else {
        return forward_send_fwd_query(n, dns_id);
    }
}

static inline int select_forward_by_view_id(node * n, uint8_t is_backup)
{
    view *v;
    uint8_t i, idx, begin;
    uint32_t vid;
    struct dnscache_source_info *src_info;
    view_db_t *views = g_recs_views;

    if (n->srv_type == SRV_TYPE_AUTH) {
        views = g_auth_views;
        struct dns_packet packet;
        adns_dname_parse_fast(n->key->data,
                n->key->len - QUERY_TYPE_LEN - SERVER_TYPE_LEN, &packet);
        struct dnscache_node *fnode = dnscache_zone_lookup(g_dnscache_node_tbl,
                &packet, n->key->data);
        if (fnode == NULL) {
            STATS(AUTH_FWD_NO_CONF);
            return -1;
        }
        n->cnode = fnode;
        src_info = fnode->src_info;

        if (src_info->src_ecs) {
            idx = src_info->src_ptr;
            //idx = fnode->src_ptr % fnode->src_len;

            if (likely(src_info->src_state != DOWN)) {
                for (i = 0; i < src_info->src_len; i++) {
                    if (src_info->source[idx].state != DOWN) {
                        break;
                    }
                    idx = (idx + 1) % src_info->src_len;
                }
            }
            n->forward_ip = src_info->source[idx].ip_addr;
            n->forward_port = src_info->source[idx].port;
            src_info->src_ptr = (idx + 1) % src_info->src_len;
            n->support_ecs = src_info->src_ecs;

            return 0;
        }
        // TODO: support authority NS disaster tolerant for auth zone
        is_backup = 0;
    }

	// specified to use backup view which is support ECS, mainly used for disaster
	// tolerant in scenarios where the authority NS is unreachable from current selected view
	if (unlikely(is_backup)) {
		vid = 0;
		/*
		ALOG(SERVER, DEBUG,
				"Lcore %d When origin view %s ,Select default view cause authority NS disaster tolerant!",
				rte_lcore_id(), view_id_to_name(n->forward_vid));
		*/
		if (vid == n->forward_rvid) {
			/*
			ALOG(SERVER, DEBUG,
					"Lcore %d When origin view %s ,Select backup view cause authority NS disaster tolerant!",
					rte_lcore_id(), view_id_to_name(n->forward_vid));
			*/
			views = g_backup_views;
		}
	} else {
		/*
		 if (unlikely(is_all_bad_view(views))) {
		 ALOG(SERVER, INFO,
		 "Lcore %d When origin view %s ,Select view default cause all view down",
		 rte_lcore_id(), view_id_to_name(n->forward_vid));
		 vid = 0;
		 } else {
		 */
		vid = n->forward_vid;
		if (is_bad_view(views, vid)) {
			vid = views->view_list[vid].backup_id;
			/*        ALOG(SERVER, INFO,
			 "Lcore %d When origin view %s ,Select view backup %s", lcore_id,
			 vname, get_view_name(vid));*/
			if (vid != 0 && is_bad_view(views, vid)) {
				vid = 0;
				/*            ALOG(SERVER, INFO,
				 "Lcore %d When origin view %s ,Select view default cause backup down",
				 lcore_id, vname);*/
			}
		}
		//}
	}

    /*find forwarder*/
	v = &views->view_list[vid];
    n->forward_rvid = vid;
    begin = v->next_id;
    idx = begin % v->fnums;
    for (i = 0; i < v->fnums; i++) {
        if (find_bit(v->fbitmap, idx)) {
            break;
        }
        idx = (idx + 1) % v->fnums;
    }
    n->forward_ip = v->fip[idx];
    n->forward_port = v->fport[idx];
    v->next_id = (idx + 1) % v->fnums;

    if (vid == 0 && n->support_ecs) {
        return 0;
    }

    if (n->forward_rvid != n->forward_vid) {
        forwarder *f = get_forwarder(n->forward_ip, n->forward_port);

        for (i = 0; i < f->bkup_count; i++) {
            if (f->bkup_id[i] == n->forward_vid)
                break;
        }
        if (i == f->bkup_count) {
            f->bkup_id[f->bkup_count++] = n->forward_vid;
        }
    }
/*    ALOG(SERVER, INFO, "Lcore %d Select view %s forwarder %d.%d.%d.%d:%d",
         lcore_id, get_view_name(vid), HIP_STR(ip), port);*/

    return 0;
}

static inline void node_prefetch(node * n, uint32_t now)
{
    n->prefetch_try++;
    n->last_prefetch_time = now;
    /*
     char dname[NAME_MAX_LEN + 30];
     get_query_dname(n->key->data, n->key->len, dname);
     ALOG(SERVER, DEBUG, "Lcore %d do prefetch for [%s] in view [%s]",
     rte_lcore_id(), dname, get_view_name(n->forward_vid));
     */
    if (unlikely(select_forward_by_view_id(n, 0) < 0)) {
        return;
    }

    if (unlikely(forward_send_query(n, PREFETCH_DNS_ID) != 0)) {
        set_node_vstate(n, VNODE_PREFETCH);
        STATS(TTL_PREFETCH_SEND_FAIL);
        n->last_prefetch_time = 0;
        return;
    }

    if (n->prefetch_try == 1) {
        STATS(TTL_PREFETCH_NODE);
    }
    STATS(TTL_PREFETCH_SEND);
}

static inline int node_prefetch_try(node *n, uint32_t now)
{
    if (n->last_prefetch_time + 1 < now) {
        node_prefetch(n, now);
        return 1;
    }
    return 0;
}

static inline void forward_send_pkt(node * n)
{
    STATS(FWD_REQ);
    n->try = 0;

    if (unlikely(forward_send_query(n, Lhtons(n->dns_id)) != 0)) {
        free_node(n);
        STATS(FWD_SEND_FAIL);
        return;
    }

    enqueue_timer(n, F_TIMER);
}

/* dec_res: directly response without answer section (SERVFAI, REFUSED...) */
static inline void notify_wait_requests(node * n, int *real, uint16_t dec_res)
{
    int len, ret;
    request *r;
    dval *dv = n->val;
    dkey *dk = n->key;
    struct dns_header *dnh;
    int kni_id = 0;
    uint16_t dns_len;

    if(unlikely(dec_res)) {
    	dns_len = DNS_HLEN + dk->len - SERVER_TYPE_LEN + 2;
    } else {
    	dns_len = dv->len;
    }

    //ALOG(ANSWER,INFO,"Lcore %d : call %s for key %s",rte_lcore_id(),__func__,dk->data);
    while(!list_empty(&n->wait_list)) {
        //ALOG(ANSWER,INFO,"Lcore %d : notify a wait job",rte_lcore_id());
        r = list_first_entry(&n->wait_list, request, list);
        list_del(&r->list);
        n->wait_size--;
        struct rte_mbuf *m = NULL;
        //RTE_LOG(INFO,LDNS,"lcore %d do notify wait request %s\n",rte_lcore_id(),n->key);
        if (r->is_from_kni) {
            kni_id = kni_lcore_port_map[r->i_port];
            m = rte_pktmbuf_alloc(app.lcore_params[kni_id].pool);
        } else {
            m = rte_pktmbuf_alloc(app.lcore_params[rte_lcore_id()].pool);
        }

        if (m == NULL) {
            //ALOG(SERVER, ERROR, "rte_pktmbuf_alloc fail in %s", __func__);
            STATS(PKT_MP_GET_FAIL);
            put_request(r);
            STATS(DNS_DROP);
            continue;
        }

        struct ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
        *eth_hdr = r->ether;
        l2_output(eth_hdr);

        union common_ip_head *ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
        union common_l4_head *l4_head;
        if (r->is_ipv6) {
            ip_head->ipv6_hdr = r->ip_head.ipv6_hdr;
            l3_output_ipv6(&(ip_head->ipv6_hdr));
            ip_head->ipv6_hdr.proto = IPPROTO_UDP;
            l4_head = (union common_l4_head *)((uint8_t*)ip_head + sizeof(struct ipv6_hdr));
        } else {
            ip_head->ipv4_hdr = r->ip_head.ipv4_hdr;
            l3_output(&(ip_head->ipv4_hdr));
            l4_head = (union common_l4_head *)dns_udp_hdr(m, &(ip_head->ipv4_hdr));
        }

        if(r->is_tcp) {
            l4_head->tcp_hdr = r->l4_head.tcp_hdr;
            l4_tcp_output(&(l4_head->tcp_hdr));
            uint32_t seq = adns_ntohl(l4_head->tcp_hdr.sent_seq);
            uint8_t *tcpopt = (uint8_t *) l4_head + sizeof(struct tcp_hdr);
            // optlen: TCP_OPT_MSS_LEN + TCP_OPT_WSCALE_LEN + PADDING
            uint8_t all_tlen = sizeof(struct tcp_hdr) + 8;
            int i;

            l4_head->tcp_hdr.tcp_flags = TCP_PSH_FLAG | TCP_ACK_FLAG;
            l4_head->tcp_hdr.sent_seq = l4_head->tcp_hdr.recv_ack;
            l4_head->tcp_hdr.recv_ack = adns_htonl(seq + r->l4_len + 2);
            l4_head->tcp_hdr.data_off = (all_tlen) << 2;
            l4_head->tcp_hdr.rx_win = adns_htons(TCP_DEFAULT_MSS);
            l4_head->tcp_hdr.tcp_urp = 0;
            i = 0;
            // MSS
            tcpopt[i++] = TCP_OPT_MSS;
            tcpopt[i++] = TCP_OPT_MSS_LEN;
            tcpopt[i++] = TCP_DEFAULT_MSS >> 8;
            tcpopt[i++] = TCP_DEFAULT_MSS % 256;
            //WSCALE
            tcpopt[i++] = TCP_OPT_NOP;
            tcpopt[i++] = TCP_OPT_WSCALE;
            tcpopt[i++] = TCP_OPT_WSCALE_LEN;
            tcpopt[i++] = 0;
            *(uint16_t *)((uint8_t *)l4_head + all_tlen) = adns_htons(dns_len);
            all_tlen += 2;
            if (r->is_ipv6) {
                len = all_tlen + dns_len;
                ip_head->ipv6_hdr.payload_len = adns_htons(len);
                len += sizeof(struct ipv6_hdr);
            } else {
                len = ((ip_head->ipv4_hdr.version_ihl & 0xf) << 2) + all_tlen
                        + dns_len;
                ip_head->ipv4_hdr.total_length = adns_htons(len);
            }
            dnh = (struct dns_header *) ((uint8_t *)l4_head + all_tlen);
        } else {
            l4_head->udp_hdr = r->l4_head.udp_hdr;
            l4_udp_output(&(l4_head->udp_hdr));
            int old_dns_len = Lntohs(l4_head->udp_hdr.dgram_len) - UDP_HLEN;
            int now_dns_len = dns_len;
            int append = now_dns_len - old_dns_len;

            if (r->is_ipv6) {
                len = adns_ntohs(ip_head->ipv6_hdr.payload_len) + append;
                ip_head->ipv6_hdr.payload_len = adns_htons(len);
                len += sizeof(struct ipv6_hdr);
            } else {
                len = adns_ntohs(ip_head->ipv4_hdr.total_length) + append;
                ip_head->ipv4_hdr.total_length = adns_htons(len);
            }
            dnh = (struct dns_header *)((uint8_t *)l4_head + UDP_HLEN);
            l4_head->udp_hdr.dgram_len = Lhtons(dns_len + UDP_HLEN);
            l4_head->udp_hdr.dgram_cksum = 0;
        }
		int ulen = ETH_HLEN + len;

		if (unlikely(rte_pktmbuf_append(m, ulen) == NULL)) {
			//ALOG(SERVER, ERROR, "rte_pktmbuf_append fail in %s", __func__);
			STATS(MBUF_APPEND_DROP);
			put_request(r);
			rte_pktmbuf_free(m);
			STATS(RESP_DROP);
			continue;
		}

		if (unlikely(dec_res)) {
			ldns_wire_set_rcode((uint8_t*) dnh, dec_res);
			ldns_wire_set_ra((uint8_t*) dnh);
			ldns_wire_clear_aa((uint8_t*) dnh);
			ldns_wire_clear_ad((uint8_t*) dnh);
			ldns_wire_set_qr((uint8_t*) dnh);
			ldns_wire_clear_tc((uint8_t*) dnh);
			ldns_wire_clear_z((uint8_t*) dnh);
			dnh->qdcount = Lhtons(1);
			dnh->ancount = 0;
			dnh->nscount = 0;
			dnh->arcount = 0;
			uint8_t *wire = (uint8_t*) dnh + DNS_HLEN + r->ori_name_size;
			uint8_t *w = ((uint8_t*) dk->data) + r->ori_name_size;
			uint16_t qtype = *((uint16_t*) w);
			uint16_t *q = (uint16_t*) wire;
			*q = Lhtons(qtype);
			wire += QUERY_TYPE_LEN;
			uint16_t *class = (uint16_t*) wire;
			*class = Lhtons(1);
			if (dec_res == DNS_RCODE_SERVFAIL) {
				STATS(ANSWER_SERVFAIL);
			}
		} else {
			rte_memcpy(dnh, dv->data, dv->len);
			fix_ttl(dnh, n);
		}
		dnh->id = Lhtons(r->id);
		fix_flag(dnh, r->flags1, r->flags2);
		fix_qname(dnh, r->ori_name, r->ori_name_size);

        if (r->has_ecs) {
            if (unlikely(add_edns_client_subnet(m, ip_head, l4_head, dns_len, dnh,
                    &(r->real_ip), r->is_ipv6, r->is_tcp, &r->ecs,
                    r->answer_max_size) < 0)) {
/*                ALOG(ANSWER, ERROR, "Add edns client subnet Fail in %s",
                     __func__);*/
                STATS(ADD_EDNS_DROP);
                rte_pktmbuf_free(m);
                STATS(RESP_DROP);
                continue;
            }
        }
        if (r->is_ipv6) {
            ip_head->ipv6_hdr.hop_limits = IPV6_TTL;

            if (r->is_tcp) {
                m->l4_len = sizeof(struct tcp_hdr);
                m->ol_flags = PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;
                l4_head->tcp_hdr.cksum =
                        rte_ipv6_phdr_cksum((void *)ip_head, m->ol_flags);
            } else {
                m->l4_len = sizeof(struct udp_hdr);
                m->ol_flags = PKT_TX_IPV6 | PKT_TX_UDP_CKSUM;
                l4_head->udp_hdr.dgram_cksum =
                        rte_ipv6_phdr_cksum((void *)ip_head, m->ol_flags);
            }
            m->l2_len = sizeof(struct ether_hdr);
            m->l3_len = sizeof(struct ipv6_hdr);
        } else {
            ip_head->ipv4_hdr.time_to_live = IPV4_TTL;
            ip_head->ipv4_hdr.hdr_checksum = 0;

            if (r->is_tcp) {
                m->l4_len = sizeof(struct tcp_hdr);
                m->ol_flags = PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
                l4_head->tcp_hdr.cksum =
                        rte_ipv4_phdr_cksum((void *) ip_head, m->ol_flags);
            } else {
                m->ol_flags = PKT_TX_IPV4;
            }
            m->ol_flags |= PKT_TX_IP_CKSUM;
            m->l2_len = sizeof(struct ether_hdr);
            m->l3_len = sizeof(struct ipv4_hdr);
        }

        if (unlikely(r->is_from_kni)) {
            STATS(KNI_DNS_OUT);
            struct lcore_msg_info* entry;
            entry = get_kni_msg_info(m, eth_hdr, ip_head, l4_head, 0, r->i_port);
            if (entry == NULL) {
                //ALOG(SERVER, ERROR, "rte_pktmbuf_append fail in %s", __func__);
                put_request(r);
                rte_pktmbuf_free(m);
                STATS(RESP_DROP);
                continue;
            }
            ret = lcore_msg_send(entry, kni_id);
            if (ret < 0) {
                //ALOG(SERVER, ERROR, "rte_pktmbuf_append fail in %s", __func__);
                put_request(r);
                rte_pktmbuf_free(m);
                STATS(RESP_DROP);
                continue;
            }
/*                char dname[NAME_MAX_LEN + 30];
                get_query_dname(n->key->buf.base,n->key->buf.len,dname);
                ALOG(ANSWER, INFO,
                        "LCORE %d : AnswerQuery [%s:%s] to KNI %d",
                        rte_lcore_id(), get_view_name(n->forward_vid), dname, kni_id);*/
            log_answer_info(&r->ip_head, &r->l4_head, r->is_tcp, r->is_from_kni,
                    r->is_ipv6, n->forward_vid, dnh, r->has_ecs, n->srv_type,
                    n->cnode == NULL ? ADNS_DNAME_MAXLEN : r->ori_name_size - n->cnode->dlen);
            put_request(r);
            continue;
        }
        STATS(DNS_OUT);
        /*
        if (r->is_tcp) {
            STATS(TCP_DNS_OUT);
        }
        */
        send_single_frame(m, r->i_port);

        STATS(FWD_LOGIC_RESP);
        if (*real == 0) {
            *real = 1;
            STATS(FWD_REAL_RESP);
        }
/*            char dname[NAME_MAX_LEN + 30];
            get_query_dname(n->key->buf.base,n->key->buf.len,dname);
            ALOG(ANSWER, INFO,
                    "LCORE %d : AnswerQuery [%s:%s] from L2 DNS(%d.%d.%d.%d:%d), is_tcp:%d, is_tc:%d",
                    rte_lcore_id(), get_view_name(n->forward_vid), dname,
                    HIP_STR(f->ip), f->port, r->is_tcp,
                    ldns_wire_get_tc((uint8_t * )dnh));*/
        log_answer_info(&r->ip_head, &r->l4_head, r->is_tcp, r->is_from_kni,
                r->is_ipv6, n->forward_vid, dnh, r->has_ecs, n->srv_type,
                n->cnode == NULL ? ADNS_DNAME_MAXLEN : r->ori_name_size - n->cnode->dlen);

        put_request(r);
    }
}

static inline void forward_timeout(node * n)
{
	int real = 1;

    n->try++;
    forward_port_down(n->o_port);
    if (n->try > g_forwarder_retry) {
        /*
         char dname[NAME_MAX_LEN + 30];
         get_query_dname(n->key->data, n->key->len, dname);
         ALOG(ANSWER,DEBUG,"Lcore %d : [TimeOut] Qname(%s), View(%s),forwarder(%d.%d.%d.%d:%d)",rte_lcore_id(),dname,get_view_name(n->forward_rvid),HIP_STR(n->forward_ip),n->forward_port);
         */
        set_forwarder_state(n->forward_ip, n->forward_port, DOWN);
        // send server fail for timeout to client
        notify_wait_requests(n, &real, DNS_RCODE_SERVFAIL);
        free_node(n);
        STATS(FWD_TIMEOUT);
        VSTATS(n->forward_rvid, VFWD_TIMEOUT);

        return;
    }

	if (unlikely(select_forward_by_view_id(n, 1) < 0)) {
		return;
	}

    if (unlikely(forward_send_query(n, Lhtons(n->dns_id)) != 0)) {
        free_node(n);
        STATS(FWD_SEND_FAIL);
        return;
    }

    enqueue_timer(n, F_TIMER);
}

typedef struct answer_info{
    uint8_t an_name[ANSWER_MAX][NAME_MAX_LEN + 30];
    uint16_t an_name_len[ANSWER_MAX];
    uint16_t ttl_pos[ANSWER_MAX];
    uint8_t ttl_pos_size;
    uint32_t min_ttl;
} answer_info_t;

static inline int parse_sec_in_answer(struct dns_packet *pkt, uint16_t rr_cnt,
        answer_info_t *an_info, const char *sec_name) {
    int i, ret;
    uint16_t type, len = 0;
    //uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;

    const uint8_t * end_pos = pkt->wire + pkt->size;
    uint8_t * dnh_pos = pkt->wire;
    uint8_t *an_pos = pkt->wire + pkt->parsed;

    for (i = 0; i < rr_cnt; i++) {
        ret = get_an_name(an_pos, 0, 0, end_pos, dnh_pos, pkt->dname,
                an_info->an_name[an_info->ttl_pos_size], sec_name, &len);
        if (unlikely(ret < 0)) {
            return -1;
        }
        an_info->an_name_len[an_info->ttl_pos_size] = ret;
        an_pos += len;
        if (unlikely(an_pos + 10 > end_pos)) {
            STATS(UDP_PKT_LEN_ERR);
/*            ALOG(SERVER, WARN,
                    "Current offset (%d) exceed the total packet length (%d) at node [%s] In %s",
                    (an_pos + 10 - dnh_pos), (end_pos - dnh_pos), pkt->dname, sec_name);*/
            return -1;
        }
        type = adns_ntohs(*(uint16_t *) an_pos);
        //assert(an_info->an_name_len[an_info->ttl_pos_size] + 2 <= NAME_MAX_LEN+2);
        *(uint16_t *) (an_info->an_name[an_info->ttl_pos_size]
                + an_info->an_name_len[an_info->ttl_pos_size]) = type;
        an_info->an_name_len[an_info->ttl_pos_size] += 2;

		*(uint8_t *) (an_info->an_name[an_info->ttl_pos_size]
				+ an_info->an_name_len[an_info->ttl_pos_size]) = pkt->srv_type;
		an_info->an_name_len[an_info->ttl_pos_size] += 1;
/*
            char tname[NAME_MAX_LEN + 30];
            get_query_dname(an_info->an_name[an_info->ttl_pos_size],
                    an_info->an_name_len[an_info->ttl_pos_size], tname);
            ALOG(SERVER, DEBUG,
                    "Get associate name [%s] in key [%s] from response [answer section]",
                    tname, pkt->dname);
        */
        an_pos += 2;
        //class = adns_ntohs(*(uint16_t*)pos);
        an_pos += 2;
        an_info->ttl_pos[an_info->ttl_pos_size++] = an_pos - dnh_pos;
        //assert(an_info->ttl_pos[an_info->ttl_pos_size] < g_obj_max_lens[OBJ_MAX_LEN-1]);
        ttl = adns_ntohl(*(uint32_t*)an_pos);
        if (ttl < an_info->min_ttl)
            an_info->min_ttl = ttl;
        an_pos += 4;
        rdlength = adns_ntohs(*(uint16_t *)an_pos);
        an_pos += 2;
        if (unlikely(an_pos + rdlength > end_pos)) {
            STATS(UDP_PKT_LEN_ERR);
/*            ALOG(SERVER, WARN,
                    "Current offset (%d) exceed the total packet length (%d) at node [%s] In %s",
                    (an_pos + rdlength - dnh_pos), (end_pos - dnh_pos), pkt->dname,
                    sec_name);*/
            return -1;
        }
        an_pos += rdlength;

        if (unlikely(an_info->ttl_pos_size >= ANSWER_MAX)) {
            STATS(UDP_PKT_LEN_ERR);
/*            ALOG(SERVER, ERROR,
                    "The total records number(%d) in answer packet exceed the max number(%d)",
                    an_info->ttl_pos_size, ANSWER_MAX);*/
            return -1;
        }
    }

    pkt->parsed = an_pos - pkt->wire;
    return 0;
}

static inline void
parse_answer_pkt(struct dns_packet *pkt,
        answer_info_t *an_info, struct dnscache_source_info *src_info) {
    uint32_t c_min_ttl = MIN_TTL;
    uint32_t c_max_ttl = MAX_TTL;
    uint32_t c_nx_max_ttl = NXDOMAIN_MAX_TTL;

    if (src_info != NULL) {
        c_min_ttl = src_info->cache_ttl_min;
        c_max_ttl = src_info->cache_ttl_max;
        c_nx_max_ttl = src_info->cache_ttl_max;
    }
    an_info->ttl_pos_size = 0;

    // clear the tc flag, since PDNS does not really support TCP
    //ldns_wire_clear_tc(pkt->wire);
    // clear the ar count, since PDNS should not cache any additional RR
    //ldns_wire_set_arcount(pkt->wire, 0);

    if (unlikely(pkt->header.ancount == 0 && pkt->header.nscount == 0)) {
        an_info->min_ttl = c_min_ttl;
        return;
    }

    if (unlikely(pkt->header.flags2 & LDNS_WIRE_RCODE_MASK) == NXDOMAIN) {
        an_info->min_ttl = c_nx_max_ttl;
    } else {
        an_info->min_ttl = c_max_ttl;
    }

    if (unlikely(
            parse_sec_in_answer(pkt, pkt->header.ancount, an_info, "Answer")
                    < 0)) {
        STATS(DNS_PARSE_DROP);
        an_info->min_ttl = 0;
        return;
    }

    if (unlikely(
            parse_sec_in_answer(pkt, pkt->header.nscount, an_info, "Authority")
                    < 0)) {
        STATS(DNS_PARSE_DROP);
        an_info->min_ttl = 0;
        return;
    }

    if (an_info->min_ttl < c_min_ttl) {
        an_info->min_ttl = c_min_ttl;
    }
}

static inline int
match_protected_key(struct dns_packet *pkt, int view_id)
{
    int lcore_id = rte_lcore_id();
    if (lcore_regex[lcore_id].work != REGEX_ON)
        return 0;

    if (lcore_regex[lcore_id].view_id != -1
        && lcore_regex[lcore_id].view_id != view_id)
        return 0;
    char *dname = pkt->dname;

    if (regexec(&lcore_regex[lcore_id].oRegex, dname, 0, NULL, 0) == 0)
        return 1;
    return 0;
}

static inline int
good_packet(struct dns_packet *pkt)
{
    uint8_t status = (pkt->header.flags2 & LDNS_WIRE_RCODE_MASK);
    if (status == NOERROR && pkt->header.ancount > 0)
        return 1;
    return 0;
}

static inline void
notify_view(uint8_t * key, uint16_t klen, uint32_t view_id,
        uint32_t hash, struct dns_packet *pkt, answer_info_t *an_info)
{
    node *n;
    dval *val;
    int real = 0;
    uint8_t i, link_idx;
    int ret;
    struct list_head *head;
    int prefetch = 0;

    if (Lhtons(pkt->header.id) == PREFETCH_DNS_ID) {
        STATS(TTL_PREFETCH_RECV);
        prefetch = 1;
    }

    if (match_protected_key(pkt, view_id)) {
/*        ALOG(SERVER, WARN,
             "Lcore %d : Recv response for %s ,view[%s],drop[protected mode]",
             rte_lcore_id(), pkt->dname, get_view_name(view_id));*/
        STATS(RESP_DROP);
        return;
    }
    //RTE_LOG(INFO,LDNS,"notify view %d , node key %s\n",view_id,key);

    /* parse additional */
    ret = adns_parse_additional(pkt, 0);
    if (unlikely(ret < 0)) {
        STATS(RESP_FAIL_PARSE_ECS);
    }

    // read the view id from ECS for default view
    if (view_id == 0 && pkt->has_ecs) {
        if (likely(pkt->opt_rr.opt_ecs.family == ECS_FAMILY_IPV4)) {
            view_id = ip_bitmap_get(Lntohl(pkt->opt_rr.opt_ecs.addr.v4), 0);
        }
    }

    head = &g_node_db[hash].view_hash[view_id];
    list_for_each_entry(n, head, node_list) {
        if (match_node(n, key, klen)) {
            uint8_t status = (pkt->header.flags2 & LDNS_WIRE_RCODE_MASK);
            if (likely((an_info->min_ttl != 0) && (status == NOERROR || status == NXDOMAIN))) {
                //valid cdn response
                set_node_vstate(n, VNODE_TRUST);
            } else {            //not valid cdn response
                if(n->try == 0)
                    break;
                set_node_vstate(n, VNODE_TRUST);
                if (n->val) {
                    STATS(SRVFAIL_NOT_UPD);
                    /*ALOG(SERVER, WARN,
                            "Lcore %d : %s %s Response [%s] ,do not overwrite old value!",
                            rte_lcore_id(), pkt->dname, QT(pkt->qtype),
                            status_str[status]);*/
                    break;
                }
            }

            if (unlikely(an_info->min_ttl == 0)) {
                //rte_hexdump("Response DNS PKT ERROR",pkt->parsed, pkt->wire);
                free_node(n);
                STATS(RESP_DROP);
                return;
            }

            // update view_id 's cache
            //assert(n->val == NULL);
            val = get_dval(pkt->answered, pkt->wire);
            if (unlikely(val == NULL)) {
                STATS(RESP_DROP);
                return;
            }

            if (likely(an_info->ttl_pos_size > 0)) {
                val->ttl_pos_size = an_info->ttl_pos_size;
                rte_memcpy(val->ttl_pos, an_info->ttl_pos,
                        an_info->ttl_pos_size * sizeof(an_info->ttl_pos[0]));

                //if (likely(status != NXDOMAIN)) {
                for (i = 0, link_idx = 1; i < an_info->ttl_pos_size; i++) {
                    uint8_t *ank = an_info->an_name[i];
                    uint16_t anklen = an_info->an_name_len[i];

                    // not link the soa rr in the answer
                    if (unlikely(*(uint16_t * )&ank[anklen - 3] == ADNS_RRTYPE_SOA)) {
                        break;
                    }

                    ret = __node_link_val(ank, anklen, n, link_idx);
                    if (ret == 0) {
                        if (++link_idx >= ALINK_MAX) {
                            if (i + 1 < an_info->ttl_pos_size) {
                                /*if (WOULD_LOG(SERVER, INFO)) {
                                    char src_aname[NAME_MAX_LEN + 30];
                                    char dst_aname[NAME_MAX_LEN + 30];
                                    get_query_aname(ank, anklen, dst_aname);
                                    get_query_aname(n->key->data, n->key->len,
                                            src_aname);
                                    ALOG(SERVER, INFO,
                                            "Lcore %d : [%s] ALINK to %s failed, exceed the max alink num [%d]\n",
                                            rte_lcore_id(), src_aname,
                                            dst_aname, ALINK_MAX);
                                }*/
                                STATS(ALINK_EXCEED_MAX);
                            }
                            break;
                        }
                    } else if (ret == 1) {
                        break;
                    }
                }
                //}
            }

            if (n->val) {
                replace_dval(n, val, pkt->answered);
            } else {
                n->val = val;
#ifdef JMEM_MGR
                mark_used_jmem(VAL, val_len, n);
#endif
            }
            n->last_prefetch_time = NOW;
            n->ttl = n->last_prefetch_time + an_info->min_ttl;
            n->stry = 0;
            //  RTE_LOG(INFO,LDNS,"min_ttl= %u,now = %u,n->ttl = %u\n",min_ttl,NOW,n->ttl);
            stop_all_timer(n);

            if (prefetch) {
                STATS(TTL_PREFETCH_RECV_IMPACT);
                n->prefetch_try = 0;
            }
            notify_wait_requests(n, &real, 0);
        }
    }
}

static inline void
put_adkey(anode *an)
{
    dkey *dk = an->key;
    clear_bit(dk->view_bit_map, g_view_nums);
    dk->ref --;

    if(dk->ref == 0){
        rte_mempool_put(dk->mp, dk);
    }

    an->key = NULL;
}

static inline void alink_unlink(alink *link)
{//断开连接
    anode *an = link->anode_owner;
    if(!an)
        return ;

    //unlink
    list_del(&link->list);

    //change anode
    an->count --;
    if(an->count <= 0){//域名关联到的节点数为0
        put_anode(&an);
    }
    //reset link
    init_alink(link);
}

static inline void anode_unlink_all(node *n)
{
    int i;
    for(i = 0 ; i < n->anode_count; i++){
        alink_unlink(&n->anode_link[i]);
    }
    n->anode_count = 0;
}

static inline void add_anode_to_hash(anode *an,hash_table *tb)
{
    list_add_tail(&an->hash_list,&tb->list); // link to hash table
    tb->size ++;
    an->tb = tb;
}
static inline void del_anode_from_hash(anode *an)
{
    if(an->tb){
        an->tb->size--;
        list_del_init(&an->hash_list);
        an->tb = NULL;
    }
}

static inline int
__node_link_key(uint32_t idx, uint8_t *key, int klen, node *n) {
    hash_table *tb = anode_hash[rte_lcore_id()] + idx;
    anode *an = NULL;
    dkey *dk;

    list_for_each_entry(an,&tb->list,hash_list)
    {
        dk = an->key;
        if (match_akey(dk, key, klen)) {
            if (find_bit(dk->view_bit_map, n->forward_vid) != 0) {
                //ALOG(SERVER,ERROR,"LCORE %d: view %s ,sharekey ptr:");
                //RTE_LOG(ERR, LDNS, "new key len %d", klen);
                rte_hexdump(stdout,
                        "bitmatch,new key,but view exist,new key is:", key,
                        klen);
                //RTE_LOG(ERR, LDNS, "dkey len %d\n", dk->len);
                rte_hexdump(stdout, "bitmatch,new key,but view exist,dkey is:",
                        dk->data, dk->len);
                //assert(0);
				ALOG(SERVER, ERROR,
						"bitmatch, new key(len:%u), but view exist, dkey(len:%u)",
						klen, dk->len);
				STATS(ALINK_NK_VEXIST);
			} else {
				set_bit(dk->view_bit_map, n->forward_vid);
			}
            dk->ref++;
            n->key = dk;

            if (an->count >= ANODE_LIST_MAX) {
                //anode exist,but full
                STATS(ALINK_EXCEED_LIST_MAX);
                /*if (WOULD_LOG(SERVER, INFO)) {
                    char src_aname[NAME_MAX_LEN + 30];
                    char dst_aname[NAME_MAX_LEN + 30];
                    get_query_aname(key, klen, dst_aname);
                    get_query_aname(n->key->data, n->key->len, src_aname);
                    ALOG(SERVER, INFO,
                            "Lcore %d : [%s] ALINK to %s Fail,Full(%d)\n",
                            rte_lcore_id(), src_aname, dst_aname,
                            an->count);
                }*/
                // for link key, must link to anode, so do not return here
                //return 0; //reach limit
            }

            __link_anode(n, an);
            return 0; // same domainName
        }
    }

    dk = dkey_new(klen, key, n->forward_vid, idx);
    if (unlikely(dk == NULL)) {
        /*ALOG(SERVER, WARN, "Fail to do rte_mempool_get from dkey_pool_%d",
         rte_lcore_id());*/
        return -1;
    }
    n->key = dk;

    if (unlikely(get_anode(&an) < 0))
        return 0;
    __link_anode(n, an);
    an->key = n->key;
    n->key->ref++;
    set_bit(n->key->view_bit_map, g_view_nums);
    add_anode_to_hash(an, tb);

    return 0;
}

static inline void node_unlink_ans(node *n, uint8_t index) {
    int i, cnt;

    cnt = n->anode_count;
    for (i = index; i < cnt; i++) {
        alink_unlink(&n->anode_link[i]);
        n->anode_count--;
    }
}

static inline int
__node_link_val(uint8_t *key, int klen, node *n, uint8_t index) {
    int lcore_id = rte_lcore_id();
    uint32_t idx = node_hash_val(key, klen); // - 2);
    hash_table *tb = anode_hash[lcore_id] + idx;
    anode *an;
    alink *al;
    dkey *dk;

    if(index < n->anode_count) {
        dk = n->anode_link[index].anode_owner->key;
        if (idx != dk->idx || klen != dk->len) {
            // diff answer, so unlink all rest
            node_unlink_ans(n, index);
        }
    }

    list_for_each_entry(an,&tb->list,hash_list) {
        if (match_akey(an->key, key, klen)) {
            // index must bigger than 1
            if(an == n->anode_link[index - 1].anode_owner) {
                // all the second level recursive DNS enable minimum response, so if
                // current answer record has the same record with previous one, there
                // will be no new keys at the rest answer records.
                /*if (WOULD_LOG(SERVER, INFO)) {
                    char src_aname[NAME_MAX_LEN + 30];
                    char dst_aname[NAME_MAX_LEN + 30];
                    get_query_aname(key, klen, dst_aname);
                    get_query_aname(n->key->data, n->key->len, src_aname);
                    ALOG(SERVER, INFO,
                            "Lcore %d : [%s] ALINK to %s stop, no more new keys, [anode_count:%d]\n",
                            rte_lcore_id(), src_aname, dst_aname,
                            n->anode_count);
                }*/
                node_unlink_ans(n, index);
                return 1;
            }

            if (index < n->anode_count) {
                if ((an == n->anode_link[index].anode_owner)) {
                    return 0; // have linked
                } else {
                    // diff answer, so unlink all rest
                    node_unlink_ans(n, index);
                }
            }

            if (an->count >= ANODE_LIST_MAX) {
                //anode exist,but full
                STATS(ALINK_EXCEED_LIST_MAX);
                /*if (WOULD_LOG(SERVER, INFO)) {
                    char src_aname[NAME_MAX_LEN + 30];
                    char dst_aname[NAME_MAX_LEN + 30];
                    get_query_aname(key, klen, dst_aname);
                    get_query_aname(n->key->data, n->key->len, src_aname);
                    ALOG(SERVER, INFO,
                            "Lcore %d : [%s] ALINK to %s Fail,Full(%d)\n",
                            rte_lcore_id(), src_aname, dst_aname,
                            ANODE_LIST_MAX);
                }*/
                return -1; //reach limit
            }

            __link_anode(n, an);
            return 0;
        }
    }

    if (unlikely(get_anode(&an) < 0))
        return -1;
    al = __link_anode(n, an);
    an->key = dkey_new(klen, key, g_view_nums, idx);
    if (unlikely(an->key == NULL)) {
        list_del(&al->list);
        an->count--;
        n->anode_count--;
        init_alink(al);
        put_anode(&an);
        return -1;
    }
    add_anode_to_hash(an, tb);

    return 0;
}

void cache_packet(struct dns_packet *pkt, uint32_t ip, uint16_t port)
{
    int i;
    answer_info_t an_info;
    struct dnscache_node *cnode = NULL;
    struct dnscache_source_info *src_info = NULL;
    struct dnscache_source_node *src_node = NULL;

    if (ldns_wire_get_rd((uint8_t *) &pkt->header)) {
        pkt->srv_type = SRV_TYPE_REC;
    } else {
#if 0 // Do not open this check, because the source server maybe not a authority server
        if (!ldns_wire_get_aa((uint8_t *) &pkt->header)) {
            /*ALOG(SERVER, ERROR,
             "Forwarder(%d.%d.%d.%d:%d) response is not authorized for %s!",
             HIP_STR(ip), port, pkt->qname);*/
            STATS(RESP_DROP);
            return;
        }
#endif
        pkt->srv_type = SRV_TYPE_AUTH;
    }
    uint8_t key[QKEY_LEN];
    //memset(qkey, 0, sizeof(qkey));
    uint16_t klen = get_query_key(pkt, key);
    uint32_t idx = node_hash_val(key, klen);

    if (SRV_TYPE_AUTH == pkt->srv_type) {
        cnode = dnscache_zone_lookup(g_dnscache_node_tbl, pkt, pkt->qname);
        if (unlikely(cnode == NULL)) {
            STATS(AUTH_RESP_NO_CONF);
            STATS(RESP_DROP);
            return;
        }
        src_info = cnode->src_info;

        if (src_info->src_ecs) {
            src_node = get_source_node(src_info, ip, port);
            if (src_node == NULL) {
                STATS(AUTH_RESP_NONE_DROP);
                STATS(RESP_DROP);
                return;
            }
            set_src_state_s(src_node, src_info, UP);
            parse_answer_pkt(pkt, &an_info, src_info);
            notify_view(key, klen, 0, idx, pkt, &an_info);
            return;
        }
    }
    forwarder *f = get_forwarder(ip, port);
    /*ALOG(ANSWER, INFO, "get forwarder(%d.%d.%d.%d:%d) in %d %s (%s)",
     HIP_STR(ip), port, rte_lcore_id(), pkt->qname, __func__);*/

    if (f == NULL) {
        STATS(RESP_FWD_NONE_DROP);
        STATS(RESP_DROP);
        /*ALOG(SERVER, WARN, "can not get forwarder(%d.%d.%d.%d:%d) in %s",
         HIP_STR(ip), port, __func__);*/
        return;
    }

    if (f->views->srv_type != SRV_TYPE_AUTH) {
        if (!ldns_wire_get_ra((uint8_t *) &pkt->header)) {
            /*ALOG(SERVER, ERROR,
             "Forwarder(%d.%d.%d.%d:%d) response cannot do rescurse for %s!",
             HIP_STR(ip), port, pkt->qname);*/
            STATS(RESP_DROP);
            return;
        }
    }
    set_forwarder_state_f(f, UP);

    if (Lhtons(pkt->header.id) == HEALTH_CHECK_DNS_ID
            && SRV_TYPE_AUTH != pkt->srv_type) {
        charge_health_check(ip, port, key, klen);
        return;
    }

    if (get_core_by_idx(idx) != rte_lcore_id()) {
        STATS(RESP_WRONG_LCORE_DROP);
        STATS(RESP_DROP);
        return;
    }
    parse_answer_pkt(pkt, &an_info, src_info);

    for (i = 0; i < f->view_count; i++) {
        notify_view(key, klen, f->view_id[i], idx, pkt, &an_info);
    }

    for (i = 0; i < f->bkup_count; i++) {
        notify_view(key, klen, f->bkup_id[i], idx, pkt, &an_info);
    }
}

static inline void flush_wait_list(node * n)
{
    request *r;

    while (!list_empty(&n->wait_list)) {
        r = list_first_entry(&n->wait_list, request, list);
        list_del(&r->list);
        //ALOG(SERVER, INFO, "flush wait list request--");
        put_request(r);
        n->wait_size--;
    }
    assert(n->wait_size == 0);
}

static inline void init_all_timer(node * n)
{
    int j;
    for (j = 0; j < TIMER_TYPE_MAX; j++)
        INIT_LIST_HEAD((&n->timer_list[j]));

}

static inline void
init_alink(alink *link)
{
    INIT_LIST_HEAD(&link->list);
    link->link_id = -1;
    link->anode_owner = NULL;
}

static inline void
init_node_link(node *n)
{
    int j;
    for(j = 0 ; j < ALINK_MAX ; j++){
        init_alink(&n->anode_link[j]);
    }

}

static inline alink *__link_anode(node *n, anode *an) {
    STATS(ALINK_ADD_NODE);

    alink *link = &n->anode_link[n->anode_count];
    link->link_id = n->anode_count;
    link->anode_owner = an;
    list_add_tail(&link->list, &an->node_list);
    an->count++;
    n->anode_count++;

    return link;
}

static inline int get_anode(anode **tan)
{
    //new anode
    //int lcore_id = rte_lcore_id();
    if(rte_mempool_get(anode_pool,(void **)tan) < 0){
        STATS(AN_MP_GET_FAIL);
        //ALOG(SERVER,WARN,"Lcore %d : Cannot rte_mempool_get anode",lcore_id);
        return -1;
    }

    anode *an = *tan;
    INIT_LIST_HEAD(&an->hash_list);
    INIT_LIST_HEAD(&an->node_list);
    an->count = 0;
    an->tb = NULL;
    return 0;
}
static inline void
put_anode(anode **tan)
{
    anode *an = *tan;
    if(an){
        if(an->key)
            put_adkey(an);
        del_anode_from_hash(an);
        rte_mempool_put(anode_pool,an);
    }
    *tan = NULL;
}

static inline void
stop_all_timer(node * n)
{
    int i;
    for (i = 0; i < TIMER_TYPE_MAX; i++)
        stop_timer(n, i);
}

static inline void
stop_timer(node * n, int type)
{

    int lcore_id = rte_lcore_id();
    if (!list_empty(&n->timer_list[type])) {
        assert(timer_mgr[lcore_id][type].nums > 0);
        list_del_init(&n->timer_list[type]);
        timer_mgr[lcore_id][type].nums--;
    }
}

static inline void free_node(node * n)
{
    if (n->lcore_id != rte_lcore_id()) {
        return;
    }
    if (!list_empty(&n->wait_list))
        flush_wait_list(n);

//    if (!list_empty(&n->wait_list_tcp))
//        flush_wait_list_tcp(n);

    n->prefetch_try = 0;
    n->last_prefetch_time = 0;

    if (n->tbl) {
        n->tbl->size--;
        list_del(&n->node_list);
    }

    stop_all_timer(n);

    //assert(list_empty(&n->node_list));
    if (n->key)
        put_dkey(n);

    if (n->val)
        put_dval(n);

    anode_unlink_all(n);

    view_nodes[rte_lcore_id()][n->forward_vid]--;
    DVSTATS(n->forward_vid, n->node_state);
    rte_mempool_put(node_pool, n);
}

static inline int check_fetch_cond(node * n)
{
    /* have been checked outside
    if (n->ttl > NOW)
        return 0;
    */
    if (n->val == NULL)
        return 0;

    if (view_nodes[rte_lcore_id()][n->forward_vid] <=
            g_view_nodes_ttl_threshold) {

        if (n->prefetch_try < MAX_PREFETCH_TRY) {
            struct dns_header *dnh = (struct dns_header *)n->val->data;
            /* only fetch normal status nodes */
            if ((dnh->flags2 & LDNS_WIRE_RCODE_MASK) == NOERROR) {
                /* ALOG(SERVER, INFO,
                 "Lcore %d,Not topn ,but view nodes only %d < %d ,so do ttl timeout fetch",
                 rte_lcore_id(), view_nodes[rte_lcore_id()][n->forward_vid],
                 g_view_nodes_ttl_threshold);*/
                return 1;
            }
        }
    }

    return 0;
}

static inline void ttl_expire_view_check(uint32_t idx, int size)
{
    uint32_t i, view_id;
    uint32_t now = NOW;
    struct list_head *head;
    node *n;
    uint32_t end_idx = idx + size;

    for (i = idx; i < end_idx; i++) {
        //RTE_LOG(INFO,LDNS,"Exp check vid %d hash %d\n",view_id,i);
        if (g_node_db[i].size == 0)
            continue;

        for (view_id = 0; view_id < g_view_nums; view_id++) {
            head = &g_node_db[i].view_hash[view_id];
            for (n = list_entry(head->next, node, node_list);
                    &n->node_list != head;) {
                node *next = list_entry(n->node_list.next, node, node_list);
                if (n->ttl != TTL_INIT) {
                    if (n->ttl <= now) {
                        if (check_fetch_cond(n)) {
                            uint32_t dt = now - n->last_prefetch_time;
                            if (dt >= 2) {
                                node_prefetch(n, now);
                            }
                        } else {
                            if (n->ttl + TTL_PREFETCH <= now) {
                                if (n->last_prefetch_time + TTL_PREFETCH
                                        <= now) {
                                    //ALOG(SERVER,INFO,"node %s free in %s",n->key->buf.base,__func__);
                                    free_node(n);
                                    STATS(TTL_EXPIRE);
                                } else {
                                    /* If just did prefetch, that means this node was queried by users,
                                     * so keep it in cache for another PROTECTED_TTL+TTL_PREFETCH. Mainly used
                                     * for the recursive return server fail or timeout in last prefetch.
                                     */
                                    n->ttl = now + PROTECTED_TTL;
                                    n->prefetch_try = 0;
                                    n->stry = 0;
                                }
                            }
                        }
                    }
                    else {
                        //data ok
                        if (servFail_node(n))
                            servFail_node_try_fix(n);
                    }
                }
                n = next;
            }
        }
    }
}

#ifdef JMEM_MGR
static inline int can_free_node(node * n)
{
    if (n->ttl == TTL_INIT)
        return 0;
//  if(is_topn(n))
//      return 0;

    return 1;

}

static inline char *get_jmem_type_str(jmem_type type)
{
    if (type == KEY)
        return "KEY";
    if (type == VAL)
        return "VAL";
    return "Unknown";
}

static void jmem_try_free(int len, jmem_type type, int size)
{
    int i = 0;
    int lcore_id = rte_lcore_id();
    int pos = find_jmem_pos(len);
    if (pos < 0)
        return;
    assert(type == KEY || type == VAL);
    node *n = NULL;
    struct list_head *jhead = &jmem_mgr[lcore_id][type][pos].list;
    for (i = 0; i < size; i++) {
        if (jmem_mgr[lcore_id][type][pos].iter == jhead) {
/*            ALOG(SERVER, ERROR, "No mem for %s size %d(%d) can jfree in %s",
                 get_jmem_type_str(type), len, pos, __func__);*/
            return;
        }

        if (type == KEY)
            n = list_entry((jmem_mgr[lcore_id][type][pos].iter), node,
                           jkey_list);
        else
            n = list_entry((jmem_mgr[lcore_id][type][pos].iter), node,
                           jval_list);
        if (can_free_node(n)) {
            jmem_mgr[lcore_id][type][pos].iter =
                jmem_mgr[lcore_id][type][pos].iter->next;
            //ALOG(SERVER, WARN, "Lcore %d free node in %s", lcore_id, __func__);
            free_node(n);
        }
    }
}

static inline void unmark_used_jmem(jmem_type type, int size, node * n)
{
    struct list_head *jlist = NULL;
    int lcore_id = rte_lcore_id();
    if (type == KEY)
        jlist = &n->jkey_list;
    else {
        assert(type == VAL);
        jlist = &n->jval_list;
    }
    int pos = find_jmem_pos(size);
    assert(pos >= 0);
    if (jmem_mgr[lcore_id][type][pos].iter == jlist)
        jmem_mgr[lcore_id][type][pos].iter = jlist->next;
    list_del(jlist);

}

static inline void mark_used_jmem(jmem_type type, int size, node * n)
{
    int lcore_id = rte_lcore_id();
    int pos = find_jmem_pos(size);
    assert(pos >= 0);
    assert(type >= 0 && type < JMEM_MAX_TYPE);
    struct list_head *jlist = NULL;
    struct list_head *jhead = &jmem_mgr[lcore_id][type][pos].list;
    if (type == KEY)
        jlist = &n->jkey_list;
    else if (type == VAL)
        jlist = &n->jval_list;
    else {
        RTE_LOG(ERR, LDNS, "unknow jmem_type %d in %s", type, __func__);
        assert(0);
    }
    list_add_tail(jlist, jhead);
    if (jmem_mgr[lcore_id][type][pos].iter == jhead)
        jmem_mgr[lcore_id][type][pos].iter = jlist;
}
#endif

void del_key(const uint8_t *key,int klen)
{
    int lcore_id = rte_lcore_id();
    uint32_t idx = node_hash_val(key,klen);// - 2);
    hash_table *tb = anode_hash[lcore_id] + idx;
    anode *an = NULL;
    struct list_head *head = &tb->list;
    for(an = list_entry(head->next,anode,hash_list); &an->hash_list != head ;){
        anode *next = list_entry(an->hash_list.next,anode,hash_list);
        if(match_akey(an->key,key,klen)){
            __task_work(&an->node_list);
            return;
        }
        an = next;
    }
}

static inline int isMatchRegex(const char *key, const regex_t * oRegex, int regCount)
{
    int i;
    for (i = 0; i < regCount; i++) {
        if (regexec(&oRegex[i], key, 0, NULL, 0) == 0) {
            printf("key[%s] Match\n", key);
            return 1;
        }
    }
    return 0;
}

void build_protect_regex(char *data, int len)
{
    int lcore_id = rte_lcore_id();

    char *p = strstr(data, ":");
    if (p == NULL || p - data < 1) {
        ALOG(SERVER, ERROR, "Protectkeys,  No view name arg");
        return;
    }

    if (p[1] == '\0') {
        ALOG(SERVER, ERROR, "Protectkeys, No keys arg ,str[%s]", data);
        return;
    }

    char vname[VIEW_NAME_MAX];
    if (p - data >= VIEW_NAME_MAX) {
        ALOG(SERVER, ERROR, "Protectkeys, view name too long > %d",
             VIEW_NAME_MAX);
        return;
    }

    strncpy(vname, data, p - data);
    vname[p - data] = '\0';

    int view_id = 0;
    if (strcmp(vname, "*") == 0)
        view_id = -1;
    else {
        view_id = view_name_to_id(vname);
        if (unlikely(view_id < 0)) {
            ALOG(SERVER, ERROR, "view [%s] not exist", vname);
            return;
        }
    }

    lcore_regex[lcore_id].work = REGEX_OFF;
    lcore_regex[lcore_id].view_id = view_id;

    p++;
    int errCode =
        regcomp(&lcore_regex[lcore_id].oRegex, p, REG_ICASE | REG_EXTENDED);
    if (errCode) {
        char errMsg[1024];
        regerror(errCode, &lcore_regex[lcore_id].oRegex, errMsg,
                 sizeof(errMsg));
        ALOG(SERVER, ERROR, "Cannot regcomp[%s],errMsg[%s]\n", p, errMsg);
        return;
    }
    lcore_regex[lcore_id].work = REGEX_ON;
    ALOG(SERVER, WARN, "Lcore %d Protectkeys begin, keys[%s] in view [%s]",
         lcore_id, p, vname);
}

void clean_protect_regex()
{
    int lcore_id = rte_lcore_id();
    lcore_regex[lcore_id].work = REGEX_OFF;
    lcore_regex[lcore_id].view_id = -1;
    ALOG(SERVER, WARN, "Lcore %d stop keys protection", lcore_id);
}

void del_reg_keys(char *data, int len)
{
    char *p = strstr(data, ":");
    if (p == NULL || p - data < 1) {
        ALOG(SERVER, ERROR, "Delkeys, delreg No view name arg");
        return;
    }

    char vname[VIEW_NAME_MAX];
    if (p - data >= VIEW_NAME_MAX) {
        ALOG(SERVER, ERROR, "Delkeys, delreg view name too long > %d",
             VIEW_NAME_MAX);
        return;
    }

    strncpy(vname, data, p - data);
    vname[p - data] = '\0';

    int view_id = 0;
    if (strcmp(vname, "*") == 0)
        view_id = -1;
    else {
        view_id = view_name_to_id(vname);
        if (unlikely(view_id < 0)) {
            ALOG(SERVER, ERROR, "view [%s] not exist", vname);
            return;
        }
    }
    __del_reg_str_keys(view_id, p + 1);
}

static inline void __del_reg_str_keys(int view_id, char *regStr)
{
    int regCount;
    char **regArray = str_split(regStr, ';', &regCount);
    __del_reg_keys(view_id, regArray, regCount);
    str_split_free(regArray);
}

static inline void __del_reg_keys(int view_id, char **regStr, int regCount)
{

    int i;
    regex_t reg[regCount];
    //regex_t ** reg = malloc(count * sizeof(regex_t *));
    char errMsg[1024];
    for (i = 0; i < regCount; i++) {
        //reg[i] = malloc(sizeof(regex_t));
        int errCode = regcomp(&reg[i], regStr[i], 0);
        if (errCode) {
            regerror(errCode, &reg[i], errMsg, sizeof(errMsg));
            RTE_LOG(ERR, LDNS, "Cannot regcomp[%s],errMsg[%s]\n", regStr[i],
                    errMsg);
            return;
        }
    }
    if (view_id != -1)
        __del_view_key(view_id, reg, regCount);
    else {
        for (i = 0; i < g_view_nums; i++) {
            __del_view_key(i, reg, regCount);
        }
    }
}

static inline void __del_view_key(int vid, regex_t * reg, int regCount)
{
    int j;
    node *n, *next;
    char dname[NAME_MAX_LEN + 30];
    int lcore_id = rte_lcore_id();
    uint32_t stime = NOW;
    printf("LCORE %d __ENTER del_view_key __\n", lcore_id);
    for (j = 0; j < g_view_hash_table_size; j++) {
        if (g_node_db[j].size == 0)
            continue;
        struct list_head *head = &g_node_db[j].view_hash[vid];

        for (n = list_entry(head->next, node, node_list);
             &n->node_list != head;) {
            next = list_entry(n->node_list.next, node, node_list);
            get_query_dname(n->key->data, n->key->len, dname);
            if (isMatchRegex(dname, reg, regCount)) {
                free_node(n);
            }
            n = next;
        }
    }
    printf("LCORE %d __OUT del_view_key __,cost %lu s\n", lcore_id, NOW - stime);
}

void del_all_key()
{

    ALOG(SERVER, WARN, "Del all key begin");
    int i, j;
    uint32_t lcore = rte_lcore_id();

    for (i = app.lcore_params[lcore].io.start_idx;
            i < app.lcore_params[lcore].io.end_idx; i++) {
        if (g_node_db[i].size == 0)
            continue;

        for (j = 0; j < g_view_nums; j++) {
            struct list_head *head = &g_node_db[i].view_hash[j];
            node *n;
            while (!list_empty(head)) {
                n = list_first_entry(head, node, node_list);
                free_node(n);
            }
        }
        assert(g_node_db[i].size == 0);
        ALOG(SERVER, WARN, "View %s done del all key", view_id_to_name(i));
    }
}

/*from hash_idx to hash_idx + size bucket check*/
void ttl_expire_check(int size) {
    uint32_t idx = RTE_PER_LCORE(ttl_expire_hash_idx);
    int lcore = rte_lcore_id();

    if (unlikely(idx + size >= app.lcore_params[lcore].io.end_idx)) {
        ttl_expire_view_check(idx, app.lcore_params[lcore].io.end_idx - idx);
        RTE_PER_LCORE(ttl_expire_hash_idx) =
                app.lcore_params[lcore].io.start_idx;
    } else {
        ttl_expire_view_check(idx, size);
        RTE_PER_LCORE(ttl_expire_hash_idx) = idx + size;
    }
}

void node_timer_manage(uint64_t timeout, int batch)
{

    int i;
    for (i = 0; i < batch; i++) {
        node *n = dequeue_timer(timeout, F_TIMER);
        if (n == NULL)
            break;
        forward_timeout(n);
    }
}

static inline void enqueue_timer(node * n, int type)
{

    int lcore_id = rte_lcore_id();
    assert(list_empty(&n->timer_list[type]));
    n->ctime = NOW64;
    list_add_tail(&n->timer_list[type], &timer_mgr[lcore_id][type].list);
    timer_mgr[lcore_id][type].nums++;
}

static inline node *dequeue_timer(uint64_t timeout, int type)
{

    node *n = NULL;
    node *tmp;
    int lcore_id = rte_lcore_id();
    uint64_t now = NOW64;
    if (!list_empty(&timer_mgr[lcore_id][type].list)) {
        assert(timer_mgr[lcore_id][type].nums > 0);
        tmp =
            list_first_entry(&timer_mgr[lcore_id][type].list, node,
                             timer_list[type]);
        if (tmp->ctime + timeout < now) {
            //ALOG(QUERY,INFO,"ctime %ld,timeout %ld,now %ld timeout",tmp->ctime,timeout,now);
            list_del(&tmp->timer_list[type]);
            INIT_LIST_HEAD((&tmp->timer_list[type]));
            timer_mgr[lcore_id][type].nums--;
            n = tmp;
        }
    } else {
        assert(timer_mgr[lcore_id][type].nums == 0);
    }
    return n;
}

static inline void notify_prefetching(int new_core_id, node *n, struct list_head *head) {
    struct lcore_msg_prefetch *p = NULL;
    struct lcore_msg_info *msg = lcore_msg_alloc(MSG_PREFETCH_NODE);
    if (msg != NULL) {
        p = &(msg->pnode);
        p->node = n;
        p->tb_head = head;
        lcore_msg_send(msg, new_core_id);
    }
}

int query_find_diff_core(uint8_t * qkey, int klen, uint32_t idx, node ** tfind,
        uint32_t view_id, int new_core_id, uint8_t support_ecs,
        view_db_t *views) {
    int answer = 0;
    struct list_head *head;
    node *n = NULL, *find = NULL;
    view *v;
    uint32_t now = NOW;
    int i;

    for(i = 0; i < 3; i++) {
        /* now view ,backup view */
        head = &g_node_db[idx].view_hash[view_id];
        for (n = list_entry(head->next, node, node_list); &n->node_list != head;
                n = list_entry(n->node_list.next, node, node_list)) {
            if (match_node(n, qkey, klen)) {
                if (n->ttl > now) {
                    find = n;
                    if (n->val == NULL) {
                        return 2;
                    }
                    if (i) {
                        VSTATS(view_id, VBOUT_REQ);
                        VSTATS(n->forward_vid, VBIN_REQ);
                    }
                    if ((n->prefetch_try < MAX_PREFETCH_TRY) &&
                            (n->ttl - now) < (MIN_TTL / 6)) {
                        notify_prefetching(new_core_id, n, head);
                    }
                    n = NULL;
                    answer = 1;
                    goto output;
                }
            }
        }

        if (support_ecs || !is_bad_view(views, view_id) || view_id == 0) {
            break;
        }

        if(i == 0) {
            v = &views->view_list[view_id];
            view_id = v->backup_id;
        } else {
            view_id = 0;
        }
    }

    return 2;
output:
    *tfind = find;
    return answer;
}

/**
 * @return 
 *   0 : has not local cache
 *   1 : has local cache
 *         node: the address of local cache
 *   -1 : the request should be dropped
 */
int query_find(uint8_t * qkey, int klen, uint32_t idx,
        struct ether_hdr *eth_hdr, union common_ip_head *ip_head,
        union common_l4_head *l4_head, uint16_t l4_len, struct dns_packet *pkt,
        uint8_t port, node ** tfind, int is_ipv6, int is_tcp, int is_from_kni,
        uint8_t support_ecs)
{
    int answer = 0;
    uint32_t bvid = 0;
    node_view_tbl *tbl = &g_node_db[idx];
    node *n = NULL, *find = NULL;
    request *r = NULL;
    uint32_t now = NOW;
    uint32_t view_id = pkt->cli_view;
    struct list_head *head = &tbl->view_hash[view_id];

    for (n = list_entry(head->next, node, node_list); &n->node_list != head;) {
        if (!match_node(n, qkey, klen)) {
            /*
            if (n->ttl != TTL_INIT && n->ttl < now) {
                node *tmp = list_entry(n->node_list.next, node, node_list);
                free_node(n);
                n = tmp;
            } else
                n = list_entry(n->node_list.next, node, node_list);
            */
            n = list_entry(n->node_list.next, node, node_list);
            continue;
        }

        /*match key */
        if (n->ttl == TTL_INIT) {   /*once the same request has send out,the ttl will set to TTL_INIT */
            /*so TTL_INIT means same request(qname,qtype,qclass all the same) has sent before */
            if (n->wait_size > 30) {
                //ALOG(SERVER, WARN, "wait size > 30,%s,drop", n->key->buf.base);
                STATS(SAME_REQ_DROP);
                answer = -1;
                n = NULL;
                goto out;
            }
            r = get_request(eth_hdr, ip_head, l4_head, l4_len, pkt, port, is_ipv6, is_tcp, is_from_kni);
            if (r == NULL) {
                answer = -1;
                n = NULL;
                goto out;
            }
            //RTE_LOG(INFO,LDNS,"TTL_INIT hold request,lcore %d,n = %u\n",rte_lcore_id(),n);
            list_add_tail(&r->list, &n->wait_list); /*link request to node */
            n->wait_size++;
            STATS(HOLD_REQ);
            n = NULL;
            goto out;
        } else if (n->ttl <= now) {
            //ALOG(SERVER,INFO,"node %s timeout--",n->key->buf.base);
            if (n->ttl + TTL_DELAY <= now) {
                //ALOG(SERVER,INFO,"node %s timeout,real_drop--",n->key->buf.base);
                STATS(TTL_EXPIRE);
                if (n->val) {
                    put_dval(n);
                    n->val = NULL;
                }

                r = get_request(eth_hdr, ip_head, l4_head, l4_len, pkt, port, is_ipv6, is_tcp, is_from_kni);
                if (r == NULL) {
                    answer = -1;
                    free_node(n);
                    n = NULL;
                    goto out;
                }
                set_node_vstate(n, VNODE_NEW);
                goto forward;
            } else {
                //ALOG(SERVER,INFO,"node %s timeout,but not drop--",n->key->buf.base);
                find = n;
                if (n->ttl + TTL_DELAY_ADJ <= now) {
                    n->ttl = now;   //adjust ttl hijack time
                }
                node_prefetch_try(n, now);
                n = NULL;
                answer = 1;
                goto out;
            }
        } else {
            find = n;
            if ((n->ttl - now) < (MIN_TTL / 6)) {
                node_prefetch_try(n, now);
            }

            n = NULL;
            answer = 1;
            goto out;
        }

        assert(0);
    }

    if (support_ecs) {
        goto newnode;
    }

    // ALOG(QUERY, INFO, "view_id = %d \n", view_id);
    if (is_bad_view(pkt->views, view_id)) {
        view *v = &pkt->views->view_list[view_id];
        bvid = v->backup_id;
        head = &tbl->view_hash[bvid];

        for (n = list_entry(head->next, node, node_list); &n->node_list != head;
             n = list_entry(n->node_list.next, node, node_list)) {

            if (match_node(n, qkey, klen)) {
                if (n->ttl == TTL_INIT)
                    goto newnode;
                if (n->ttl > now) {
                    find = n;
                    assert(n->val != NULL);
                    VSTATS(bvid, VBOUT_REQ);
                    VSTATS(n->forward_vid, VBIN_REQ);
                    if (n->lcore_id == rte_lcore_id()) {
                        if ((n->ttl - now) < (MIN_TTL / 6)) {
                            node_prefetch_try(n, now);
                        }
                    }
                    n = NULL;
                    answer = 1;
                    goto out;
                }

                if (n->ttl + TTL_DELAY <= now) {
                    //ALOG(SERVER,INFO,"node %s timeout,real_drop--",n->key->buf.base);
                    //STATS(TTL_EXPIRE);
                    goto newnode;
                } else {
                    //ALOG(SERVER,INFO,"node %s timeout,but not drop--",n->key->buf.base);
                    //data ok
                    find = n;
                    if (n->lcore_id == rte_lcore_id()) {
                        if (n->ttl + TTL_DELAY_ADJ <= now) {
                            n->ttl = now;   //adjust ttl hijack time
                        }
                        node_prefetch_try(n, now);
                    }
                    VSTATS(bvid, VBOUT_REQ);
                    VSTATS(n->forward_vid, VBIN_REQ);
                    n = NULL;
                    answer = 1;
                    goto out;
                }
            }
        }

        if (bvid !=0 && is_bad_view(pkt->views, bvid)) {
            bvid = 0;
            head = &tbl->view_hash[bvid];
            for (n = list_entry(head->next, node, node_list);
                 &n->node_list != head;
                 n = list_entry(n->node_list.next, node, node_list)) {

                if (match_node(n, qkey, klen)) {
                    if (n->ttl == TTL_INIT)
                        goto newnode;
                    if (n->ttl > now) {
                        find = n;
                        assert(n->val != NULL);
                        answer = 1;
                        VSTATS(bvid, VBOUT_REQ);
                        VSTATS(n->forward_vid, VBIN_REQ);
                        if (n->lcore_id == rte_lcore_id()) {
                            if ((n->ttl - now) < (MIN_TTL / 6)) {
                                node_prefetch_try(n, now);
                            }
                        }
                        n = NULL;
                        goto out;
                    }
                    if (n->ttl + TTL_DELAY <= now) {
                        //ALOG(SERVER,INFO,"node %s timeout,real_drop--",n->key->buf.base);
                        //STATS(TTL_EXPIRE);
                        goto newnode;
                    } else {
                        //ALOG(SERVER,INFO,"node %s timeout,but not drop--",n->key->buf.base);
                        //data ok
                        find = n;
                        assert(n->val != NULL);

                        if (n->lcore_id == rte_lcore_id()) {
                            if (n->ttl + TTL_DELAY_ADJ <= now) {
                                n->ttl = now;   //adjust ttl hijack time
                            }
                            node_prefetch_try(n, now);
                        }
                        answer = 1;
                        VSTATS(bvid, VBOUT_REQ);
                        VSTATS(n->forward_vid, VBIN_REQ);
                        n = NULL;
                        goto out;
                    }
                }
            }
        }
    }

newnode:
    // Limit the forwarding QPS
	if (!is_from_kni && g_fwd_qps_limit_on[FWD_QPSLIMIT_ID]) {
		if (!is_ipv6) {
			if (ipv4_pass(ip_head->ipv4_hdr.src_addr,
					g_fwd_qps_quota[FWD_QPSLIMIT_ID]) == IO_RET_DROP) {
				answer = -1;
				n = NULL;
				goto out;
			}
		} else {
			if (ipv6_pass(ip_head->ipv6_hdr.src_addr,
					g_fwd_qps_quota[FWD_QPSLIMIT_ID]) == IO_RET_DROP) {
				answer = -1;
				n = NULL;
				goto out;
			}
		}
	}
    r = get_request(eth_hdr, ip_head, l4_head, l4_len, pkt, port, is_ipv6, is_tcp, is_from_kni);
    if (r == NULL) {
        answer = -1;
        n = NULL;
        goto out;
    }
    int try = 0;
    int tmax = 3;
    for (try = 0; try < tmax; try++) {
        if (rte_mempool_get(node_pool, (void **)&n) < 0) {
            STATS(NODE_MP_GET_FAIL);
            /*ALOG(SERVER, WARN, "Fail to try rte_mempool_get from node_pool_%d",
             rte_lcore_id());*/
            ttl_expire_check(g_ttl_expire_clean_hash_size);
            n = NULL;
        } else {
            memset(n, 0, sizeof(*n));
#ifdef JMEM_MGR
            INIT_LIST_HEAD((&n->jkey_list));
            INIT_LIST_HEAD((&n->jval_list));
#endif
            INIT_LIST_HEAD((&n->node_list));
            INIT_LIST_HEAD((&n->wait_list));
            INIT_LIST_HEAD((&n->node_list));
            init_all_timer(n);
            init_node_link(n);
            n->lcore_id = rte_lcore_id();
            n->node_state = VNODE_NEW;
            VSTATS(view_id, VNODE_NEW);
            n->dns_id = pkt->header.id;
            n->support_ecs = support_ecs;
            n->srv_type = pkt->srv_type;
            break;
        }
    }
    if (try == tmax) {
        /*ALOG(SERVER, WARN, "Fail to do rte_mempool_get from node_pool_%d",
         rte_lcore_id());*/
        STATS(MP_GET_FAIL_DROP);
        put_request(r);
        answer = -1;
        goto out;
    }
    n->forward_vid = view_id;
    view_nodes[rte_lcore_id()][view_id]++;

    if (unlikely(__node_link_key(idx, qkey, klen, n) != 0)) {
        put_request(r);
        free_node(n);
        answer = -1;
        n = NULL;
        goto out;
    }
#ifdef JMEM_MGR
    mark_used_jmem(KEY, klen, n);
#endif
    //ALOG(QUERY,ERROR,"store key %s, len %d in view %s,hash = %d",r->key,r->klen,get_view_name(view_id),idx);
    n->tbl = tbl;

    list_add_tail(&n->node_list, &tbl->view_hash[n->forward_vid]);    /*link to hash table */
    tbl->size++;
    STATS(HOLD_REQ);

forward:
    assert(find == NULL);
    assert(list_empty(&n->timer_list[F_TIMER]));
    list_add_tail(&r->list, &n->wait_list); /*link request to node */
    n->ttl = TTL_INIT;          /*once the same request has send out,the ttl will set to < 0 */
    n->wait_size = 1;
    n->o_port = port;
    if (unlikely(select_forward_by_view_id(n, 0) < 0)) {
        put_request(r);
        free_node(n);
        answer = -1;
        n = NULL;
        goto out;
    }
    if (n->forward_rvid != n->forward_vid) {
        VSTATS(n->forward_rvid, VBOUT_REQ);
        VSTATS(n->forward_vid, VBIN_REQ);
    }
    forward_send_pkt(n);

out:
    *tfind = find;

    return answer;
}

int lcore_misc_init(int lcore_id)
{
    return 0;
}

/*
void nic_tx(struct rte_mbuf *m)
{
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *iph;
    struct tcp_hdr *tcph;

    if(m->port >= RTE_MAX_ETHPORTS){
        printf("out port invaild %u\n",m->port);
        return;
    }

    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_addr_copy(&nic[m->port].nic_mac, &eth_hdr->s_addr);
    ether_addr_copy(&nic[m->port].gw_mac, &eth_hdr->d_addr);

    iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
    iph->hdr_checksum = 0;
    //iph->hdr_checksum = get_ipv4_cksum(iph);

    tcph = (struct tcp_hdr*) (rte_pktmbuf_mtod(m, unsigned char *)
                + sizeof(struct ether_hdr) 
                + sizeof(struct ipv4_hdr));
    m->ol_flags |= PKT_TX_TCP_CKSUM;
    tcph->cksum = 0;
    //tcph->cksum = get_ipv4_psd_sum(iph);
    tcph->cksum = get_psd_sum((void *)iph, ETHER_TYPE_IPv4, m->ol_flags);
    m->l3_len = (iph->version_ihl & 0xf) << 2;
    m->l2_len = sizeof(struct ether_hdr);

    send_single_frame(m, m->port);
}
*/

int socket_init()
{
    char *error_str;
    socket_linux = dlsym(RTLD_NEXT, "socket");
    if (NULL != (error_str = dlerror())) {
        fprintf(stderr, "%s\n", error_str);
        return -1;
    }

    return 0;
}

int node_db_init() {
    int i, j;
    uint32_t io_id;
    struct lcore_params_io *lp_io = NULL;
    char name[32] = "g_node_db";

    g_node_db = rte_zmalloc(name,
            g_view_hash_table_size * sizeof(node_view_tbl), 0);
    if (g_node_db == NULL) {
        RTE_LOG(ERR, LDNS, "Fail to create %s", name);
        return -1;
    }

    for (i = 0; i < g_view_hash_table_size; i++) {
        for (j = 0; j < VIEW_MAX_COUNT; j++) {
            INIT_LIST_HEAD((&g_node_db[i].view_hash[j]));
        }
        //g_node_db[i].size = 0;
    }

    g_ids_per_core = g_view_hash_table_size / gio_count + 1;
    for (io_id = 0; io_id < gio_count; io_id++) {
        lp_io = &app.lcore_params[gio_id[io_id]].io;
        lp_io->start_idx = io_id * g_ids_per_core;
        lp_io->end_idx = lp_io->start_idx + g_ids_per_core;
    }
    if (lp_io != NULL)
        lp_io->end_idx = g_view_hash_table_size;

    return 0;
}

/*
 * dkey_obj constructor, given as a callback function to
 * rte_mempool_create().
 * Set the mp field of a dkey to corresponding value.
 */
static void
dkey_obj_init(struct rte_mempool *mp,
        __attribute__((unused)) void *opaque, void *obj,
        __attribute__((unused)) unsigned obj_idx)
{
    dkey *dk = obj;
    dk->mp = mp;
}

/*
 * dval_obj constructor, given as a callback function to
 * rte_mempool_create().
 * Set the mp field of a dval to corresponding value.
 */
static void
dval_obj_init(struct rte_mempool *mp,
        __attribute__((unused)) void *opaque, void *obj,
        __attribute__((unused)) unsigned obj_idx)
{
    dval *dv = obj;
    dv->mp = mp;
}

int g_pool_init() {
    char name[32];
    int i, lcore_id = rte_lcore_id();
    sprintf(name, "node_pool");
    node_pool = rte_mempool_create(name,
            g_lcore_node_max,
            sizeof(node),
            32,
            0,
            NULL,
            NULL,
            NULL,
            NULL,
            rte_lcore_to_socket_id(lcore_id),
            0);
    if (node_pool == NULL) {
        RTE_LOG(ERR, LDNS, "Fail to create %s", name);
        return -1;
    }
    sprintf(name, "request_pool");
    request_pool = rte_mempool_create(name,
            (g_lcore_node_max / 8),
            sizeof(request),
            32,
            0,
            NULL,
            NULL,
            NULL,
            NULL,
            rte_lcore_to_socket_id
            (lcore_id),
            0);
    if (request_pool == NULL) {
        RTE_LOG(ERR, LDNS, "Fail to create %s", name);
        return -1;
    }
    sprintf(name,"anode_pool");
    anode_max_count = g_lcore_node_max;
    anode_pool = rte_mempool_create(name,
            anode_max_count,
            sizeof(anode),
            32,
            0,
            NULL,
            NULL,
            NULL,
            NULL,
            rte_lcore_to_socket_id(lcore_id),
            0);
    if(anode_pool == NULL){
        RTE_LOG(ERR,LDNS,"Fail to create %s",name);
        return -1;
    }

    for (i = 0; i < DKEY_KEN_TYPE_NUM; ++i) {
        snprintf(name, sizeof(name), "dkey_%d_pools", dkey_buff_max_lens[i]);
        dkey_pools[i] = rte_mempool_create(name,
                get_obj_num(g_lcore_node_max, dkey_obj_ratio, DKEY_KEN_TYPE_NUM, i),
                sizeof(dkey) + dkey_buff_max_lens[i], 32, 0,
                NULL, NULL, dkey_obj_init, &i, rte_lcore_to_socket_id(lcore_id),
                0);
        if (dkey_pools[i] == NULL) {
            RTE_LOG(ERR, LDNS, "Fail to create %s", name);
            return -1;
        }
    }

    for (i = 0; i < DVAL_KEN_TYPE_NUM; ++i) {
        snprintf(name, sizeof(name), "dval_%d_pools", dval_buff_max_lens[i]);
        dval_pools[i] = rte_mempool_create(name,
                get_obj_num(g_lcore_node_max, g_dval_obj_ratio, DVAL_KEN_TYPE_NUM,
                        i), sizeof(dval) + dval_buff_max_lens[i], 32, 0,
                NULL, NULL, dval_obj_init, &i, rte_lcore_to_socket_id(lcore_id),
                0);
        if (dval_pools[i] == NULL) {
            RTE_LOG(ERR, LDNS, "Fail to create %s", name);
            return -1;
        }
    }

    return 0;
}

int lcore_io_init()
{
    int lcore_id = rte_lcore_id();
    RTE_PER_LCORE(ttl_expire_hash_idx) = app.lcore_params[lcore_id].io.start_idx;
    lcore_regex[lcore_id].work = 0;
    char name[32];

    int i;

    for (i = 0; i < TIMER_TYPE_MAX; i++) {
        timer_mgr[lcore_id][i].nums = 0;
        INIT_LIST_HEAD(&timer_mgr[lcore_id][i].list);
    }

    sprintf(name,"anode_hash_lcore_%d",lcore_id);
    anode_hash[lcore_id] = create_hash_table(name,g_view_hash_table_size,rte_lcore_to_socket_id(lcore_id));
    if(anode_hash[lcore_id] == NULL){
        RTE_LOG(ERR,LDNS,"Fail to create %s",name);
        return -1;
    }

#ifdef JMEM_MGR
    int j;
    for (i = 0; i < DVAL_KEN_TYPE_NUM; i ++) {
        for (j = 0; j < JMEM_MAX_TYPE; j++) {
            INIT_LIST_HEAD(&(jmem_mgr[lcore_id][j][i].list));
            jmem_mgr[lcore_id][j][i].iter = &(jmem_mgr[lcore_id][j][i].list);
        }
    }
#endif

    memset(view_nodes[lcore_id], 0, sizeof(view_nodes[lcore_id]));
    //RTE_LOG(INFO,LDNS,"%d view nodes set to 0,view_nodes[lcore_id][0] = %d",lcore_id,view_nodes[lcore_id][0]);
    //reset_task_pending();
    return 0;
}

static inline dval *get_dval(int size, const uint8_t * ptr)
{
    dval *dv;
    void *data = NULL;
    uint32_t i;

    for (i = 0; i < DVAL_KEN_TYPE_NUM; ++i) {
        if (dval_buff_max_lens[i] >= size) {
            if (unlikely(
                    rte_mempool_get(dval_pools[i], &data) < 0 || data == NULL)) {
                ALOG(SERVER, WARN,
                        "Lcore %d : dval_new failed, len: %d, len index: %d in %s",
                        rte_lcore_id(), size, i, __func__);
                STATS(MP_GET_FAIL_DROP);
                // try to get a dkey buffer from next pool
                continue;
            }
            dv = (dval *) data;
            dv->ref = 1;
            dv->len = size;
            dv->ttl_pos_size = 0;
            rte_memcpy(dv->data, ptr, size);

            return dv;
        }
    }

    STATS(DVAL_MP_GET_FAIL);
#ifdef JMEM_MGR
    jmem_try_free(size, VAL, JMEM_FREE_SIZE);
#endif
    /*ALOG(SERVER, WARN, "Fail to do rte_mempool_get from dval_pool");*/
    return NULL;
}

static inline void replace_dval(node *n, dval *dv, int dvlen)
{
    dval *temp_dv = n->val;
    n->val = dv;
    rte_mempool_put(temp_dv->mp, temp_dv);
}

static inline void put_dval(node * n)
{
    dval *dv = n->val;
    rte_mempool_put(dv->mp, dv);
}

static inline void put_dkey(node * n)
{
    dkey *dk = n->key;
    clear_bit(dk->view_bit_map, n->forward_vid);
    dk->ref--;
#ifdef JMEM_MGR
    unmark_used_jmem(KEY, dk->len, n);
#endif
    if (dk->ref == 0) {
        rte_mempool_put(dk->mp, dk);
    }
}

static inline void
get_query_aname(uint8_t *key,int size,char *target)
{
    if(size > NAME_MAX_LEN + 2){
        goto error;
    }
    char *dname = target;
    uint8_t *wire = key;
    uint16_t c,j,idx = 0,i=0,qlen =0;
    while(i < size && wire[i] != 0){
        c = wire[i];
        if(c == 0)
            break;
        qlen ++;
        if(qlen + c >= NAME_MAX_LEN){
            goto error;
        }

        for(j = 0 ; j < c; j ++){
            qlen ++;
            i ++;
            dname[idx++] = wire[i];
            dname[idx] = '\0';
        }
        dname[idx++] = '.';
        dname[idx] = '\0';
        i ++;
        
    }

    if(idx == 0){
        dname[0] = '.';
        dname[1] = '\0';
    }
    assert(idx < NAME_MAX_LEN);
    return;
error:
    sprintf(target,"query_name_len_bigger_than_%d",NAME_MAX_LEN);
}

void get_query_dname(uint8_t * key, int size, char *target)
{
    if (size > NAME_MAX_LEN + 2) {
        goto error;
    }
    char dname[NAME_MAX_LEN];
    uint8_t *wire = key;
    uint16_t c, j, idx = 0, i = 0, qlen = 0;
    while (i < size && wire[i] != 0) {
        c = wire[i];
        if (c == 0)
            break;
        qlen++;
        if (qlen + c >= NAME_MAX_LEN) {
            goto error;
        }

        for (j = 0; j < c; j++) {
            qlen++;
            i++;
            dname[idx++] = wire[i];
            dname[idx] = '\0';
        }
        dname[idx++] = '.';
        dname[idx] = '\0';
        i++;

    }

    if (idx == 0) {
        dname[0] = '.';
        dname[1] = '\0';
    }

    assert(idx < NAME_MAX_LEN);
    uint16_t qtype = *((uint16_t *) (wire + i + 1));
    sprintf(target, "%s/%s", dname, QT(qtype));
    return;
error:
    sprintf(target, "query_name_len_bigger_than_%d", NAME_MAX_LEN);
}

void fix_flag(struct dns_header *dnh, uint8_t flags1, uint8_t flags2)
{
    if (flags1 & LDNS_WIRE_RD_MASK) {
        dnh->flags1 |= LDNS_WIRE_RD_MASK;
    } else {
        dnh->flags1 &= (~LDNS_WIRE_RD_MASK);
    }

    if (flags2 & LDNS_WIRE_CD_MASK) {
        dnh->flags2 |= LDNS_WIRE_CD_MASK;
    } else {
        dnh->flags2 &= (~LDNS_WIRE_CD_MASK);
    }
}

static inline int servFail_node(node * n)
{
    dval *dv = n->val;
    if (dv == NULL)
        return 0;
    struct dns_header *dnh = (struct dns_header *)dv->data;
/*
    if((dnh->flags2 & LDNS_WIRE_RCODE_MASK) == SERVER_FAIL ){
        return 1;
    }

    return 0;
*/
    uint8_t status = (dnh->flags2 & LDNS_WIRE_RCODE_MASK);
    if (status != NOERROR && status != NXDOMAIN)
        return 1;               //servFail,format error,refused,not implement,other
    return 0;
}

static inline int servFail_node_try_fix(node * n)
{
    //ALOG(SERVER,WARN,"LCORE %d : If Try to fix [ServFail],stime=%ld,now=%ld",rte_lcore_id(),n->ctime,now);
    if (n->stry < SERVFAIL_TRY_MAX && node_prefetch_try(n, NOW)) {    // try to fix servFail
        n->stry++;
        STATS(SRVFAIL_TRY_FIX);
        /*
            char dname[NAME_MAX_LEN + 30];
            get_query_dname(n->key->buf.base, n->key->buf.len, dname);
            //ALOG(SERVER,WARN,"LCORE %d : Try to fix [ServFail] %s,last %u,now %u ,node = %p,viewid %d,view_name[%s]",rte_lcore_id(),dname,last,now,n,n->forward_vid,get_view_name(n->forward_vid));
            ALOG(SERVER, DEBUG,
                 "LCORE %d : Try to fix [ServFail] %s in view [%s]",
                 rte_lcore_id(), dname, get_view_name(n->forward_vid));
        */
        return 1;
    }
    return 0;                   //not send
}

static inline void servFail_node_send_fix(node * n)
{
    //if (!servFail_node_try_fix(n)) {
        //ignore try max limit
    if (node_prefetch_try(n, NOW)) {
        STATS(SRVFAIL_TRY_FIX);
        /*
         char dname[NAME_MAX_LEN + 30];
         get_query_dname(n->key->buf.base, n->key->buf.len, dname);
         ALOG(SERVER, DEBUG,
         "LCORE %d : Try to fix [ServFail] %s in view [%s]",
         rte_lcore_id(), dname, get_view_name(n->forward_vid));
         */
    }
    //}
}

void fix_ttl(struct dns_header *dnh, node * n)
{
    if ((dnh->flags2 & LDNS_WIRE_RCODE_MASK) == SERVER_FAIL) {
        STATS(ANSWER_SERVFAIL);
/*
            char dname[NAME_MAX_LEN + 30];
            get_query_dname(n->key->buf.base, n->key->buf.len, dname);
            ALOG(ANSWER, DEBUG, "LCORE %d : [ServFail] %s", rte_lcore_id(),
                 dname);
        */

        if (n->lcore_id == rte_lcore_id()) {
            servFail_node_send_fix(n);
        }
    }

    // should not update ttl for authority node
    if (SRV_TYPE_AUTH == n->srv_type) {
        return;
    }

    uint8_t *wire = (uint8_t *) dnh;
    int i;

    uint32_t now = NOW;
    uint32_t ttl = n->ttl - now;
    if (n->ttl < now || n->ttl - now < MIN_TTL / 2) {
        //ALOG(SERVER,INFO,"Fix ttl :real ttl = %d ,now = %d",n->ttl - now,MIN_TTL/2);
        ttl = MIN_TTL / 2;
    }
    for(i = 0; i < n->val->ttl_pos_size; i++) {
        wire = ((uint8_t *) dnh) + n->val->ttl_pos[i];
        uint32_t *t = (uint32_t *) wire;
        *t = Lhtonl(ttl);
    }
}

static inline int __add_edns_client_subnet(struct dns_header *dnh, char *wire,
        union common_ip *real_ip, struct adns_opt_ecs *ecs, uint16_t buf_size)
{
    dnh->arcount = Lhtons(Lntohs(dnh->arcount) + 1);

    char *p = wire;
    *p = 0;                     /*name(1):empty */
    p++;
    ECHECK(wire, p, 1);

    uint16_t *t16 = (uint16_t *) p; /*type(2) */
    *t16 = Lhtons(41);
    p += 2;
    ECHECK(wire, p, 2);

    t16 = (uint16_t *) p;       /*udp payload size */
    *t16 = Lhtons(buf_size);
    p += 2;
    ECHECK(wire, p, 3);

    uint32_t *t32 = (uint32_t *) p; /*ttl(4) ,can ignore[higher bits in extended RCODE(1),EDNS0 VERSION(1),Z(2) */
    *t32 = Lhtonl(0);
    p += 4;
    ECHECK(wire, p, 4);

    t16 = (uint16_t *) p;       /*rdata length */
    *t16 = Lhtons(8 + ecs->addr_len);
    p += 2;
    ECHECK(wire, p, 5);

    t16 = (uint16_t *) p;       /*option Code(2) */
    *t16 = Lhtons(8);
    p += 2;
    ECHECK(wire, p, 6);

    t16 = (uint16_t *) p;       /*option length(2) */
    *t16 = Lhtons(4 + ecs->addr_len);
    p += 2;
    ECHECK(wire, p, 7);

    t16 = (uint16_t *) p;       /*family,ipv4 or ipv6(2) */
    *t16 = Lhtons(ecs->family);
    p += 2;
    ECHECK(wire, p, 8);

    *p = ecs->src_mask;
    p += 1;
    if (ecs->family == 2) {
        *p = 64;
        p += 1;
    } else {
        *p = 24;
        p += 1;
    }
    ECHECK(wire, p, 9);

    memcpy(p, &(real_ip->client_ipv6), ecs->addr_len);
    p += ecs->addr_len;
    ECHECK(wire, p, 10);

    return p - wire;
}

static inline int __modify_edns_client_subnet(char **pac,
        union common_ip *real_ip, int *modified, struct adns_opt_ecs *ecs,
        uint16_t buf_size) {

    char *wire = *pac;
    char *p = wire;
    struct dns_header header;
    header.ancount = ldns_wire_get_u16((const uint8_t *)wire, LDNS_WIRE_OFFSET_ANCOUNT);
    header.nscount = ldns_wire_get_u16((const uint8_t *)wire, LDNS_WIRE_OFFSET_NSCOUNT);
    header.arcount = ldns_wire_get_u16((const uint8_t *)wire, LDNS_WIRE_OFFSET_ARCOUNT);
    wire += DNS_HLEN;
    int i, j;
    for (j = 0; j < NAME_MAX_LEN; j++) {
        if (*(wire + j) == 0)
            break;
    }
    assert(j != NAME_MAX_LEN);  //have check prev,here shouldnot be ==   
    wire += (j + 5);            //qname(j + 1) + qtype(2) + qclass(2)

    //answer
    ECHECK(p, wire, 1);
    for (i = 0; i < header.ancount; i++) {
        if (((*wire) & 0xc0) == 0xc0) {   //compression
            wire += 2;
        } else {
            j = 0;
            while(j < NAME_MAX_LEN ){
                uint8_t c = wire[j];
                if(c == 0)
                    break;
                if((wire[j] & 0xc0) == 0xc0){
                    j += 1;//compression
                    break;
                }

                j ++;
                if(j + c + 1>= NAME_MAX_LEN){
                    STATS(DNAME_PARSE_ERR);
                    //ALOG(QUERY,ERROR,"Response qname + c + 1 size >= %d",NAME_MAX_LEN);
                    return -1;

                }
                j += c;
            }
            wire += (j + 1);
        }
        wire += 8; //type,class,ttl

        uint16_t *d = (uint16_t *) wire;
        wire += 2;              //data length
        wire += (Lntohs(*d));   //data
    }

    ECHECK(p, wire, 2);

    for (i = 0; i < header.nscount; i++) {
        
        if (((*wire) & 0xc0) == 0xc0){ //compression
            wire += 2;
        } else {
            j = 0;
            while(j < NAME_MAX_LEN ){
                uint8_t c = wire[j];
                if(c == 0)
                    break;
                if((wire[j] & 0xc0) == 0xc0){
                    j += 1;//compression
                    break;
                }

                j ++;
                if(j + c + 1>= NAME_MAX_LEN){
                    STATS(DNAME_PARSE_ERR);
                    //ALOG(QUERY,ERROR,"Response qname + c + 1 size >= %d",NAME_MAX_LEN);
                    return -1;

                }
                j += c;
            }
            wire += (j + 1);
        }

        wire += 8;              //type,class,ttl

        uint16_t *d = (uint16_t *) wire;
        wire += 2;              //data length
        wire += (Lntohs(*d));   //data
    }
    ECHECK(p, wire, 3);

    for (i = 0; i < header.arcount; i++) {
        char *p = wire;
        if ((*wire) == 0) {
            wire += 1;
            uint16_t opt = *(uint16_t *) wire; /*type */
            opt = Lntohs(opt);
            if (opt != 41)
                goto common;
            if (i != header.arcount - 1)
                break;
            wire += 2; /*opt(2) */
            *(uint16_t *) (wire) = Lhtons(buf_size); /* udp payload size */
            wire +=6 ; /*class(2):udp payload size + ttl(4):can ignore[higher bits in extended RCODE(1),edns0 version(1),Z(2) */
            uint16_t dlen = *(uint16_t *) (wire); /*rdata length */
            dlen = Lntohs(dlen);
            ECHECK(p, wire, 4);
            if (dlen != 0 && dlen > 8 + ecs->addr_len)
                return -1;
            *(uint16_t *) (wire) = Lhtons(8 + ecs->addr_len);
            wire += 2;

            ECHECK(p, wire, 5);
            *(uint16_t *)(wire) = Lhtons(8); /*option code(2) */
            wire += 2;

            ECHECK(p, wire, 6);
            *(uint16_t*) (wire) = Lhtons(4 + ecs->addr_len);/*option length(2) */
            wire += 2;

            ECHECK(p, wire, 7);
            *(uint16_t *) (wire) = Lhtons(ecs->family); /*family,ipv4 or ipv6(2) */
            wire += 2;

            ECHECK(p, wire, 8);

            *wire = ecs->src_mask;
            wire += 1;
            if (ecs->family == 2) {
                *wire = 64;
                wire += 1;
            } else {
                *wire = 24;
                wire += 1;
            }

            ECHECK(p, wire, 9);
            memcpy(wire, &(real_ip->client_ipv6), ecs->addr_len);
            wire += ecs->addr_len;
            *pac = wire;
            *modified = 1;
            return 8 + ecs->addr_len - dlen;
        }
common:
        wire = p;

        if (((*wire) & 0xc0) == 0xc0){   //compression
            wire += 2;
        } else {

            j = 0;
            while(j < NAME_MAX_LEN ){
                uint8_t c = wire[j];
                if(c == 0)
                    break;
                if((wire[j] & 0xc0) == 0xc0){
                    j += 1;//compression
                    break;
                }

                j ++;
                if(j + c + 1>= NAME_MAX_LEN){
                    STATS(DNAME_PARSE_ERR);
                    //ALOG(QUERY,ERROR,"Response qname + c + 1 size >= %d",NAME_MAX_LEN);
                    return -1;

                }
                j += c;
            }
            wire += (j + 1);
        }

        wire += 8; //type,class,ttl

        uint16_t *d = (uint16_t *) wire;
        wire += 2;              //data length
        wire += (Lntohs(*d));   //data
    }

    ECHECK(p, wire, 10);
    *pac = wire;
    return 0;
}

int add_edns_client_subnet(struct rte_mbuf *m, union common_ip_head *ip_head,
        union common_l4_head *l4_head, uint16_t l4_len, struct dns_header *dnh,
        union common_ip *real_ip, int is_ipv6, int is_tcp,
        struct adns_opt_ecs *ecs, uint16_t buf_size)
{
    char *wire;
    int append = 0;

    ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
            sizeof(struct ether_hdr));
    wire = ((char *)dnh) + l4_len;
    // there should no ecs in additional section of cache node, so append directly
    append = __add_edns_client_subnet(dnh, wire, real_ip, ecs, buf_size);
    /*
    int modified = 0;

    if (Lntohs(dnh->arcount) == 0) {
        wire = ((char *)dnh) + l4_len;
        append = __add_edns_client_subnet(dnh, wire, real_ip, ecs, buf_size);
    } else {
        wire = (char *)dnh;
        //printf("Call __modify_edns_client_subnet in %s\n",__func__);
        append = __modify_edns_client_subnet(&wire, real_ip, &modified, ecs, buf_size);
        if (append == 0) {
            if (modified == 0) {
                append = __add_edns_client_subnet(dnh, wire, real_ip, ecs, buf_size);
            } else {
                return 0;
            }
        }
    }
    */
    if (append <= 0)
        return -1;

    if (is_tcp) {
        *(((uint16_t *) dnh) - 1) = adns_htons(l4_len + append);
    } else {
        l4_head->udp_hdr.dgram_len = Lhtons(
                Lntohs(l4_head->udp_hdr.dgram_len) + append);
    }

    if (is_ipv6) {
        ip_head->ipv6_hdr.payload_len = adns_htons(
                adns_ntohs(ip_head->ipv6_hdr.payload_len) + append);
    } else {
        ip_head->ipv4_hdr.total_length = adns_htons(
                Lntohs(ip_head->ipv4_hdr.total_length) + append);
    }

    if (unlikely(rte_pktmbuf_append(m, append) < 0)) {
        return -1;
    }
    return 0;
}

void specified_node_prefetch(struct lcore_msg_prefetch *p) {
    node *n = NULL;
    struct list_head *head = p->tb_head;
    list_for_each_entry(n, head, node_list) {
        if (n == p->node) {
            node_prefetch_try(n, NOW);
        }
    }
}
