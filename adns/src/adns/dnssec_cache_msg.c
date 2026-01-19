#include "rte_mempool.h"

#include "dnssec_cache_msg.h"
#include "dnssec_cache.h"
#include "adns.h"
#include "log.h"
#include "rcu.h"
#include "zonedb.h"
#include "domain_hash.h"

#define DNSSEC_CACHE_MSG_RING_SIZE 1<<16
#define DNSSEC_CACHE_MSG_POOL_SIZE 4096
#define MSG_READ_SIZE 32

struct rte_mempool *g_dnssec_cache_msg_pool = NULL;
struct rte_ring *g_dnssec_cache_msg_ring[RTE_MAX_LCORE] = { NULL };
static uint32_t dnssec_cache_msg_ring_num = 0;
static int g_lcore_2_dnssec_cache_msg_ring_index[RTE_MAX_LCORE] = { RTE_MAX_LCORE };


static inline dnssec_cache_msg * __attribute__ ((always_inline))
dnssec_cache_msg_alloc(struct rte_mempool *mp) 
{
    void *msg;

    if (rte_mempool_get(mp, &msg) < 0) {
        return NULL;
    }
    memset(msg, 0, sizeof(dnssec_cache_msg));

    return (dnssec_cache_msg *) msg;
}

static inline void __attribute__ ((always_inline))
__dnssec_cache_msg_free(struct rte_mempool *mp, dnssec_cache_msg* msg)
{
    if (msg == NULL)
        return;
    rte_mempool_put(mp, (void *) msg);
}

static inline dnssec_cache_msg * __attribute__ ((always_inline))
new_dnssec_cache_msg(void)
{
    dnssec_cache_msg *msg;

    msg = dnssec_cache_msg_alloc(g_dnssec_cache_msg_pool);
    if (msg == NULL) {
        return NULL;
    }

    return msg;
}

void dnssec_cache_msg_free(dnssec_cache_msg* msg) {
    __dnssec_cache_msg_free(g_dnssec_cache_msg_pool, msg);
}


int send_dnssec_cache_msg(uint32_t lcore,
                          dnssec_cache_operation_type op,
                          uint8_t *owner,
                          uint8_t owner_len,
                          uint16_t type,
                          adns_viewid_t id,
                          adns_rrsig_rdata *rrsig_rdata,
                          uint8_t *signer,
                          uint8_t signer_len,
                          uint8_t *signature,
                          uint8_t *rdata,
                          uint16_t rdlen)
{
    dnssec_cache_msg *msg;
    int ret, ring_index;
    struct rte_ring *ring = NULL;
    dnssec_cache_msg_ctx *ctx = NULL;
    uint8_t pass_value = 1;

    /*
     * Pre check dnssec_cache_msg
     */
    // if operation is DNSSEC cache node deletion, no need to pass node value
    if (op == DNSSEC_CACHE_DELETE) {
        pass_value = 0;
    }

    if (unlikely(owner == NULL || owner_len == 0 || rdata == NULL || rdlen == 0)) {
        log_server_error(rte_lcore_id(), "Unexpected errors sending dnssec cache msg\n");
        return -1;
    }

    if (unlikely( (pass_value == 1) &&
                (rrsig_rdata == NULL || 
                signer == NULL || signer_len == 0 ||
                signature == NULL) )) {
        log_server_error(rte_lcore_id(), "Unexpected errors sending dnssec cache msg\n");
        return -1;
    }

    // get dnssec cache msg ring by lcore id
    ring_index = g_lcore_2_dnssec_cache_msg_ring_index[lcore];
    if (ring_index == RTE_MAX_LCORE) {
        log_server_error(rte_lcore_id(), "No corresponding DNSSEC cache msg ring for lcore %u\n");
        return -1;
    }
    ring = g_dnssec_cache_msg_ring[ring_index];
    if (ring == NULL) {
        log_server_error(rte_lcore_id(), "No corresponding DNSSEC cache msg ring for lcore %u\n");
        return -1;
    }

    // new dnssec cache msg
    msg = new_dnssec_cache_msg();
    if (msg == NULL) {
        return -1;
    }

    // fill dnssec cache msg
    msg->op = op;
    ctx = &(msg->ctx);
    rte_memcpy(ctx->owner, owner, owner_len);
    ctx->owner_len = owner_len;
    ctx->type = type;
    ctx->view_id = id;
    if (unlikely(rdlen > MAX_CACHE_KEY_SIZE)) {
        log_server_error(rte_lcore_id(), "pass rdata error when sending dnssec cache msg\n");
        __dnssec_cache_msg_free(g_dnssec_cache_msg_pool, msg);
        return -1;
    }
    rte_memcpy(ctx->rdata, rdata, rdlen);
    ctx->rdlen = rdlen;

    // pass node value if needed
    if (pass_value == 1) {
        rte_memcpy(&(ctx->rrsig_rdata), rrsig_rdata, sizeof(adns_rrsig_rdata));
        rte_memcpy(ctx->signer, signer, signer_len);
        ctx->signer_len = signer_len;
        rte_memcpy(ctx->signature, signature, DNS_SIG_ECDSA256SIZE);
    }

    // enqueue msg to percore dnssec cache msg ring
    ret = rte_ring_enqueue(ring, (void*) msg);
    if (ret == -ENOBUFS) {
        log_server_error(rte_lcore_id(), "Enqueue cache msg ring error\n");
        __dnssec_cache_msg_free(g_dnssec_cache_msg_pool, msg);
        return -1;
    }

    return 0;
}

static inline int handle_single_dnssec_cache_msg(dnssec_cache_msg *msg)
{
    dnssec_cache_msg_ctx *ctx = NULL;
    adns_dnssec_cache_node *cache_node = NULL, *old_node = NULL;
    //adns_dnssec_neg_cache_node *neg_cache_node = NULL, *neg_old_node = NULL;
    int ret;
    typedef void (*pfn) (void *);

    if (msg == NULL) {
        return -1;
    }
    ctx = &(msg->ctx);

    // lookup dnssec cache node
    old_node = adns_dnssec_cache_hash_lookup(ctx->owner, ctx->owner_len, ctx->type, ctx->view_id, ctx->rdata, ctx->rdlen, ctx->rrsig_rdata.original_ttl);

    switch (msg->op) {
        // add DNSSEC cache
        case DNSSEC_CACHE_INSERT:
            if (old_node != NULL) {
                log_server_warn(rte_lcore_id(), "CACHE_INSERT: dnssec cache node already exists\n");
                break;
            }
            cache_node = adns_new_dnssec_cache_node(ctx->owner,
                                                    ctx->owner_len,
                                                    ctx->type,
                                                    ctx->view_id,
                                                    ctx->rdata,
                                                    ctx->rdlen,
                                                    &(ctx->rrsig_rdata),
                                                    ctx->signer,
                                                    ctx->signer_len,
                                                    ctx->signature);
            if (cache_node == NULL) {
                log_server_error(rte_lcore_id(), "CACHE_INSERT: create dnssec cache node error\n");
                return -1;
            }
            adns_dnssec_cache_add_hash(cache_node);
            break;
        // delete DNSSEC cache
        case DNSSEC_CACHE_DELETE:
            if (old_node == NULL) {
                log_server_warn(rte_lcore_id(), "CACHE_DELETE: dnssec cache node not exist\n");
                break;
            }
            adns_dnssec_cache_del_hash(old_node);
            ret = call_rcu( (pfn)adns_free_dnssec_cache_node, old_node);
            if (ret < 0) {
                // rarely happens, due to memory run out, recover node deletion, 
                log_server_error(rte_lcore_id(), "CACHE_DELETE: call rcu error\n");
                adns_dnssec_cache_add_hash(old_node);
            }
            break;
        // update DNSSEC cache
        case DNSSEC_CACHE_UPDATE:
            cache_node = adns_new_dnssec_cache_node(ctx->owner,
                                                    ctx->owner_len,
                                                    ctx->type,
                                                    ctx->view_id,
                                                    ctx->rdata,
                                                    ctx->rdlen,
                                                    &(ctx->rrsig_rdata),
                                                    ctx->signer,
                                                    ctx->signer_len,
                                                    ctx->signature);
            if (cache_node == NULL) {
                log_server_error(rte_lcore_id(), "CACHE_UPDATE: create dnssec cache node error\n");
                return -1;
            }
            // if node already flushed, just insert the new node
            if (old_node == NULL) {
                adns_dnssec_cache_add_hash(cache_node);
            } else { // replace node
                if (adns_dnssec_cache_replace_hash(cache_node, old_node) < 0) {
                    adns_free_dnssec_cache_node(cache_node);
                    log_server_error(rte_lcore_id(), "CACHE_UPDATE: replace dnssec cache node error\n");
                    return -1;
                }
                ret = call_rcu( (pfn)adns_free_dnssec_cache_node, old_node);
                if (ret < 0) {
                    // rarely happens, due to memory run out, recover node replace
                    adns_dnssec_cache_replace_hash(old_node, cache_node);
                    adns_free_dnssec_cache_node(cache_node);
                    log_server_error(rte_lcore_id(), "CACHE_UPDATE: call rcu error\n");
                }
            }
            break;
        default:
            break;
    }

    return 0;
}

uint32_t handle_dnssec_cache_msg()
{
    uint32_t i, j, num, tot_num = 0;
    struct rte_ring *ring;
    dnssec_cache_msg *msg_queue[MSG_READ_SIZE];

    for (i = 0; i < dnssec_cache_msg_ring_num; i++) {
        ring = g_dnssec_cache_msg_ring[i];
        num = MSG_READ_SIZE;

        while (num > 0
                && rte_ring_dequeue_bulk(ring, (void **) msg_queue, num) != 0) {
            num = RTE_MIN(rte_ring_count(ring), MSG_READ_SIZE);
        }

        for (j = 0; j < num; j++) {
            if (handle_single_dnssec_cache_msg(msg_queue[j]) <= 0) {
                __dnssec_cache_msg_free(g_dnssec_cache_msg_pool, msg_queue[j]);
            }
        }
        tot_num += num;
    }

    return tot_num;
}

int dnssec_cache_msg_init()
{
    adns_socket_id_t socket_id;
    char name[32];
    uint32_t i;

    socket_id = rte_lcore_to_socket_id(rte_lcore_id());
    g_dnssec_cache_msg_pool = rte_mempool_create("dnssec_cache_msg_pool", DNSSEC_CACHE_MSG_POOL_SIZE,
            sizeof(struct dnssec_cache_msg), 32, 0, NULL,
            NULL, NULL, NULL, socket_id, MEMPOOL_F_SP_PUT);
    if (g_dnssec_cache_msg_pool == NULL) {
        RTE_LOG(ERR, ADNS, "[%s]: Failed to create dnssec cache msg pool\n", __FUNCTION__);
        return -1;
    }
    RTE_LOG(INFO, ADNS, "[%s]: Finish to init dnssec cache msg pool\n", __FUNCTION__);

    for (i = 0; i < RTE_MAX_LCORE; i++) {
        // only io core and admin core
        if (app.lcore_params[i].type == e_LCORE_DISABLED ||
            app.lcore_params[i].type == e_LCORE_MISC) {
            continue;
        }
        snprintf(name, 32, "DNSSEC_CACHE_MSG_RING_%u", i);
        g_dnssec_cache_msg_ring[dnssec_cache_msg_ring_num] = rte_ring_create(name, DNSSEC_CACHE_MSG_RING_SIZE, socket_id, RING_F_SC_DEQ);
        if (g_dnssec_cache_msg_ring[dnssec_cache_msg_ring_num] == NULL) {
            RTE_LOG(ERR, ADNS, "[%s]: Failed to create dnssec cache msg ring %s\n", __FUNCTION__, name);
            return -1;
        }
        g_lcore_2_dnssec_cache_msg_ring_index[i] = dnssec_cache_msg_ring_num;
        dnssec_cache_msg_ring_num ++;
    }
    RTE_LOG(INFO, ADNS, "[%s]: Finish to init dnssec cache msg rings\n", __FUNCTION__);

    return 0;
}

void dnssec_cache_msg_destory()
{
    uint32_t i;

    for (i = 0; i < dnssec_cache_msg_ring_num; i ++) {
        rte_ring_free(g_dnssec_cache_msg_ring[i]);
        g_dnssec_cache_msg_ring[i] = NULL;
    }

    rte_mempool_free(g_dnssec_cache_msg_pool);
    g_dnssec_cache_msg_pool = NULL;
}