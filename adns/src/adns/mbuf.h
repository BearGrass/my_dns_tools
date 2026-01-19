#ifndef __MBUF_H__
#define __MBUF_H__


extern int init_mbuf();
extern struct rte_mempool *g_pktmbuf_pool;


static inline struct rte_mbuf* mbuf_alloc(void)
{
    return rte_pktmbuf_alloc(g_pktmbuf_pool);
}

static inline struct rte_mbuf* mbuf_clone(struct rte_mbuf * m)
{
    return rte_pktmbuf_clone(m , g_pktmbuf_pool);
}

int app_init_mbuf_pools(void);

#endif
