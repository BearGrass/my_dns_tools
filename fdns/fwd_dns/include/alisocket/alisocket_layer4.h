#ifndef __ALISOCKET_LAYER4__
#define __ALISOCKET_LAYER4__

#include "rte_mempool.h"
#include "rte_mbuf.h"

struct l3devinfo{
	uint32_t mtu;
	uint16_t port;
	uint32_t ip;
};

typedef struct __alisk_layer4_ops{
	struct rte_mempool **rx_pktmbuf_pool;
	int (*nic_rx)(void);
	void (*nic_tx)(struct rte_mbuf *m);
	void (*nic_drain_tx)(void);
	int (*get_l3devinfo_by_laddr)(uint32_t laddr, struct l3devinfo* info);
	int (*get_l3devinfo_by_faddr)(uint32_t faddr, struct l3devinfo* info);
}alisk_layer4_ops;


extern int alisk_init(alisk_layer4_ops *ops);
extern int alisk_layer4_input(struct rte_mbuf *m);
extern struct rte_mempool * alisk_rx_pkt_mpool_alloc( const char *name, int sock_id, unsigned flags ); 


#endif //__ALISOCKET_LAYER4__
