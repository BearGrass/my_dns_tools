
#ifndef _ADNS_H_
#define _ADNS_H_

#include <stdint.h>

#include "rte_core.h"

#define ADNS_VERSION		"2.3.3"
#define ADNS_COPYRIGHT		"Copyright (c) <2013-2017>, Alibaba Inc"
#define ADNS_AUTHORS		("\n\tAndy Chen <sanjie.cyg@taobao.com>" \
                            "\n\thefeng <hejun.hj@alibaba-inc.com>" \
                            "\n\tshengyan <jie.cj@alibaba-inc.com>" \
                            "\n\tyangle <yangle.ghq@alibaba-inc.com>" \
                            "\n\tzhaoge <zhaozhi.gzz@alibaba-inc.com>" \
                            "\n\tyisong <songyi.sy@alibaba-inc.com>" \
                            "\n\tyingze <mayong.my@alibaba-inc.com>" \
                            "\n\tmogu <mogu.lwp@alibaba-inc.com>" \
                            "\n\twangnan <wn147929@alibaba-inc.com>")


extern char *run_dir;
#define ADNS_NB_SOCKETS 1

/* Logical cores */
#define MAX_RX_QUEUES_PER_NIC_PORT 32
#define MAX_TX_QUEUES_PER_NIC_PORT 32

#define MAX_NIC_RX_QUEUES_PER_IO_LCORE 8
#define MAX_NIC_TX_QUEUES_PER_IO_LCORE 8

#define MAX_ADMIN_LCORES 2
#define MAX_MISC_LCORES 2

/* Mempools */
#define DEFAULT_MBUF_SIZE (4096 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define DEFAULT_MEMPOOL_BUFFERS         8192 * 32
#define DEFAULT_MEMPOOL_CACHE_SIZE       32
#define DEFAULT_SYSLOG_MEMPOOL_BUFFERS  102400

/* NIC RX */
#define DEFAULT_NIC_RX_RING_SIZE 4096

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define DEFAULT_NIC_RX_PTHRESH  8
#define DEFAULT_NIC_RX_HTHRESH  8
#define DEFAULT_NIC_RX_WTHRESH  4
#define DEFAULT_NIC_RX_FREE_THRESH  64
#define DEFAULT_NIC_RX_DROP_EN 1

/* NIC TX */
#define DEFAULT_NIC_TX_RING_SIZE 4096

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define DEFAULT_NIC_TX_PTHRESH  36
#define DEFAULT_NIC_TX_HTHRESH  0
#define DEFAULT_NIC_TX_WTHRESH  0
#define DEFAULT_NIC_TX_FREE_THRESH  0
#define DEFAULT_NIC_TX_RS_THRESH  0


#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define PREFETCH_OFFSET 3

#define RTE_LOGTYPE_ADNS RTE_LOGTYPE_USER1

/* surprisingly thereis no IPPROTO_OSPFIGP in netinet/in.h */
#define IPPROTO_OSPFIGP 89
#define IPPROTO_BGP 179

/* max tcp port allowed number */
#define MAX_ALLOW_TCP_PORT_NUM        64

enum app_lcore_type {
    e_LCORE_DISABLED = 0,
    e_LCORE_IO,		/* Process DNS request */
    e_LCORE_ADMIN,  /* Admin tool and conf sync */
    e_LCORE_MISC,	/* queue 0, for arp, ospf packet... */
    e_LCORE_TCP/* queue 0, for arp, ospf packet... */
};

struct mbuf_table {
    struct rte_mbuf *m_table[MAX_PKT_BURST];
    uint32_t len;
};

struct lcore_rx_queue {
    uint8_t port_id;
    uint8_t queue_id;
};

struct lcore_tx_queue {
    uint8_t port_id;
    uint8_t queue_id;
};

struct lcore_params_io {
    /* RX queues */
    uint16_t n_rx_queues;
    struct lcore_rx_queue rx_queues[MAX_NIC_RX_QUEUES_PER_IO_LCORE];

    /* TX */
    uint16_t n_tx_ports;
    uint8_t tx_ports[MAX_NIC_TX_QUEUES_PER_IO_LCORE];
    /* Only support one queue for every port on every lcore */
    uint8_t tx_queues[RTE_MAX_ETHPORTS];

    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

    /* Stats */
    uint32_t rx_queues_count[MAX_NIC_RX_QUEUES_PER_IO_LCORE];
    uint32_t rx_queues_iters[MAX_NIC_RX_QUEUES_PER_IO_LCORE];
    uint32_t tx_queues_count[MAX_NIC_TX_QUEUES_PER_IO_LCORE];
    uint32_t tx_queues_iters[MAX_NIC_TX_QUEUES_PER_IO_LCORE];

    uint32_t io_id;
};

struct lcore_params_misc {
    /* misc lcore use NIC queue 0 for rx/tx */
    uint8_t nic_port_mask[RTE_MAX_ETHPORTS];

    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

    /* Stats */
    uint32_t rx_count[RTE_MAX_ETHPORTS];
    uint32_t rx_iters[RTE_MAX_ETHPORTS];
    uint32_t tx_count[RTE_MAX_ETHPORTS];
    uint32_t tx_iters[RTE_MAX_ETHPORTS];
};


struct lcore_params_admin {

};

struct lcore_params {
    union {
        struct lcore_params_io io;
        struct lcore_params_admin admin;
        struct lcore_params_misc misc;
    };
    enum app_lcore_type type;
    struct rte_mempool *pool;
    struct timeval start_time;
    uint64_t start_cycles;
} __rte_cache_aligned;


struct app_params {
    /* lcore */
    struct lcore_params lcore_params[RTE_MAX_LCORE];

    /* NIC */
    uint8_t nic_rx_queue_mask[RTE_MAX_ETHPORTS][MAX_RX_QUEUES_PER_NIC_PORT];
    uint8_t nic_tx_queue_mask[RTE_MAX_ETHPORTS][MAX_TX_QUEUES_PER_NIC_PORT];
    uint8_t port_enabled[RTE_MAX_ETHPORTS];    /* from config file io section, port-queue-lcore */
    struct  ether_addr eth_addrs[RTE_MAX_ETHPORTS];
    uint16_t allowed_tcp_port[MAX_ALLOW_TCP_PORT_NUM];  /* from config file tcp_port_allowed section, allowed tcp port number */

    uint8_t portmask;    /* from cmdline -p, port totally up or not */
    uint8_t lcore_num;
    uint8_t lcore_io_num;
    uint8_t lcore_io_start_id;

    /* mbuf pools */
    struct rte_mempool *pools[RTE_MAX_NUMA_NODES];

    /* rings */
    uint32_t nic_rx_ring_size;
    uint32_t nic_tx_ring_size;

    /* load balancing */
    uint8_t pos_lb;

    /* arguments */
    int32_t argc;				/* Number of arguments */
    char    *argv[64];			/* Argument list */
} __rte_cache_aligned;

extern struct app_params app;
extern char *cfg_profile;


// ------ KNI --------
/* Max size of a single packet */
#define KNI_MAX_PACKET_SZ           2048

/* Number of bytes needed for each mbuf */
#define KNI_MBUF_SZ \
    (KNI_MAX_PACKET_SZ + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define KNI_NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define KNI_PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define KNI_MEMPOOL_CACHE_SZ        KNI_PKT_BURST_SZ

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

/* Mempool for mbufs */
extern struct rte_mempool *kni_pktmbuf_pool;

/* kni port specific information array*/
extern struct rte_kni *kni_port_info[RTE_MAX_ETHPORTS];

int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

extern uint8_t nb_sys_ports;
extern int kni_running;

extern struct rte_kni_ops kni_ops;

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets;
    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped;
    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets;
    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped;
};


int send_single_packet(struct rte_mbuf *m, uint8_t port);

int is_socket_used(uint32_t socket);
int get_nic_rx_queues_per_port(uint8_t port);
int get_nic_tx_queues_per_port(uint8_t port);
int get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t *lcore_out);
int get_lcore_for_nic_tx(uint8_t port, uint8_t queue, uint32_t *lcore_out);
int get_lcore_num();
int get_io_lcore_start_id();
int get_io_lcore_num();


int adns_parse_args(int argc, char **argv);
void adns_usage(const char *prgname);
int adns_init(void);
void app_print_params(void);
int lcore_main_loop(void *arg);

int main(int argc, char **argv);

inline static int lcore_is_enable(int lcore) {
	if (app.lcore_params[lcore].type == e_LCORE_DISABLED)
		return 0;
	else
		return 1;
}

#define BE_53 13568 
#define BE_BGP_PORT 45824
#define ZONE_CNT 0
#endif

