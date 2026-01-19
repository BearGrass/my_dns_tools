
#ifndef _LDNS_H_
#define _LDNS_H_

#include <stdint.h>
#include "rte_core.h"

#define LDNS_COPYRIGHT        "Copyright (c) <2014-2015>, Alibaba Inc"
#define LDNS_PROG_NAME        "aliDns public dns"
#define LDNS_AUTHORS        "\n\tlong<mogu.lwp@alibaba-inc.com> May MA<mayong.my@alibaba-inc.com>\n\n"

extern char *run_dir;


/* Logical cores */
#define MAX_RX_QUEUES_PER_NIC_PORT 16
#define MAX_TX_QUEUES_PER_NIC_PORT 16

#define MAX_IO_LCORES 16
#if (MAX_IO_LCORES > RTE_MAX_LCORE)
#error "MAX_IO_LCORES is too big"
#endif

#define MAX_NIC_RX_QUEUES_PER_IO_LCORE 8
#define MAX_NIC_TX_QUEUES_PER_IO_LCORE 8

#define MAX_ADMIN_LCORES 2
#define MAX_MISC_LCORES 2
#define MAX_KNI_LCORES 1
#define MAX_ATTACK_LCORES 1

/* Mempools */
#define DEFAULT_MBUF_SIZE (2048 + RTE_PKTMBUF_HEADROOM)
#define DEFAULT_MEMPOOL_BUFFERS   8192 * 32
#define DEFAULT_MEMPOOL_CACHE_SIZE  256

/* NIC RX */
#define DEFAULT_NIC_RX_RING_SIZE 1024

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
#define DEFAULT_NIC_TX_RING_SIZE 1024

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

/* Load balancing logic */
#define DEFAULT_IO_RX_LB_POS 29
#if (DEFAULT_IO_RX_LB_POS >= 64)
#error "DEFAULT_IO_RX_LB_POS is too big"
#endif


#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define PREFETCH_OFFSET 3

#define RTE_LOGTYPE_LDNS RTE_LOGTYPE_USER1
/* max tcp port allowed number */
#define MAX_ALLOW_TCP_PORT_NUM        64
/* max query name length */
#define NAME_MAX_LEN 256
/* query type len */
#define QUERY_TYPE_LEN 2
/* server type len */
#define SERVER_TYPE_LEN 1
/* server type len */
#define QKEY_TAIL_LEN (QUERY_TYPE_LEN + SERVER_TYPE_LEN)
/* QKEY length QNAME+QTYPE+SERVER_TYPE */
#define QKEY_LEN (NAME_MAX_LEN +QKEY_TAIL_LEN)


enum app_lcore_type {
    e_LCORE_DISABLED = 0,
    e_LCORE_IO,        /* Process DNS request */
    e_LCORE_ADMIN,  /* Admin tool and conf sync */
    e_LCORE_MISC,    /* queue 0, for arp, ospf packet... */
    e_LCORE_KNI,
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
    uint16_t n_tx_queues;
    struct lcore_tx_queue tx_queues[MAX_NIC_TX_QUEUES_PER_IO_LCORE];

    uint16_t tx_port_queue[RTE_MAX_ETHPORTS];

    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];

    /* Stats */
    uint32_t rx_queues_count[MAX_NIC_RX_QUEUES_PER_IO_LCORE];
    uint32_t rx_queues_iters[MAX_NIC_RX_QUEUES_PER_IO_LCORE];
    uint32_t tx_queues_count[MAX_NIC_TX_QUEUES_PER_IO_LCORE];
    uint32_t tx_queues_iters[MAX_NIC_TX_QUEUES_PER_IO_LCORE];

    uint32_t io_id;
    uint32_t start_idx;
    uint32_t end_idx;
};

struct lcore_params_kni {
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

struct lcore_params_misc {

};

struct lcore_params {
    union {
        struct lcore_params_io io;
        struct lcore_params_admin admin;
        struct lcore_params_kni kni;
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
    uint8_t port_mask[RTE_MAX_ETHPORTS];
    struct ether_addr eth_addrs[RTE_MAX_ETHPORTS];
    uint16_t allowed_tcp_port[MAX_ALLOW_TCP_PORT_NUM];  /* from config file tcp_port_allowed section, allowed tcp port number */

    uint8_t portmask;
    /* port number */
    uint8_t nb_ports;
    uint8_t max_lcore;

    /* mbuf pools */
    struct rte_mempool *pools[RTE_MAX_NUMA_NODES];

    /* rings */
    uint32_t nic_rx_ring_size;
    uint32_t nic_tx_ring_size;

    /* load balancing */
    uint8_t pos_lb;

    /* arguments */
    int32_t argc;                /* Number of arguments */
    char    *argv[64];            /* Argument list */
} __rte_cache_aligned;

extern struct app_params app;
extern char *cfg_profile;
extern struct rte_eth_dev_info g_dev_info[RTE_MAX_ETHPORTS];


// ------ KNI --------
/* Max size of a single packet */
#define KNI_MAX_PACKET_SZ           2048

/* Number of bytes needed for each mbuf */
#define KNI_MBUF_SZ \
    (KNI_MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define KNI_NB_MBUF                 (8192 * 32)

/* How many packets to attempt to read from NIC in one go */
#define KNI_PKT_BURST_SZ            32
//#define KNI_PKT_BURST_SZ            8

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define KNI_MEMPOOL_CACHE_SZ        KNI_PKT_BURST_SZ

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

/* Mempool for mbufs */
struct rte_mempool *kni_pktmbuf_pool;

struct ports_kni {
    struct rte_kni *kni;
    uint32_t lcore_id;
    uint32_t is_running;
    uint8_t force_bind;
};
/* kni port specific information array*/
struct ports_kni kni_port_info[RTE_MAX_ETHPORTS];

int kni_lcore_port_map[RTE_MAX_ETHPORTS];

int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

extern uint8_t nb_sys_ports;
extern int kni_running;


struct rte_kni_ops kni_ops;


void send_single_frame(struct rte_mbuf *m, uint8_t port);

int is_socket_used(uint32_t socket);
int get_nic_rx_queues_per_port(uint8_t port);
int get_nic_tx_queues_per_port(uint8_t port);
int get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t *lcore_out);
int get_lcore_for_nic_tx(uint8_t port, uint8_t queue, uint32_t *lcore_out);

int ldns_parse_args(int argc, char **argv);
void ldns_usage(const char *prgname);
int ldns_init(void);
void app_print_params(void);
int lcore_main_loop(void *arg);

int main(int argc, char **argv);


#endif

