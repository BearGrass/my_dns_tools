#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_byteorder.h>
#include <rte_string_fns.h>

#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_core.h>
#include <rte_kni.h>
#include <rte_ethdev.h>
#include <rte_interrupts.h>


#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_memory.h>

#include "net_debug.h"
#include "iplib.h"
#include "ldns.h"
#include "msg.h"
#include "cfg_file.h"
#include "log.h"
#include "bit.h"
#include "view.h"
#include "common.h"
#include "request.h"
#include "storage.h"
#include "adns_fdir.h"
#include "qtype.h"
#include "user_config.h"
#include "whitelist.h"
#include "man_whitelist.h"
#include "man_blacklist.h"
#include "ip_filter.h"
#include "blacklist.h"
#include "oversealist.h"
#include "ae.h"
#include "admin.h"
#include "stats.h"
#include "user_config.h"
#include "health_check.h"
#include "view_maps.h"
#include "qos.h"
#include "hijack.h"
#include "dnscache_tbl.h"
#include "dnscache.h"
#include "fwd_user.h"
#include "fwd_ip_user_tbl.h"
#include "fwd_user_db.h"

#define VIEW_ID_INIT 0Xffffffff


struct sys_admin admin;
#define FILE_PATH_MAX 200
#define VGOUP_MAX 2550
uint8_t gvstate_bitmap[RTE_MAX_LCORE][VIEW_BITMAP_SIZE];
uint8_t gio_id[_MAX_LCORE];
uint8_t gio_count;
uint8_t gkni_id[_MAX_LCORE];
uint8_t gkni_count;
int gkni_rotate_id[_MAX_LCORE];

int glog_lcore_count = 0;
int glog_lcore_id[_MAX_LCORE];

uint32_t goversea_view_id = VIEW_ID_INIT;
uint32_t ganode_view_id = 0;
#ifdef __FDIR_DIP_ENABLE
static uint32_t vport_ips[RTE_MAX_ETHPORTS];
#ifdef __IPV6_SUPPORT
static uint32_t ipv6_vport_ips[RTE_MAX_ETHPORTS][4];
#endif
#endif

struct id_name_map {
    int id;
    const char *name;
};

static struct id_name_map rss_conf_maps[] = {
#ifdef __SUPPORT_NIC_XL710
    {ETH_RSS_TCP,  "tcp"},
#else
    {ETH_RSS_NONFRAG_IPV4_TCP,  "tcp"},
#endif
    {ETH_RSS_UDP,  "udp"},
    {ETH_RSS_IP,   "ip"},
    {ETH_RSS_IPV6, "ipv6"},
};

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .split_hdr_size = 0,
        .header_split   = 0, /**< Header Split disabled */
        .hw_ip_checksum = 1, /**< IP checksum offload enabled */
        .hw_vlan_filter = 0, /**< VLAN filtering disabled */
        .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
        .hw_strip_crc   = 0, /**< CRC stripped by hardware */
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_TCP | ETH_RSS_UDP, /*ETH_RSS_IPV4*/
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
    .intr_conf = {
        .lsc = 1, /**< lsc interrupt feature enabled */
    },
    .fdir_conf = {
        .mode = RTE_FDIR_MODE_PERFECT,
        .pballoc = RTE_FDIR_PBALLOC_64K,
        .status = RTE_FDIR_REPORT_STATUS,
        .drop_queue = 127,
        .mask = {
            .dst_port_mask = 0xffff,    // this only works on 82599, it has no effects on xl710
        },
    },
};

static struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
                  .pthresh = DEFAULT_NIC_RX_PTHRESH,
                  .hthresh = DEFAULT_NIC_RX_HTHRESH,
                  .wthresh = DEFAULT_NIC_RX_WTHRESH,
                  },
    .rx_free_thresh = DEFAULT_NIC_RX_FREE_THRESH,
    .rx_drop_en = DEFAULT_NIC_RX_DROP_EN,
};

static struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
                  .pthresh = DEFAULT_NIC_TX_PTHRESH,
                  .hthresh = DEFAULT_NIC_TX_HTHRESH,
                  .wthresh = DEFAULT_NIC_TX_WTHRESH,
                  },
    .tx_free_thresh = DEFAULT_NIC_TX_FREE_THRESH,
    .tx_rs_thresh = DEFAULT_NIC_TX_RS_THRESH,
};

static void print_ethaddr(const char *name, const struct ether_addr *eth_addr);
static int str_to_unsigned_array(const char *s, size_t sbuflen,
                                 char separator,
                                 unsigned num_vals, unsigned *vals)
{
    char str[sbuflen + 1];
    char *splits[num_vals];
    char *endptr = NULL;
    int i, num_splits = 0;

    /* copy s so we don't modify original string */
    snprintf(str, sizeof(str), "%s", s);
    num_splits = rte_strsplit(str, sizeof(str), splits, num_vals, separator);

    errno = 0;
    for (i = 0; i < num_splits; i++) {
        vals[i] = strtoul(splits[i], &endptr, 0);
        if (errno != 0 || *endptr != '\0')
            return -1;
    }

    return num_splits;
}

static int str_to_unsigned_vals(const char *s,
                                size_t sbuflen,
                                char separator, unsigned num_vals, ...)
{
    unsigned i, vals[num_vals];
    va_list ap;

    num_vals = str_to_unsigned_array(s, sbuflen, separator, num_vals, vals);

    va_start(ap, num_vals);
    for (i = 0; i < num_vals; i++) {
        unsigned *u = va_arg(ap, unsigned *);
        *u = vals[i];
    }
    va_end(ap);
    return num_vals;
}

#define ETH_RX_MAX_CHARS     4096
#define ETH_RX_MAX_TUPLES    128

static int parse_eth_rx(const char *arg)
{
    const char *p0 = arg, *p = arg;
    uint32_t n_tuples;

    if (strnlen(arg, ETH_RX_MAX_CHARS + 1) == ETH_RX_MAX_CHARS + 1) {
        return -1;
    }

    n_tuples = 0;
    while ((p = strchr(p0, '(')) != NULL) {
        struct lcore_params *lp;
        uint32_t port, queue, lcore, i;

        p0 = strchr(p++, ')');
        /*
         * fill port queue lcore by (n1,n2,n3)
         * port=n1, queue=n2, lcore=n3
         */
        if ((p0 == NULL) ||
            (str_to_unsigned_vals(p, p0 - p, ',', 3, &port, &queue, &lcore) !=
             3)) {
            return -2;
        }

        /* Enable port and queue for later initialization */
        if ((port >= RTE_MAX_ETHPORTS) || (queue >= MAX_RX_QUEUES_PER_NIC_PORT)) {
            return -3;
        }
        if (app.nic_rx_queue_mask[port][queue] != 0) {
            return -4;
        }
        app.nic_rx_queue_mask[port][queue] = 1;

        if (app.port_mask[port] == 0)
            app.port_mask[port] = 1;

        /* Check and assign (port, queue) to I/O lcore */
        if (rte_lcore_is_enabled(lcore) == 0) {
            return -5;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -6;
        }
        lp = &app.lcore_params[lcore];
        if (lp->type == e_LCORE_ADMIN || lp->type == e_LCORE_MISC || lp->type == e_LCORE_KNI) {
            return -7;
        }
        lp->type = e_LCORE_IO;
        for (i = 0; i < lp->io.n_rx_queues; i++) {
            if ((lp->io.rx_queues[i].port_id == port) &&
                (lp->io.rx_queues[i].queue_id == queue)) {
                return -8;
            }
        }
        if (lp->io.n_rx_queues >= MAX_NIC_RX_QUEUES_PER_IO_LCORE) {
            return -9;
        }
        lp->io.rx_queues[lp->io.n_rx_queues].port_id = (uint8_t) port;
        lp->io.rx_queues[lp->io.n_rx_queues].queue_id = (uint8_t) queue;
        lp->io.n_rx_queues++;

        n_tuples++;
        if (n_tuples > ETH_RX_MAX_TUPLES) {
            return -10;
        }

        if (lcore > app.max_lcore) {
            app.max_lcore = lcore;
        }
    }

    if (n_tuples == 0) {
        return -11;
    }

    return 0;
}

#define ETH_TX_MAX_CHARS     4096
#define ETH_TX_MAX_TUPLES    128

static int parse_eth_tx(const char *arg)
{
    const char *p0 = arg, *p = arg;
    uint32_t n_tuples;

    if (strnlen(arg, ETH_TX_MAX_CHARS + 1) == ETH_TX_MAX_CHARS + 1) {
        return -1;
    }

    n_tuples = 0;
    while ((p = strchr(p0, '(')) != NULL) {
        struct lcore_params *lp;
        uint32_t port, queue, lcore, i;

        p0 = strchr(p++, ')');
        if ((p0 == NULL) ||
            (str_to_unsigned_vals(p, p0 - p, ',', 3, &port, &queue, &lcore) !=
             3)) {
            return -2;
        }

        /* Enable port and queue for later initialization */
        if ((port >= RTE_MAX_ETHPORTS) || (queue >= MAX_TX_QUEUES_PER_NIC_PORT)) {
            return -3;
        }
        if (app.nic_tx_queue_mask[port][queue] != 0) {
            return -4;
        }
        app.nic_tx_queue_mask[port][queue] = 1;

        if (app.port_mask[port] == 0)
            app.port_mask[port] = 1;

        /* Check and assign (port, queue) to I/O lcore */
        if (rte_lcore_is_enabled(lcore) == 0) {
            return -5;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -6;
        }
        lp = &app.lcore_params[lcore];
        if (lp->type == e_LCORE_ADMIN
            || lp->type == e_LCORE_MISC || lp->type == e_LCORE_KNI) {
            return -7;
        }
        lp->type = e_LCORE_IO;
        for (i = 0; i < lp->io.n_tx_queues; i++) {
            if ((lp->io.tx_queues[i].port_id == port) &&
                (lp->io.tx_queues[i].queue_id == queue)) {
                return -8;
            }
        }
        if (lp->io.n_tx_queues >= MAX_NIC_TX_QUEUES_PER_IO_LCORE) {
            return -9;
        }
        lp->io.tx_queues[lp->io.n_tx_queues].port_id = (uint8_t) port;
        lp->io.tx_queues[lp->io.n_tx_queues].queue_id = (uint8_t) queue;
        lp->io.tx_port_queue[port] = queue;
        lp->io.n_tx_queues++;

        n_tuples++;
        if (n_tuples > ETH_TX_MAX_TUPLES) {
            return -10;
        }

        if (lcore > app.max_lcore) {
            app.max_lcore = lcore;
        }
    }

    if (n_tuples == 0) {
        return -11;
    }

    return 0;
}

#define KNI_LCORE_MAX_CHARS     4096
#define KNI_LCORE_MAX_TUPLES    128

static int parse_lcore_kni(const char *arg)
{
    const char *p0 = arg, *p = arg;
    uint32_t n_tuples;

    if (strnlen(arg, KNI_LCORE_MAX_CHARS + 1) == KNI_LCORE_MAX_CHARS + 1) {
        return -1;
    }

    n_tuples = 0;
    while ((p = strchr(p0, '(')) != NULL) {
        struct lcore_params *lp;
        uint32_t port, lcore, force_bind;

        p0 = strchr(p++, ')');
        /*
         * fill port kni lcore by (n1,n2,n3)
         * port=n1, lcore=n2, force_bind=n3
         */
        if ((p0 == NULL) ||
            (str_to_unsigned_vals(p, p0 - p, ',', 3, &port, &lcore, &force_bind) !=
             3)) {
            return -2;
        }

        /* Enable port and queue for later initialization */
        if ((port >= RTE_MAX_ETHPORTS)) {
            return -3;
        }

        if (app.port_mask[port] != 1) {
            return -4;
        }

        /* Check and assign (port, queue) to I/O lcore */
        if (rte_lcore_is_enabled(lcore) == 0) {
            return -5;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -6;
        }
        lp = &app.lcore_params[lcore];
        if (lp->type == e_LCORE_ADMIN || lp->type == e_LCORE_MISC
                || lp->type == e_LCORE_KNI || lp->type == e_LCORE_IO) {
            return -7;
        }
        kni_port_info[port].lcore_id = lcore;

        if (force_bind != 0 && force_bind != 1) {
            return -8;
        }
        kni_port_info[port].force_bind = force_bind;

        n_tuples++;
        if (n_tuples > KNI_LCORE_MAX_TUPLES) {
            return -9;
        }
    }

    if (n_tuples == 0) {
        return -10;
    }

    return 0;
}

#if 0
#define ARG_ADMIN_MAX_CHARS     4096
#define ARG_ADMIN_MAX_TUPLES    MAX_ADMIN_LCORES

static int parse_eth_admin(const char *arg)
{
    const char *p = arg;
    uint32_t n_tuples;

    if (strnlen(arg, ARG_ADMIN_MAX_CHARS + 1) == ARG_ADMIN_MAX_CHARS + 1) {
        return -1;
    }

    n_tuples = 0;
    while (*p != 0) {
        struct lcore_params *lp;
        uint32_t lcore;

        errno = 0;
        lcore = strtoul(p, NULL, 0);
        if ((errno != 0)) {
            return -2;
        }

        /* Check and enable worker lcore */
        if (rte_lcore_is_enabled(lcore) == 0) {
            return -3;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -4;
        }
        lp = &app.lcore_params[lcore];
        if (lp->type == e_LCORE_IO
            || lp->type == e_LCORE_MISC || lp->type == e_LCORE_KNI) {
            return -5;
        }
        lp->type = e_LCORE_ADMIN;

        if (lcore > app.max_lcore) {
            app.max_lcore = lcore;
        }

        n_tuples++;
        if (n_tuples > ARG_ADMIN_MAX_TUPLES) {
            return -6;
        }

        p = strchr(p, ',');
        if (p == NULL) {
            break;
        }
        p++;
    }

    if (n_tuples == 0) {
        return -7;
    }

    if ((n_tuples & (n_tuples - 1)) != 0) {
        return -8;
    }

    return 0;
}
#endif

#define ARG_MISC_MAX_CHARS     4096
#define ARG_MISC_MAX_TUPLES    MAX_MISC_LCORES

static int parse_eth_misc(const char *arg)
{
    const char *p = arg;
    uint32_t n_tuples;
    uint32_t port, queue;

    if (strnlen(arg, ARG_MISC_MAX_CHARS + 1) == ARG_MISC_MAX_CHARS + 1) {
        return -1;
    }

    n_tuples = 0;
    while (*p != 0) {
        struct lcore_params *lp;
        uint32_t lcore;

        errno = 0;
        lcore = strtoul(p, NULL, 0);
        if ((errno != 0)) {
            return -2;
        }

        /* Check and enable worker lcore */
        if (rte_lcore_is_enabled(lcore) == 0) {
            return -3;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -4;
        }
        lp = &app.lcore_params[lcore];
        if (lp->type == e_LCORE_IO
            || lp->type == e_LCORE_ADMIN || lp->type == e_LCORE_KNI) {
            return -5;
        }
        lp->type = e_LCORE_MISC;

        if (lcore > app.max_lcore) {
            app.max_lcore = lcore;
        }

        n_tuples++;
        if (n_tuples > ARG_MISC_MAX_TUPLES) {
            return -6;
        }

        p = strchr(p, ',');
        if (p == NULL) {
            break;
        }
        p++;
    }

    if (n_tuples == 0) {
        return -7;
    }

    if ((n_tuples & (n_tuples - 1)) != 0) {
        return -8;
    }

    /* misc lcore process nic queue 0 */
    queue = 0;
    for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
        if (app.port_mask[port] == 0)
            continue;

        if (app.nic_tx_queue_mask[port][queue] != 0) {
            return -9;
        }
        app.nic_tx_queue_mask[port][queue] = 1;
        app.nic_rx_queue_mask[port][queue] = 1;
    }

    return 0;
}

#define ARG_KNI_MAX_CHARS     4096
#define ARG_KNI_MAX_TUPLES    MAX_KNI_LCORES

static int parse_eth_kni(const char *arg)
{
    const char *p = arg;
    uint32_t n_tuples;

    if (strnlen(arg, ARG_KNI_MAX_CHARS + 1) == ARG_KNI_MAX_CHARS + 1) {
        return -1;
    }

    n_tuples = 0;
    while (*p != 0) {
        struct lcore_params *lp;
        uint32_t lcore;

        errno = 0;
        lcore = strtoul(p, NULL, 0);
        if ((errno != 0)) {
            return -2;
        }

        /* Check and enable worker lcore */
        if (rte_lcore_is_enabled(lcore) == 0) {
            return -3;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -4;
        }
        lp = &app.lcore_params[lcore];
        if (lp->type == e_LCORE_IO
            || lp->type == e_LCORE_MISC || lp->type == e_LCORE_ADMIN) {
            return -5;
        }
        lp->type = e_LCORE_KNI;

        if (lcore > app.max_lcore) {
            app.max_lcore = lcore;
        }

        n_tuples++;
        if (n_tuples > ARG_KNI_MAX_TUPLES) {
            return -6;
        }

        p = strchr(p, ',');
        if (p == NULL) {
            break;
        }
        p++;
    }

    if (n_tuples == 0) {
        return -7;
    }

    if ((n_tuples & (n_tuples - 1)) != 0) {
        return -8;
    }

    return 0;
}

//#define ARG_ATTACK_MAX_CHARS     4096
//#define ARG_ATTACK_MAX_TUPLES    MAX_ATTACK_LCORES
//
//static int parse_eth_wild_attack(const char *arg)
//{
//    const char *p = arg;
//    uint32_t n_tuples;
//
//    if (strnlen(arg, ARG_ATTACK_MAX_CHARS + 1) == ARG_ATTACK_MAX_CHARS + 1) {
//        return -1;
//    }
//
//    n_tuples = 0;
//    while (*p != 0) {
//        struct lcore_params *lp;
//        uint32_t lcore;
//
//        errno = 0;
//        lcore = strtoul(p, NULL, 0);
//        if ((errno != 0)) {
//            return -2;
//        }
//
//        /* Check and enable worker lcore */
//        if (rte_lcore_is_enabled(lcore) == 0) {
//            return -3;
//        }
//
//        if (lcore >= RTE_MAX_LCORE) {
//            return -4;
//        }
//        lp = &app.lcore_params[lcore];
//        if (lp->type == e_LCORE_IO
//            || lp->type == e_LCORE_ADMIN || lp->type == e_LCORE_KNI || lp->type == e_LCORE_MISC) {
//            return -5;
//        }
//        lp->type = e_LCORE_ATTACK;
//
//        n_tuples++;
//        if (n_tuples > ARG_ATTACK_MAX_TUPLES) {
//            return -6;
//        }
//
//        p = strchr(p, ',');
//        if (p == NULL) {
//            break;
//        }
//        p++;
//    }
//
//    if (n_tuples == 0) {
//        return -7;
//    }
//
//    if ((n_tuples & (n_tuples - 1)) != 0) {
//        return -8;
//    }
//
//    return 0;
//}

#define MAX_ALLOW_TCP_PORT            65535

static int check_port_range(const char *port_range)
{
    while (*port_range != '\0') {
        if (isdigit((int)*port_range) || isblank((int)*port_range) || *port_range == '-') {
            port_range ++;
        }
        else {
            return -1;
        }
    }
    return 0;
}

static int parse_allowed_tcp_port(char *arg)
{
    char *split[MAX_ALLOW_TCP_PORT_NUM] = {0};
    int arg_len;
    int n_token, n_port_range, i;
    uint32_t port, port_start, port_end;
    int index = 0;
    char *p = arg;

    if (arg == NULL) {
        return -1;
    }

    arg_len = (int)strnlen(arg, CFG_VALUE_LEN + 1);

    n_token = rte_strsplit(p, arg_len, split, MAX_ALLOW_TCP_PORT_NUM, ',');
    if (n_token < 0) {
        return -2;
    }

    for (i = 0; i < n_token; i ++) {
        char *port_range = split[i];
        if (port_range == NULL || check_port_range(port_range)) {
            continue;
        }
        char *port_tup[2];
        n_port_range = rte_strsplit(port_range, strlen(port_range), port_tup, 2, '-');
        if (n_port_range < 0) {
            return -3;
        }

        if (n_port_range == 1) {
            port = atoi(port_tup[0]);
            if (port == 0 || port > MAX_ALLOW_TCP_PORT) {
                return -4;
            }
            if (index + 1 >= MAX_ALLOW_TCP_PORT_NUM) {
                return -5;
            }
            app.allowed_tcp_port[index++] = (uint16_t)port;
        }
        else if (n_port_range == 2) {
            port_start = atoi(port_tup[0]);
            port_end = atoi(port_tup[1]);
            if ( (port_start == 0 || port_start > MAX_ALLOW_TCP_PORT) ||
                 (port_end == 0 || port_end > MAX_ALLOW_TCP_PORT)     ||
                 (port_end <= port_start) ) {
                return -4;
            }
            if (index + (port_end - port_start) + 1 >= MAX_ALLOW_TCP_PORT_NUM) {
                return -5;
            }

            for (port = port_start; port <= port_end; port ++) {
                app.allowed_tcp_port[index++] = (uint16_t)port;
            }

        }
        else {
            return -6;
        }
    }

    return 0;
}

static int get_rss_conf(char *protocol) {
    int i;
    int len = sizeof(rss_conf_maps)/sizeof(struct id_name_map);
    if (protocol == NULL) {
        return -1;
    }
    for (i = 0; i < len; i ++) {
        if (!strcasecmp(rss_conf_maps[i].name, protocol)) {
            return rss_conf_maps[i].id;
        }
    }
    return -1;
}

static int parse_rss_conf(char *arg)
{
    // port_conf.rx_adv_conf.rss_conf.rss_hf =  ETH_RSS_TCP | ETH_RSS_UDP
    char *splits[MAX_ALLOW_TCP_PORT_NUM] = {0};
    int proto;
    int n_token, i, num_splits = 0;

    if (arg == NULL) {
        return -1;
    }
    n_token = sizeof(rss_conf_maps)/sizeof(struct id_name_map);
    num_splits = rte_strsplit(arg, sizeof(arg), splits, n_token, ',');
    if (num_splits < 0) {
        return -2;
    }
    port_conf.rx_adv_conf.rss_conf.rss_hf = 0;
    for (i = 0; i < num_splits; i ++) {
        char *n_proto= splits[i];
        proto = get_rss_conf(n_proto);
        if (proto >= 0) {
            port_conf.rx_adv_conf.rss_conf.rss_hf |= proto;
            printf("%s add to rx_adv_conf\n", n_proto);
        } else {
            printf("%s is not allowed add to rx_adv_conf\n", n_proto==NULL?"null":n_proto);
        }
    }
    return 0;
}

static inline void set_vip_net(uint32_t *vips, uint32_t ip, uint8_t ipaddr_num,
        const char *vip_name) {
    vips[ipaddr_num] = ip;
    RTE_LOG(INFO, LDNS, "Set ipaddr_num %d of %s to %d.%d.%d.%d\n",
            ipaddr_num, vip_name, NIP_STR(ip));
}

static inline void set_vip6_net(uint8_t vips[][16], uint8_t ip6[16],
        uint8_t ipaddr_num, const char *vip_name) {
    rte_memcpy(vips[ipaddr_num], ip6, 16);
    RTE_LOG(INFO, LDNS, "Set ip6addr_num %d of %s to " NIP6_FMT "\n",
            ipaddr_num, vip_name, NIP6(ip6));
}

static int cfg_load_vip(struct cfg_file *cfg, const char *vip_name,
        const char *sec_name, uint32_t *vips) {
    char iname[20];
    const char *entry;
    int i;

    for (i = 0; i < VIP_IPADDR_NUM_MAX; i++) {
        /* load VIP addr */
        sprintf(iname, "%s_%d", vip_name, i);
        entry = cfg_get_entry(cfg, sec_name, iname);
        if (entry == NULL) {
            break;
        } else {
            struct in_addr s;
            if (inet_pton(AF_INET, entry, (void *) &s) <= 0) {
                printf("Failed to convert ip addr %s for %s in section %s\n",
                        entry, iname, sec_name);
                return -1;
            }
            set_vip_net(vips, s.s_addr, i, vip_name);
        }
    }

    return 0;
}

static int cfg_load_vip6(struct cfg_file *cfg, const char *vip_name,
        const char *sec_name, uint8_t vips[][16]) {
    char iname[20];
    const char *entry;
    int i;

    for (i = 0; i < VIP_IPADDR_NUM_MAX; i++) {
        /* load VIP addr */
        sprintf(iname, "%s_%d", vip_name, i);
        entry = cfg_get_entry(cfg, sec_name, iname);
        if (entry == NULL) {
            break;
        } else {
            uint8_t ip6_addr[16];
            if (inet_pton(AF_INET6, entry, (void *) ip6_addr) <= 0) {
                printf("Failed to convert ipv6 addr %s for %s in section %s\n",
                        entry, iname, sec_name);
                return -1;
            }
            set_vip6_net(vips, ip6_addr, i, vip_name);
        }
    }

    return 0;
}

/* load nic about configuration */
static int cfg_load_nic(struct cfg_file *cfg)
{
    int ret;
    const char *entry;
    char sec_name[CFG_NAME_LEN];
    uint32_t nic_rx = 0;        /* nic section must specify rx/tx entry */
    uint32_t nic_tx = 0;
    //uint32_t nic_admin = 0;
    uint32_t nic_misc = 0;
    uint32_t nic_kni = 0;

    snprintf(sec_name, sizeof(sec_name), "nic");

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    uint8_t i;

    uint32_t use_ports_mask = 0;
    entry = cfg_get_entry(cfg, sec_name, "use_ports_mask");
    if (entry == NULL) {
        printf("Cannot get use_ports_mask in section %s\n", sec_name);
        return -1;
    }

    use_ports_mask = atoi(entry);
    if (use_ports_mask == 0) {
        printf("use_ports_mask in section %s cannot be 0\n", sec_name);
        return -1;
    }

    /* load IP addr, IP addr netmask, Gateway IP addr, Gateway mac addr */
    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        printf("mask:%u,1<<i= %u,&=%u\n", use_ports_mask, 1 << i,
               use_ports_mask & (1 << i));
        if ((use_ports_mask & (1 << i)) == 0)
            continue;

        char iname[20];

        /* load IP addr */
        sprintf(iname, "port%d_ip", i);
        entry = cfg_get_entry(cfg, sec_name, iname);
        if (entry == NULL) {
            printf("Cannot get %s in section %s\n", iname, sec_name);
            return -1;
        }
        uint32_t port_ip = inet_addr(entry);
        set_port_ip_net(port_ip, i);

#ifdef __FDIR_DIP_ENABLE
        /* load vEth0 vEth1 addr */
        sprintf(iname, "vEth%d_ip", i);
        entry = cfg_get_entry(cfg, sec_name, iname);
        if (entry == NULL) {
            printf("Cannot get %s in section %s\n", iname, sec_name);
            return -1;
        }
        port_ip = inet_addr(entry);
        vport_ips[i] = port_ip;
        RTE_LOG(INFO, LDNS, "Set vEth%d ip to %d.%d.%d.%d\n", i, NIP_STR(port_ip));
#ifdef __IPV6_SUPPORT
        sprintf(iname, "ipv6_vEth%d_ip", i);
        entry = cfg_get_entry(cfg, sec_name, iname);
        if (entry == NULL) {
            printf("Cannot get %s in section %s\n", iname, sec_name);
            return -1;
        }
        struct in6_addr v6_addr;
        if (inet_pton(AF_INET6, entry, &v6_addr) == 1) {
        } else {
            printf("ipv6 addr format error!\n");
            return -1;
        }
        memcpy(ipv6_vport_ips[i], &v6_addr, sizeof(struct in6_addr));
        RTE_LOG(INFO, LDNS, "Set vEth%d ipv6 to %s\n", i, entry);
#endif // __IPV6_SUPPORT
#endif // __FDIR_DIP_ENABLE
    }

    if ((cfg_load_vip(cfg, "vip", sec_name, g_rec_vip) != 0)
            || (cfg_load_vip6(cfg, "vip6", sec_name, g_rec_vip6) != 0)
            || (cfg_load_vip(cfg, "vip_auth", sec_name, g_auth_vip) != 0)
            || (cfg_load_vip6(cfg, "vip6_auth", sec_name, g_auth_vip6) != 0)
            || (cfg_load_vip(cfg, "vip_sec", sec_name, g_sec_vip) != 0)
            || (cfg_load_vip6(cfg, "vip6_sec", sec_name, g_sec_vip6) != 0)) {
        return -1;
    }

    /* parse rx param, then fill configurature */
    entry = cfg_get_entry(cfg, sec_name, "rx");
    if (entry == NULL) {
        printf("Cannot get [%s]-%s configuration\n", sec_name, "rx");
        return -1;
    }

    printf("\nentry[rx]: === %s\n", entry);
    nic_rx = 1;
    ret = parse_eth_rx(entry);
    if (ret) {
        printf("Incorrect value for --rx argument (%d)\n", ret);
        return -1;
    }

    /* parse tx param, then fill configurature */
    entry = cfg_get_entry(cfg, sec_name, "tx");
    if (entry == NULL) {
        printf("Cannot get [%s]-%s configuration\n", sec_name, "tx");
        return -1;
    }

    printf("\nentry[tx]: === %s\n", entry);
    nic_tx = 1;
    ret = parse_eth_tx(entry);
    if (ret) {
        printf("Incorrect value for --tx argument (%d)\n", ret);
        return -1;
    }

    /* parse admin param, then fill configurature */
    /*entry = cfg_get_entry(cfg, sec_name, "admin");
    if (entry == NULL) {
        printf("Cannot get [%s]-%s configuration\n", sec_name, "admin");
        return -1;
    }

    printf("\nentry[admin]: === %s\n", entry);
    nic_admin = 1;
    ret = parse_eth_admin(entry);
    if (ret) {
        printf("Incorrect value for --admin argument (%d)\n", ret);
        return -1;
    }*/

    /* parse misc param, then fill configurature */
    entry = cfg_get_entry(cfg, sec_name, "misc");
    if (entry == NULL) {
        printf("Cannot get [%s]-%s configuration\n", sec_name, "misc");
        return -1;
    }

    printf("\nentry[misc]: === %s\n", entry);
    nic_misc = 1;
    ret = parse_eth_misc(entry);
    if (ret) {
        printf("Incorrect value for --misc argument (%d)\n", ret);
        return -1;
    }
    /* parse KNI param, then fill configurature */
    entry = cfg_get_entry(cfg, sec_name, "kni");
    if (entry == NULL) {
        printf("Cannot get [%s]-%s configuration\n", sec_name, "kni");
        return -1;
    }

    printf("\nentry[kni]: === %s\n", entry);
    nic_kni = 1;
    ret = parse_eth_kni(entry);
    if (ret) {
        printf("Incorrect value for --kni argument (%d)\n", ret);
        return -1;
    }

    /* Check that all mandatory arguments are provided */
    if ((nic_rx == 0) || (nic_tx == 0) || /*(nic_admin == 0) || */(nic_misc == 0)
        || (nic_kni == 0)) {
        printf("Not all mandatory arguments are present\n");
        return -1;
    }

    /* parse allow tcp port */
    entry = cfg_get_entry(cfg, sec_name, "tcp_port_allowed");
    ret = parse_allowed_tcp_port((char *)entry);
    if (ret) {
        printf("Cannot get tcp port allowd\n");
        return -1;
    }

    /* parse rss_port_conf param, then fill configuration */
    entry = cfg_get_entry(cfg, sec_name, "rss_port_conf");
    ret = parse_rss_conf((char *)entry);
    if (ret) {
        printf("Incorrect value for --rss_port_conf argument (%d)\n", ret);
        return -1;
    }

    /* parse lcore_kni param, then fill configuration */
    entry = cfg_get_entry(cfg, sec_name, "lcore_kni");
    if (entry == NULL) {
        printf("no %s configuration\n", "lcore_kni");
        return -1;
    } else {
        ret = parse_lcore_kni(entry);
        if (ret) {
            printf("Incorrect value for --lcore_kni argument (%d)\n", ret);
            return -1;
        }
    }

    return 0;
}

uint32_t ips[RTE_MAX_ETHPORTS] = { 0 };

#if 0
static int cfg_load_ipconfig(struct cfg_file *cfg)
{
    int i;
    char sec_name[CFG_NAME_LEN];
    const char *entry;
    char port_str[64];
    uint32_t tmp_ip;

    snprintf(sec_name, sizeof(sec_name), "ipconfig");
    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    /* conform again */
    memset(ips, 0, sizeof(uint32_t) * RTE_MAX_ETHPORTS);

    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        snprintf(port_str, 64, "%d", i);
        entry = cfg_get_entry(cfg, sec_name, port_str);
        if (entry == NULL) {
            continue;
        }

        /* convert address */
        tmp_ip = inet_addr(entry);
        ips[i] = rte_be_to_cpu_32(tmp_ip);
    }

    return 0;
}
#endif

/* Load server about configure, such as log setting, pid file, etc. */
char *ldns_log_path = NULL;
int ldns_log_level = LOG_INFO;
/* ip geo info file */
char *ipfile_path = NULL;

static int cfg_load_view_by_name(struct cfg_file *cfg, view_db_t *views,
        const char *name)
{
    int i, j, k;
    const char *entry;
    char sec_name[CFG_NAME_LEN];

    snprintf(sec_name, sizeof(sec_name), name);

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }
    i = 0;

    uint8_t fidx;
    char tmp_ip[IP_MAX_LEN + 1];
    char tmp_port[PORT_MAX_LEN + 1];
    char *sp1, *sp2, *sp3, *p;

    /* read the "default" forwarders */
    entry = cfg_get_entry(cfg, sec_name, view_id_to_name(i));
    if (!entry) {
        printf(
                "Error: Cannot get view (id=%d)%s's forwarder in section[%s]\n",
                i, view_id_to_name(i), sec_name);
        return -2;
    }
    /*
     * sp1=ip
     * sp2=port
     * sp3=separator
     */
    fidx = 0;
    sp1 = strdup(entry);
    p = sp1;
    while (sp1 && *sp1) {
        if (*sp1 == ' ' || *sp1 == '\r' || *sp1 == '\t') {
            sp1++;
            continue;
        }
        sp2 = strstr(sp1, ",");
        if (sp2 == NULL) {
            sp2 = sp1 + strlen(sp1);
        }
        sp3 = strstr(sp1, ":");
        if (sp3 == NULL) {
            break;
        }
        strncpy(tmp_ip, sp1, sp3 - sp1);
        tmp_ip[sp3 - sp1] = '\0';
        strncpy(tmp_port, sp3 + 1, sp2 - sp3);
        tmp_port[sp2 - sp3] = '\0';
        views->view_list[0].fip[fidx] = Lntohl(inet_addr(tmp_ip));
        views->view_list[0].fport[fidx] = atoi(tmp_port);
        for (j = 0; j < gio_count; j++) {
            if (forward_add_view(views, Lntohl(inet_addr(tmp_ip)), atoi(tmp_port), 0,
                    gio_id[j]) < 0) {
                return -3;
            }
        }
        set_bit(views->view_list[0].fbitmap, fidx);
        fidx++;
        if (*sp2 == '\0')
            break;
        sp1 = sp2 + 1;

    }
    if (p)
        free(p);
    if (fidx == 0) {
        printf("Cannot get view %s's forward in section[%s]\n",
                view_id_to_name(i), sec_name);
        return -3;
    }
    views->view_list[0].fnums = fidx;

    /* read the view specified forwarders */
    uint32_t tmp_ip_addr;
    uint32_t tmp_port_num;
    adns_viewid_t tmp_view;
    entry = cfg_get_entry(cfg, sec_name, "forwarders");
    if (!entry) {
        printf("Warning: Cannot get view specified forwarders in section[%s]\n",
                sec_name);
        //return -4;
    } else {
        /*
         * sp1=ip
         * sp2=port
         * sp3=separator
         */
        sp1 = strdup(entry);
        p = sp1;
        while (sp1 && *sp1) {
            if (*sp1 == ' ' || *sp1 == '\r' || *sp1 == '\t') {
                sp1++;
                continue;
            }
            sp2 = strstr(sp1, ",");
            if (sp2 == NULL) {
                sp2 = sp1 + strlen(sp1);
            }
            sp3 = strstr(sp1, ":");
            if (sp3 == NULL) {
                break;
            }
            strncpy(tmp_ip, sp1, sp3 - sp1);
            tmp_ip[sp3 - sp1] = '\0';
            strncpy(tmp_port, sp3 + 1, sp2 - sp3);
            tmp_port[sp2 - sp3] = '\0';
            tmp_ip_addr = Lntohl(inet_addr(tmp_ip));
            tmp_port_num = atoi(tmp_port);
            tmp_view = ip_bitmap_get(tmp_ip_addr, 0);
            views->view_list[tmp_view].fip[views->view_list[tmp_view].fnums] = tmp_ip_addr;
            views->view_list[tmp_view].fport[views->view_list[tmp_view].fnums] = tmp_port_num;

            for (j = 0; j < gio_count; j++) {
                if (forward_add_view(views, tmp_ip_addr, tmp_port_num, tmp_view,
                        gio_id[j]) < 0) {
                    return -4;
                }
            }
            set_bit(views->view_list[tmp_view].fbitmap, views->view_list[tmp_view].fnums);
            views->view_list[tmp_view].fnums++;
            if (*sp2 == '\0')
                break;
            sp1 = sp2 + 1;
        }
        if (p)
            free(p);
    }

    /*set up backup view for each view */
    views->view_list[0].backup_id = 0;
    for (i = 1; i < g_view_nums; i++) {
        char tname[FILE_PATH_MAX];
        char bkup[FILE_PATH_MAX];
        memset(bkup, 0, sizeof(bkup));
        int bid = -1;
        sprintf(tname, "%s__backup", view_id_to_name(i));
        entry = cfg_get_entry(cfg, sec_name, tname);
        if (entry == NULL)
            strcpy(bkup, "default");
        else {
            if (strlen(entry) >= VIEW_NAME_MAX) {
                printf("Error,view backup name %s len %lu bigger than %d\n",
                        entry, strlen(entry), VIEW_NAME_MAX);
            }
            strcpy(bkup, entry);
        }
        for (k = 0; k < g_view_nums; k++) {
            if (strcasecmp(bkup, view_id_to_name(k)) == 0) {
                bid = k;
                break;
            }
        }

        if (bid == -1) {
            printf(
                    "Error,the view %s backup view is %s,but cannot find the backup view",
                    view_id_to_name(i), entry);
            return -5;
        }
        views->view_list[i].backup_id = bid;
        if (views->view_list[i].fnums == 0) {
            if (bid != 0 && views->view_list[bid].fnums != 0) {
                for (j = 0; j < views->view_list[bid].fnums; j++) {
                    views->view_list[i].fip[j] = views->view_list[bid].fip[j];
                    views->view_list[i].fport[j] = views->view_list[bid].fport[j];

                    for (k = 0; k < gio_count; k++) {
                        if (forward_add_view(views, views->view_list[i].fip[j],
                                views->view_list[i].fport[j], i, gio_id[k]) < 0) {
                            return -6;
                        }
                    }
                    set_bit(views->view_list[i].fbitmap, views->view_list[i].fnums);
                    views->view_list[i].fnums++;
                }
            } else {
                printf(
                        "Warning:Cannot get view (id=%d)%s's forwarder, so set it to down!\n",
                        i, view_id_to_name(i));
                for (j = 0; j < gio_count; j++) {
                    set_bit(views->vstate_bitmap[gio_id[j]], i);
                    views->view_list[i].state = DOWN;
                }
            }
        }
    }
    printf("==========BEGIN SHOW VIEW===============");
    show_all_view(views);
    printf("fwder L2DNS count %d\n", g_fwder_mgr[gio_id[0]].nums);
    printf("==========END SHOW VIEW===============");
    /*no need to initialize to 0 for global variable
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        set_all_bit(views->vstate_bitmap[lcore_id], 0,
                sizeof(views->vstate_bitmap[lcore_id]));
    }
    */

    return 0;
}

static int cfg_load_view(struct cfg_file *cfg) {
    int ret;

    ret = cfg_load_view_by_name(cfg, g_recs_views, "recs_view");
    if (ret < 0) {
        return ret;
    }

    ret = cfg_load_view_by_name(cfg, g_auth_views, "auth_view");
    if (ret < 0) {
        return ret;
    }

    return cfg_load_view_by_name(cfg, g_backup_views, "backup_view");
}

static int cfg_load_system(struct cfg_file *cfg)
{
    const char *entry;
    char sec_name[CFG_NAME_LEN];
    char temp_name[CFG_NAME_LEN];

    snprintf(sec_name, sizeof(sec_name), "system");

    int forwarder_retry = 1;    //total 2
    int forwarder_retry_interval = 2;   //total 3
    int timer_exec_interval = 20;   //20us
    int ttl_expire_clean_exec_interval = 30;    // 30us
    int ttl_expire_clean_hash_size = 50;    //50 buckets
    uint32_t lcore_node_max = (1 << 22);    //400w
    uint32_t view_hash_table_size = (1 << 19);  //50w
    int edns_on = 0;
    int httpdns_on = 0;
    int forwarder_fail_down = 10;
    int forwarder_up_after_down = 120;  // 2 min
    int charge_file_interval = 5;   //5s 
    char *bind_addr = "127.0.0.1";
    uint16_t bind_port = 6666;
    char *query_log_level = "error";
    char *server_log_level = "error";
    char *answer_log_level = "error";
    char *attack_log_level = "error";
    char *secure_log_level = "error";
    char *log_path = "/var/log/";
    char *snapshot_path = "/work/dpdk_fwrd/data/";
    int whitelist_on = 0;
    int blacklist_on = 0;
    int man_whitelist_on = 0;
    int man_blacklist_on = 0;
    int oversealist_on = 0;
    int share_lcore_data_on = 0;
    int view_nodes_ttl_threshold = 10000;
    int obj_ratio_num = 0;
    uint32_t sum;
    int i;
    uint32_t src_len_max_num[MAX_SOURCE_LEN_TYPE_NUM];

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s],will use default config\n", sec_name);
    } else {
        entry = cfg_get_entry(cfg, sec_name, "forwarder_retry");
        if (entry != NULL) {
            forwarder_retry = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "forwarder_retry_interval");
        if (entry != NULL) {
            forwarder_retry_interval = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "charge_file_interval");
        if (entry != NULL) {
            charge_file_interval = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "timer_exec_interval");
        if (entry != NULL) {
            timer_exec_interval = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "ttl_expire_clean_exec_interval");
        if (entry != NULL) {
            ttl_expire_clean_exec_interval = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "ttl_expire_clean_hash_size");
        if (entry != NULL) {
            ttl_expire_clean_hash_size = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "lcore_node_max");
        if (entry != NULL) {
            lcore_node_max = atoi(entry);
        }
        for (obj_ratio_num = 0; obj_ratio_num < DVAL_KEN_TYPE_NUM; obj_ratio_num ++) {
            entry = cfg_get_entry(cfg, sec_name, g_obj_name[obj_ratio_num]);
            if (entry != NULL) {
                g_dval_obj_ratio[obj_ratio_num]= atoi(entry);
            }
        }
        entry = cfg_get_entry(cfg, sec_name, "view_hash_table_size");
        if (entry != NULL) {
            view_hash_table_size = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "edns_on");
        if (entry != NULL) {
            edns_on = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "httpdns_on");
        if (entry != NULL) {
            httpdns_on = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "whitelist_on");
        if (entry != NULL) {
            whitelist_on = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "blacklist_on");
        if (entry != NULL) {
            blacklist_on = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "man_whitelist_on");
        if (entry != NULL) {
            man_whitelist_on = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "man_blacklist_on");
        if (entry != NULL) {
            man_blacklist_on = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "oversealist_on");
        if (entry != NULL) {
            oversealist_on = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name,"share_lcore_data_on");
        if(entry != NULL){
            share_lcore_data_on = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "kni_qps_limit_on");
        if (entry != NULL) {
            g_fwd_qps_limit_on[OTHER_QPSLIMIT_ID] = atoi(entry);
            if (g_fwd_qps_limit_on[OTHER_QPSLIMIT_ID]) {
                g_kni_qps_limit_on_status |= (1 << OTHER_QPSLIMIT_ID);
            }
        }

        entry = cfg_get_entry(cfg, sec_name, "kni_qps_limit");
        if (entry != NULL) {
            g_fwd_qps_quota[OTHER_QPSLIMIT_ID] = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "kni_doh_qps_limit_on");
        if (entry != NULL) {
            g_fwd_qps_limit_on[DOH_QPSLIMIT_ID] = atoi(entry);
            if (g_fwd_qps_limit_on[DOH_QPSLIMIT_ID]) {
                g_kni_qps_limit_on_status |= (1 << DOH_QPSLIMIT_ID);
            }
        }

        entry = cfg_get_entry(cfg, sec_name, "kni_doh_qps_limit");
        if (entry != NULL) {
            g_fwd_qps_quota[DOH_QPSLIMIT_ID] = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "kni_dot_qps_limit_on");
        if (entry != NULL) {
            g_fwd_qps_limit_on[DOT_QPSLIMIT_ID] = atoi(entry);
            if (g_fwd_qps_limit_on[DOT_QPSLIMIT_ID]) {
                g_kni_qps_limit_on_status |= (1 << DOT_QPSLIMIT_ID);
            }
        }

        entry = cfg_get_entry(cfg, sec_name, "kni_dot_qps_limit");
        if (entry != NULL) {
            g_fwd_qps_quota[DOT_QPSLIMIT_ID] = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "kni_ip_qps_limit_on");
        if (entry != NULL) {
            g_fwd_qps_limit_on[IP_QPSLIMIT_ID] = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "kni_ip_qps_limit");
        if (entry != NULL) {
            g_fwd_qps_quota[IP_QPSLIMIT_ID] = atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "fwd_qps_limit_on");
		if (entry != NULL) {
			g_fwd_qps_limit_on[FWD_QPSLIMIT_ID] = atoi(entry);
		}

		entry = cfg_get_entry(cfg, sec_name, "fwd_qps_limit");
		if (entry != NULL) {
			g_fwd_qps_quota[FWD_QPSLIMIT_ID] = atoi(entry);
		}

        sum = 0;
		for (i = 0; i < MAX_SOURCE_LEN_TYPE_NUM; ++i) {
			snprintf(temp_name, sizeof(temp_name), "cache_src_len_%u",
					g_src_len_max_lens[i]);
			entry = cfg_get_entry(cfg, sec_name, temp_name);
			if (entry == NULL) {
				src_len_max_num[i] = 0;
			} else {
				src_len_max_num[i] = (uint32_t) atoi(entry);
			}
			printf("section[%s]: cache_src_len_%u = %u\n", sec_name, i,
					src_len_max_num[i]);
			sum += src_len_max_num[i];
		}

		if (sum != 0) {
			rte_memcpy(g_src_len_max_num, src_len_max_num,
					sizeof(src_len_max_num));
			g_dnscache_max_num = sum;
		}

        init_qtype_view_fwd();
        entry = cfg_get_entry(cfg, sec_name,"clean_view_fwd_qtype");
        if(entry != NULL){
            char *clean_view_fwd = strdup(entry);
            if(clean_view_fwd){
                char *cur = clean_view_fwd;
                while(cur != NULL){
                    char *p = strstr(cur,",");
                    if(p != NULL){
                        char tmp[20];
                        memset(tmp,0,sizeof(tmp));
                        strncpy(tmp,cur,p - cur);
                        int qtype = atoi(tmp);
                        if(qtype < 0 || qtype >= QTYPE_MAX_H){
                            printf("clean_view_fwd_qtype config error, <0 || > %d\n",QTYPE_MAX_H);
                            return -1;
                        }
                        clean_qtype_view_fwd(qtype);
                        cur = p + 1;
                    }else{
                        int qtype = atoi(cur);    
                        if(qtype < 0 || qtype >= QTYPE_MAX_H){
                            printf("clean_view_fwd_qtype config error, <0 || > %d\n",QTYPE_MAX_H);
                            return -1;
                        }
                        clean_qtype_view_fwd(qtype);
                        break;
                    }
                }        
            }
        }

        entry = cfg_get_entry(cfg, sec_name, "view_nodes_ttl_threshold");
        if (entry != NULL) {
            view_nodes_ttl_threshold = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "forwarder_fail_down");
        if (entry != NULL) {
            forwarder_fail_down = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "forwarder_up_after_down");
        if (entry != NULL) {
            forwarder_up_after_down = atoi(entry);
        }
        entry = cfg_get_entry(cfg, sec_name, "bind_addr");
        if (entry != NULL) {
            bind_addr = strdup(entry);
        }
        assert(bind_addr);

        entry = cfg_get_entry(cfg, sec_name, "bind_port");
        if (entry != NULL) {
            bind_port = (uint16_t) atoi(entry);
        }

        entry = cfg_get_entry(cfg, sec_name, "query_log_level");
        if (entry != NULL) {
            query_log_level = strdup(entry);
        }
        assert(query_log_level);

        entry = cfg_get_entry(cfg, sec_name, "answer_log_level");
        if (entry != NULL) {
            answer_log_level = strdup(entry);
        }
        assert(answer_log_level);
        entry = cfg_get_entry(cfg, sec_name, "server_log_level");
        if (entry != NULL) {
            server_log_level = strdup(entry);
        }
        assert(server_log_level);
        entry = cfg_get_entry(cfg, sec_name, "attack_log_level");
        if (entry != NULL) {
            attack_log_level = strdup(entry);
        }
        assert(attack_log_level);
		entry = cfg_get_entry(cfg, sec_name, "secure_log_level");
		if (entry != NULL) {
			secure_log_level = strdup(entry);
		}
		assert(secure_log_level);
        entry = cfg_get_entry(cfg, sec_name, "log_path");
        if (entry != NULL) {
            log_path = strdup(entry);
        }
        assert(log_path);
        entry = cfg_get_entry(cfg, sec_name, "snapshot_path");
        if (entry != NULL) {
            snapshot_path = strdup(entry);
        }
        assert(snapshot_path);
		entry = cfg_get_entry(cfg, sec_name, "fwd_user_max_num");
		if (entry != NULL) {
			g_fwd_user_max_num = atoi(entry);
		}
		entry = cfg_get_entry(cfg, sec_name, "ip_user_max_num");
		if (entry != NULL) {
			g_ip_user_max_num = atoi(entry);
		}
    }

    set_forwarder_retry(forwarder_retry);
    set_forwarder_retry_interval(forwarder_retry_interval);
    set_charge_file_interval(charge_file_interval);
    set_timer_exec_interval(timer_exec_interval);
    set_ttl_expire_clean_exec_interval(ttl_expire_clean_exec_interval);
    set_ttl_expire_clean_hash_size(ttl_expire_clean_hash_size);
    set_lcore_node_max(lcore_node_max);
    set_view_hash_table_size(view_hash_table_size);
    set_edns_on(edns_on);
    set_httpdns_on(httpdns_on);
    set_white_state(whitelist_on);
    set_black_state(blacklist_on);
    set_man_white_state(man_whitelist_on);
    set_man_black_state(man_blacklist_on);
    set_oversea_state(oversealist_on);
    set_share_lcore_data(share_lcore_data_on);
    set_forwarder_fail_down(forwarder_fail_down);
    set_forwarder_up_after_down(forwarder_up_after_down);
    if (view_nodes_ttl_threshold < 0 || view_nodes_ttl_threshold > MVNODES) {
        printf("set view_nodes_ttl_threshold to %d fail,must >= 0 && <= %d\n",
               view_nodes_ttl_threshold, MVNODES);
        goto free;
    }
    set_view_nodes_ttl_threshold(view_nodes_ttl_threshold);
    set_bind_addr(bind_addr);
    set_bind_port(bind_port);

    char buf[100];
    memset(buf, 0, sizeof(buf));

    for (i = 0; i < LOG_LEVEL_NUM; i++) {
        strcat(buf, log_level_str[i]);
        strcat(buf, ",");
    }

    if (set_log_level(log_type_str[LOG_SERVER], server_log_level) < 0) {
        printf("Set log %s to level %s fail,level must be %s\n",
                log_type_str[LOG_SERVER], server_log_level, buf);
        goto free;
    }
    if (set_log_level(log_type_str[LOG_QUERY], query_log_level) < 0) {
        printf("Set log %s to level %s fail,level must be %s\n",
                log_type_str[LOG_QUERY], query_log_level, buf);
        goto free;
    }
    if (set_log_level(log_type_str[LOG_ANSWER], answer_log_level) < 0) {
        printf("Set log %s to level %s fail,level must be %s\n",
                log_type_str[LOG_ANSWER], answer_log_level, buf);
        goto free;
    }
	if (set_log_level(log_type_str[LOG_SECURE], answer_log_level) < 0) {
		printf("Set log %s to level %s fail,level must be %s\n",
				log_type_str[LOG_SECURE], answer_log_level, buf);
		goto free;
	}
	if (set_log_level(log_type_str[LOG_SECURE], secure_log_level) < 0) {
		printf("Set log %s to level %s fail,level must be %s\n",
				log_type_str[LOG_SECURE], secure_log_level, buf);
		goto free;
	}
    set_log_path(log_path);
    set_snapshot_path(snapshot_path);
    admin.bind_addr = bind_addr;
    admin.bind_port = bind_port;
    return 0;

free:
    free(bind_addr);
    free(query_log_level);
    free(answer_log_level);
    free(server_log_level);
    free(attack_log_level);
    free(log_path);
    free(snapshot_path);
    return -1;
}

static void app_assign_io_ids(void)
{
    uint32_t lcore, io_id;

    /* Assign ID for each ioer */
    io_id = 0;
    gio_count = 0;
    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        struct lcore_params_io *lp_io = &app.lcore_params[lcore].io;
        if (app.lcore_params[lcore].type != e_LCORE_IO) {
            continue;
        }
        lp_io->io_id = io_id;
        io_id++;

        gio_id[gio_count++] = lcore;
    }
}

/* load configuration profile */
static int app_load_cfg_profile(void)
{
    struct cfg_file *cfg_file;

    RTE_LOG(INFO, LDNS, "start app_load_cfg_profile\n");
    if (cfg_profile == NULL) {
        RTE_LOG(ERR, LDNS, "No configuration profile\n");
        return -1;
    }

    cfg_file = cfg_load(cfg_profile, 0);
    if (cfg_file == NULL) {
        RTE_LOG(ERR, LDNS, "Cannot load configuration profile %s\n",
                cfg_profile);
        return -2;
    }

    /* for nic */
    if (cfg_load_nic(cfg_file) < 0) {
        RTE_LOG(ERR, LDNS, "Failed to load section[%s] in %s\n", "NIC",
                cfg_profile);
        return -3;
    }

    app_assign_io_ids();

    /* for server */
    if (cfg_load_system(cfg_file) < 0) {
        RTE_LOG(ERR, LDNS, "Failed to load section[%s] in %s\n", "SYSTEM",
                cfg_profile);
        return -6;
    }

    /*for view */
    if (cfg_load_view(cfg_file) < 0) {
        RTE_LOG(ERR, LDNS, "Failed to load section[%s] in %s\n", "VIEW",
                cfg_profile);
        return -7;
    }
    cfg_close(cfg_file);

    return 0;
}

static void app_io_misc_init(void)
{
    uint32_t lcore;

    /* Assign ID for each ioer */
    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        if (app.lcore_params[lcore].type == e_LCORE_IO) {
            lcore_misc_init(lcore);
        }
    }
}

static int app_init_mbuf_pools(void)
{
    unsigned socket, lcore;

    /* Create the mbuf pool */
    kni_pktmbuf_pool = rte_pktmbuf_pool_create("kni_mbuf_pool",
            KNI_NB_MBUF,
            KNI_MEMPOOL_CACHE_SZ, 0,
            KNI_MBUF_SZ, rte_socket_id());
    if (kni_pktmbuf_pool == NULL) {
        RTE_LOG(ERR, LDNS, "Could not initialise mbuf pool");
        return -1;
    }

    /* Init the buffer pools */
    for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
        char name[32];
        if (is_socket_used(socket) == 0) {
            continue;
        }

        snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
        RTE_LOG(ERR, LDNS, "Creating the mbuf pool for socket %u ...\n",
                socket);
        app.pools[socket] = rte_pktmbuf_pool_create(name,
                DEFAULT_MEMPOOL_BUFFERS,
                DEFAULT_MEMPOOL_CACHE_SIZE, 0,
                DEFAULT_MBUF_SIZE, rte_socket_id());
        if (app.pools[socket] == NULL) {
            RTE_LOG(ERR, LDNS, "Cannot create mbuf pool on socket %u\n", socket);
            return -1;
        }
    }

    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        if (app.lcore_params[lcore].type == e_LCORE_DISABLED) {
            continue;
        }
        socket = rte_lcore_to_socket_id(lcore);
        if (app.lcore_params[lcore].type == e_LCORE_KNI) {
            app.lcore_params[lcore].pool = kni_pktmbuf_pool;
            continue;
        }
        app.lcore_params[lcore].pool = app.pools[socket];
    }

    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100      /* 100ms */
#define MAX_CHECK_TIME 90       /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;
    uint32_t n_rx_queues, n_tx_queues;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if ((port_mask & (1 << portid)) == 0)
                continue;
            n_rx_queues = get_nic_rx_queues_per_port(portid);
            n_tx_queues = get_nic_tx_queues_per_port(portid);
            if ((n_rx_queues == 0) && (n_tx_queues == 0))
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                           "Mbps - %s\n", (uint8_t) portid,
                           (unsigned)link.link_speed,
                           (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                           ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n", (uint8_t) portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == 0) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}

static void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
    printf("%s%02X:%02X:%02X:%02X:%02X:%02X", name,
           eth_addr->addr_bytes[0],
           eth_addr->addr_bytes[1],
           eth_addr->addr_bytes[2],
           eth_addr->addr_bytes[3],
           eth_addr->addr_bytes[4], eth_addr->addr_bytes[5]);
}

static void gen_reta_conf(
          uint16_t nb_rx_queue,
          struct rte_eth_rss_reta_entry64 *reta_conf,
          uint16_t reta_size)
{
    uint16_t hash_index, idx = 0, shift = 0;
    uint8_t queue_idx = 1;

    /* Populate rss redirection table.
     * skip queue 0, to let traffic that unmatch RSS filter
     * (like ICMP, ARP, OSPF) goes into queue 0 */
    for (hash_index = 0; hash_index < reta_size; hash_index++) {
        if (queue_idx >= nb_rx_queue) {
            queue_idx = 1; /* queue_idx goes around back to 1 */
        }

        idx = hash_index / RTE_RETA_GROUP_SIZE;
        shift = hash_index % RTE_RETA_GROUP_SIZE;
        reta_conf[idx].mask |= (1ULL << shift);
        reta_conf[idx].reta[shift] = queue_idx;

        queue_idx++;
    }
    return;
}

static char *
flowtype_to_str(uint16_t flow_type)
{
    struct flow_type_info {
        char str[32];
        uint16_t ftype;
    };

    uint8_t i;
    static struct flow_type_info flowtype_str_table[] = {
        {"raw", RTE_ETH_FLOW_RAW},
        {"ipv4", RTE_ETH_FLOW_IPV4},
        {"ipv4-frag", RTE_ETH_FLOW_FRAG_IPV4},
        {"ipv4-tcp", RTE_ETH_FLOW_NONFRAG_IPV4_TCP},
        {"ipv4-udp", RTE_ETH_FLOW_NONFRAG_IPV4_UDP},
        {"ipv4-sctp", RTE_ETH_FLOW_NONFRAG_IPV4_SCTP},
        {"ipv4-other", RTE_ETH_FLOW_NONFRAG_IPV4_OTHER},
        {"ipv6", RTE_ETH_FLOW_IPV6},
        {"ipv6-frag", RTE_ETH_FLOW_FRAG_IPV6},
        {"ipv6-tcp", RTE_ETH_FLOW_NONFRAG_IPV6_TCP},
        {"ipv6-udp", RTE_ETH_FLOW_NONFRAG_IPV6_UDP},
        {"ipv6-sctp", RTE_ETH_FLOW_NONFRAG_IPV6_SCTP},
        {"ipv6-other", RTE_ETH_FLOW_NONFRAG_IPV6_OTHER},
        {"l2_payload", RTE_ETH_FLOW_L2_PAYLOAD},
    };

    for (i = 0; i < RTE_DIM(flowtype_str_table); i++) {
        if (flowtype_str_table[i].ftype == flow_type)
            return flowtype_str_table[i].str;
    }

    return NULL;
}


static int adns_port_rss_config(int port_id, int nb_rx_queue)
{
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rss_reta_entry64 reta_conf[16];

    /* get reta size */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    if (dev_info.reta_size == 0) {
        RTE_LOG(ERR, LDNS, "Redirection table size is 0 which is invalid for RSS\n");
        return -1;
    } else if (dev_info.reta_size > ETH_RSS_RETA_SIZE_512) {
        RTE_LOG(ERR, LDNS, "Currently do not support more than %u entries of "
            "redirection table\n", ETH_RSS_RETA_SIZE_512);
        return -2;
    } else {
        RTE_LOG(ERR, LDNS, "The reta size of port %d is %u\n", port_id, dev_info.reta_size);
    }

    gen_reta_conf(nb_rx_queue, reta_conf, dev_info.reta_size);
    ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, dev_info.reta_size);
    if (ret != 0) {
        RTE_LOG(ERR, LDNS, "Bad redirection table parameter, return code = %d \n", ret);
        return -3;
    }
    return 0;
}

static inline void
print_fdir_mask(struct rte_eth_fdir_masks *mask)
{
    printf("\n    vlan_tci: 0x%04x, ", mask->vlan_tci_mask);

    if (port_conf.fdir_conf.mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN)
        printf("mac_addr: 0x%02x", mask->mac_addr_byte_mask);
    else if (port_conf.fdir_conf.mode == RTE_FDIR_MODE_PERFECT_TUNNEL)
        printf("mac_addr: 0x%02x, tunnel_type: 0x%01x, tunnel_id: 0x%08x",
            mask->mac_addr_byte_mask, mask->tunnel_type_mask,
            mask->tunnel_id_mask);
    else {
        printf("src_ipv4: 0x%08x, dst_ipv4: 0x%08x,"
            " src_port: 0x%04x, dst_port: 0x%04x",
            mask->ipv4_mask.src_ip, mask->ipv4_mask.dst_ip,
            mask->src_port_mask, mask->dst_port_mask);

        printf("\n    src_ipv6: 0x%08x,0x%08x,0x%08x,0x%08x,"
            " dst_ipv6: 0x%08x,0x%08x,0x%08x,0x%08x",
            mask->ipv6_mask.src_ip[0], mask->ipv6_mask.src_ip[1],
            mask->ipv6_mask.src_ip[2], mask->ipv6_mask.src_ip[3],
            mask->ipv6_mask.dst_ip[0], mask->ipv6_mask.dst_ip[1],
            mask->ipv6_mask.dst_ip[2], mask->ipv6_mask.dst_ip[3]);
    }

    printf("\n");
}

static inline void
print_fdir_flex_payload(struct rte_eth_fdir_flex_conf *flex_conf, uint32_t num)
{
    struct rte_eth_flex_payload_cfg *cfg;
    uint32_t i, j;

    for (i = 0; i < flex_conf->nb_payloads; i++) {
        cfg = &flex_conf->flex_set[i];
        if (cfg->type == RTE_ETH_RAW_PAYLOAD)
            printf("\n    RAW:  ");
        else if (cfg->type == RTE_ETH_L2_PAYLOAD)
            printf("\n    L2_PAYLOAD:  ");
        else if (cfg->type == RTE_ETH_L3_PAYLOAD)
            printf("\n    L3_PAYLOAD:  ");
        else if (cfg->type == RTE_ETH_L4_PAYLOAD)
            printf("\n    L4_PAYLOAD:  ");
        else
            printf("\n    UNKNOWN PAYLOAD(%u):  ", cfg->type);
        for (j = 0; j < num; j++)
            printf("  %-5u", cfg->src_offset[j]);
    }
    printf("\n");
}

static inline void
print_fdir_flex_mask(struct rte_eth_fdir_flex_conf *flex_conf, uint32_t num)
{
    struct rte_eth_fdir_flex_mask *mask;
    uint32_t i, j;
    char *p;

    for (i = 0; i < flex_conf->nb_flexmasks; i++) {
        mask = &flex_conf->flex_mask[i];
        p = flowtype_to_str(mask->flow_type);
        printf("\n    %s:\t", p ? p : "unknown");
        for (j = 0; j < num; j++)
            printf(" %02x", mask->mask[j]);
    }
    printf("\n");
}

static inline void
print_fdir_flow_type(uint32_t flow_types_mask)
{
    int i;
    char *p;

    for (i = RTE_ETH_FLOW_UNKNOWN; i < RTE_ETH_FLOW_MAX; i++) {
        if (!(flow_types_mask & (1 << i)))
            continue;
        p = flowtype_to_str(i);
        if (p)
            printf(" %s", p);
        else
            printf(" unknown");
    }
    printf("\n");
}

void
fdir_get_infos(int port_id)
{
    struct rte_eth_fdir_stats fdir_stat;
    struct rte_eth_fdir_info fdir_info;
    int ret;

    static const char *fdir_stats_border = "########################";

    ret = rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_FDIR);
    if (ret < 0) {
        printf("\n FDIR is not supported on port %-2d\n",
            port_id);
        return;
    }

    memset(&fdir_info, 0, sizeof(fdir_info));
    rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
                   RTE_ETH_FILTER_INFO, &fdir_info);
    memset(&fdir_stat, 0, sizeof(fdir_stat));
    rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR,
                   RTE_ETH_FILTER_STATS, &fdir_stat);
    printf("\n  %s FDIR infos for port %-2d     %s\n",
           fdir_stats_border, port_id, fdir_stats_border);
    printf("  MODE: ");
    if (fdir_info.mode == RTE_FDIR_MODE_PERFECT)
        printf("  PERFECT\n");
    else if (fdir_info.mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN)
        printf("  PERFECT-MAC-VLAN\n");
    else if (fdir_info.mode == RTE_FDIR_MODE_PERFECT_TUNNEL)
        printf("  PERFECT-TUNNEL\n");
    else if (fdir_info.mode == RTE_FDIR_MODE_SIGNATURE)
        printf("  SIGNATURE\n");
    else
        printf("  DISABLE\n");
    if (fdir_info.mode != RTE_FDIR_MODE_PERFECT_MAC_VLAN
        && fdir_info.mode != RTE_FDIR_MODE_PERFECT_TUNNEL) {
        printf("  SUPPORTED FLOW TYPE: ");
        print_fdir_flow_type(fdir_info.flow_types_mask[0]);
    }
    printf("  FLEX PAYLOAD INFO:\n");
    printf("  max_len:       %-10"PRIu32"  payload_limit: %-10"PRIu32"\n"
           "  payload_unit:  %-10"PRIu32"  payload_seg:   %-10"PRIu32"\n"
           "  bitmask_unit:  %-10"PRIu32"  bitmask_num:   %-10"PRIu32"\n",
        fdir_info.max_flexpayload, fdir_info.flex_payload_limit,
        fdir_info.flex_payload_unit,
        fdir_info.max_flex_payload_segment_num,
        fdir_info.flex_bitmask_unit, fdir_info.max_flex_bitmask_num);
    printf("  MASK: ");
    print_fdir_mask(&fdir_info.mask);
    if (fdir_info.flex_conf.nb_payloads > 0) {
        printf("  FLEX PAYLOAD SRC OFFSET:");
        print_fdir_flex_payload(&fdir_info.flex_conf, fdir_info.max_flexpayload);
    }
    if (fdir_info.flex_conf.nb_flexmasks > 0) {
        printf("  FLEX MASK CFG:");
        print_fdir_flex_mask(&fdir_info.flex_conf, fdir_info.max_flexpayload);
    }
    printf("  guarant_count: %-10"PRIu32"  best_count:    %"PRIu32"\n",
           fdir_stat.guarant_cnt, fdir_stat.best_cnt);
    printf("  guarant_space: %-10"PRIu32"  best_space:    %"PRIu32"\n",
           fdir_info.guarant_spc, fdir_info.best_spc);
    printf("  collision:     %-10"PRIu32"  free:          %"PRIu32"\n"
           "  maxhash:       %-10"PRIu32"  maxlen:        %"PRIu32"\n"
           "  add:           %-10"PRIu64"  remove:        %"PRIu64"\n"
           "  f_add:         %-10"PRIu64"  f_remove:      %"PRIu64"\n",
           fdir_stat.collision, fdir_stat.free,
           fdir_stat.maxhash, fdir_stat.maxlen,
           fdir_stat.add, fdir_stat.remove,
           fdir_stat.f_add, fdir_stat.f_remove);
    printf("  %s############################%s\n",
           fdir_stats_border, fdir_stats_border);
}

static int adns_port_fdir_config(int port)
{
    int ret = -1;
    struct rte_eth_fdir_filter entry;
    int i, j, p;

#ifdef __SUPPORT_NIC_XL710
    struct rte_eth_fdir_filter entry6;
    struct rte_eth_fdir_filter_info fdir_info6;
    struct rte_eth_input_set_conf * inset_conf = NULL;
    struct rte_eth_fdir_filter_info fdir_info;
#endif

    ret = rte_eth_dev_filter_supported(port, RTE_ETH_FILTER_FDIR);
    if (ret < 0) {
        printf("flow director is not supported on port %u.\n", port);
        return -1;
    }

#ifdef __SUPPORT_NIC_XL710
    /* select input set */
    memset(&fdir_info, 0, sizeof(struct rte_eth_fdir_filter_info));
    fdir_info.info_type = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
    inset_conf = &(fdir_info.info.input_set_conf);
    inset_conf->flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_TCP;
    inset_conf->inset_size = 1;
#ifdef __FDIR_DIP_ENABLE
    inset_conf->field[0] = RTE_ETH_INPUT_SET_L3_DST_IP4;
#else
    inset_conf->field[0] = RTE_ETH_INPUT_SET_L4_TCP_DST_PORT;
#endif
    inset_conf->op = RTE_ETH_INPUT_SET_SELECT;

    ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_SET, &fdir_info);
    if (ret < 0) {
        printf("flow director programming error: (%s)\n", strerror(-ret));
        return -2;
    }

    memset(&fdir_info, 0, sizeof(struct rte_eth_fdir_filter_info));
    fdir_info.info_type = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
    inset_conf = &(fdir_info.info.input_set_conf);
    inset_conf->flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
    inset_conf->inset_size = 1;
    inset_conf->field[0] = RTE_ETH_INPUT_SET_L4_UDP_DST_PORT;
    inset_conf->op = RTE_ETH_INPUT_SET_SELECT;

    ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_SET, &fdir_info);
    if (ret < 0) {
        printf("flow director programming error: (%s)\n", strerror(-ret));
        return -3;
    }

    memset(&fdir_info6, 0, sizeof(struct rte_eth_fdir_filter_info));
    fdir_info6.info_type = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
    inset_conf = &(fdir_info6.info.input_set_conf);
    inset_conf->flow_type = RTE_ETH_FLOW_NONFRAG_IPV6_TCP;
    inset_conf->inset_size = 1;
#ifdef __FDIR_DIP_ENABLE
    inset_conf->field[0] = RTE_ETH_INPUT_SET_L3_DST_IP6;
#else
    inset_conf->field[0] = RTE_ETH_INPUT_SET_L4_TCP_DST_PORT;
#endif
    inset_conf->op = RTE_ETH_INPUT_SET_SELECT;

    ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_SET, &fdir_info6);
    if (ret < 0) {
        printf("flow director programming error: (%s)\n", strerror(-ret));
        return -4;
    }
#endif

    /* add an filter */
    memset(&entry, 0, sizeof(struct rte_eth_fdir_filter));
    entry.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_TCP;
    entry.action.behavior = RTE_ETH_FDIR_ACCEPT;
    entry.action.report_status = RTE_ETH_FDIR_REPORT_ID;
    entry.action.rx_queue = 0;

#ifdef __SUPPORT_NIC_XL710
    memset(&entry6, 0, sizeof(struct rte_eth_fdir_filter));
    entry6.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV6_TCP;
    entry6.action.behavior = RTE_ETH_FDIR_ACCEPT;
    entry6.action.report_status = RTE_ETH_FDIR_REPORT_ID;
    entry6.action.rx_queue = 0;
#endif

    uint32_t soft_id = 1;
#ifdef __FDIR_DIP_ENABLE
    entry.soft_id = soft_id ++;
    entry.input.flow.tcp4_flow.ip.dst_ip = vport_ips[port];
    ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &entry);
    if (ret < 0) {
        printf("flow director programming error: (%s)\n", strerror(-ret));
        return -5;
    }
#ifdef __IPV6_SUPPORT
    entry.soft_id = soft_id ++;
    memcpy(entry.input.flow.tcp6_flow.ip.dst_ip, ipv6_vport_ips[port], sizeof(struct in6_addr));
    ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &entry);
    if (ret < 0) {
        printf("flow director programming error: (%s)\n", strerror(-ret));
        return -6;
    }
#endif
#else
    for (i = 0; i < MAX_ALLOW_TCP_PORT_NUM; i ++) {
        uint16_t tcp_port = app.allowed_tcp_port[i];
        if (tcp_port == 0) {
            continue;
        }
        entry.soft_id = soft_id ++;
        entry.input.flow.tcp4_flow.dst_port = rte_cpu_to_be_16(tcp_port);

        ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &entry);
        if (ret < 0) {
            printf("flow director programming error: (%s)\n", strerror(-ret));
            return -5;
        }

#ifdef __SUPPORT_NIC_XL710
        entry6.soft_id = soft_id ++;
        entry6.input.flow.tcp6_flow.dst_port = rte_cpu_to_be_16(tcp_port);

        ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &entry6);
        if (ret < 0) {
            printf("flow director programming error: (%s)\n", strerror(-ret));
            return -6;
        }
#endif

        printf("FDIR accept TCP port %u\n", tcp_port);
    }
#endif

    fdir_get_infos(port);
    /* add each lcore fdir */
    memset(&entry, 0, sizeof(struct rte_eth_fdir_filter));
    entry.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
    entry.action.behavior = RTE_ETH_FDIR_ACCEPT;
    entry.action.report_status = RTE_ETH_FDIR_REPORT_ID;
    for (i = 0; i < RTE_MAX_LCORE; i ++) {
        struct lcore_params *lp = &app.lcore_params[i];
        if (lp->type != e_LCORE_IO) {
            continue;
        }
        for (j = 0; j < lp->io.n_rx_queues; j ++) {
            int port_id = lp->io.rx_queues[j].port_id;
            int queue_id = lp->io.rx_queues[j].queue_id;
            if (port_id != port)
                continue;
            for (p = 0; p < LCORE_FWD_PORTS_MAX; p ++) {
                entry.soft_id = soft_id ++;
                entry.action.rx_queue = queue_id;
                entry.input.flow.udp4_flow.dst_port = rte_cpu_to_be_16(fwd_port_mgr[i][port_id].ports[p]);
                ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &entry);
                if (ret < 0) {
                    printf("lcore %d, rxqueue %d, port_id %d, flow director programming error: (%s)\n",
                            i, queue_id, p, strerror(-ret));
                    return -7;
                }
                printf("[FDIR_DEBUG] lcore %d, rxqueue %d, port_id %d, fdir set", i, queue_id, fwd_port_mgr[i][port_id].ports[p]);
                fdir_get_infos(port_id);
            }
        }
    }
    return 0;
}

#ifndef __SUPPORT_NIC_XL710
static int set_tx_queue_stats_mapping_registers(uint8_t port_id)
{
    uint16_t i;
    int diag;

    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        diag = rte_eth_dev_set_tx_queue_stats_mapping(port_id, i, i);
        if (diag != 0)
            return diag;
    }
    return 0;
}

static int set_rx_queue_stats_mapping_registers(uint8_t port_id)
{
    uint16_t i;
    int diag;

    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        diag = rte_eth_dev_set_rx_queue_stats_mapping(port_id, i, i);
        if (diag != 0)
            return diag;
    }
    return 0;
}

static int map_port_queue_stats_mapping_registers(uint8_t port_id)
{
    int diag = 0;

    diag = set_tx_queue_stats_mapping_registers(port_id);
    if (diag != 0) {
        if (diag == -ENOTSUP) {
            RTE_LOG(ERR, LDNS, "TX queue stats mapping not supported port id=%d\n",
                    port_id);
        }
        else
            RTE_LOG(ERR, LDNS, "set_tx_queue_stats_mapping_registers "
                    "failed for port id=%d diag=%d\n", port_id, diag);

        return diag;
    }

    diag = set_rx_queue_stats_mapping_registers(port_id);
    if (diag != 0) {
        if (diag == -ENOTSUP) {
            RTE_LOG(ERR, LDNS, "RX queue stats mapping not supported port id=%d\n",
                    port_id);
        }
        else
            RTE_LOG(ERR, LDNS, "set_rx_queue_stats_mapping_registers "
                    "failed for port id=%d diag=%d\n", port_id, diag);
    }
    return diag;
}
#endif


/**
 * It will be called as the callback for specified port after a LSI interrupt
 * has been fully handled. This callback needs to be implemented carefully as
 * it will be called in the interrupt host thread which is different from the
 * application main thread.
 *
 * @param port_id
 *  Port id.
 * @param type
 *  event type.
 * @param param
 *  Pointer to(address of) the parameters.
 *
 * @return
 *  void.
 */
static void lsi_event_callback(uint8_t port_id, enum rte_eth_event_type type,
        void *param) {
    struct rte_eth_link link;

    RTE_SET_USED(param);

    if (kni_port_info[port_id].kni == NULL)
        return;

    rte_eth_link_get_nowait(port_id, &link);
    if (rte_kni_update_link(kni_port_info[port_id].kni, link.link_status) != 0) {
        RTE_LOG(ERR, LDNS,
                "The port %d link %s, failed to change the carrier status on %s.\n",
                port_id, link.link_status ? "up" : "down",
                rte_kni_get_name(kni_port_info[port_id].kni));
    } else {
        RTE_LOG(INFO, LDNS,
                "The port %d link %s, change the carrier status on %s.\n",
                port_id, link.link_status ? "up" : "down",
                rte_kni_get_name(kni_port_info[port_id].kni));
    }
}

/* Initialize all NIC port */
static int app_init_nics(void)
{
    unsigned socket;
    uint32_t lcore;
    uint8_t port, queue;
    int ret;
    uint32_t n_rx_queues, n_tx_queues;

    /* Init driver */
    if (rte_eal_pci_probe() < 0) {
        RTE_LOG(ERR, LDNS, "Cannot probe PCI\n");
        return -1;
    }

    if (rte_eth_dev_count() == 0) {
        RTE_LOG(ERR, LDNS, "No Ethernet port - bye\n");
        return -1;
    }

    /* Init NIC ports and queues, then start the ports */
    for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
        struct rte_mempool *pool;

        n_rx_queues = get_nic_rx_queues_per_port(port);
        n_tx_queues = get_nic_tx_queues_per_port(port);

        if (app.port_mask[port] == 1)
            RTE_LOG(ERR, LDNS, "Port[%d]: rx queues - %d, tx queues - %d\n",
                    port, n_rx_queues, n_tx_queues);

        if ((n_rx_queues == 0) && (n_tx_queues == 0)) {
            continue;
        }
        app.nb_ports ++;

        /* Init port */
        RTE_LOG(ERR, LDNS, "Initializing NIC port %u ...\n", (unsigned)port);
        ret = rte_eth_dev_configure(port,
                                    (uint8_t) n_rx_queues,
                                    (uint8_t) n_tx_queues, &port_conf);
        if (ret < 0) {
            RTE_LOG(ERR, LDNS, "Cannot init NIC port %u (%d)\n", (unsigned)port,
                    ret);
            return -1;
        }

        /* register lsi interrupt callback, need to be after
         * rte_eth_dev_configure(). if (intr_conf.lsc == 0), no
         * lsc interrupt will be present, and below callback to
         * be registered will never be called.
         */
        rte_eth_dev_callback_register(port, RTE_ETH_EVENT_INTR_LSC,
                lsi_event_callback, NULL);

        /* Enable nic promiscuous mode */
        rte_eth_promiscuous_enable(port);

        /* Get nic ethernet address */
        rte_eth_macaddr_get(port, &app.eth_addrs[port]);

        /* On daemon mode, dumped to /dev/null */
        print_ethaddr(" Address: ", &app.eth_addrs[port]);
        printf("\n");

        /* Init RX queues */
        for (queue = 0; queue < MAX_RX_QUEUES_PER_NIC_PORT; queue++) {
            if (app.nic_rx_queue_mask[port][queue] == 0) {
                continue;
            }

            ret = get_lcore_for_nic_rx(port, queue, &lcore);
            if (ret < 0) {
                RTE_LOG(ERR, LDNS, "Cannot get lcore for port[%u]-queue[%u]\n",
                        (unsigned)port, (unsigned)queue);
                return -1;
            }

            socket = rte_lcore_to_socket_id(lcore);
            pool = app.lcore_params[lcore].pool;

            RTE_LOG(ERR, LDNS,
                    "Initializing NIC port %u RX queue %u On lcore[%u] ...\n",
                    (unsigned)port, (unsigned)queue, (unsigned)lcore);
            ret =
                rte_eth_rx_queue_setup(port, queue,
                                       (uint16_t) app.nic_rx_ring_size, socket,
                                       &rx_conf, pool);
            if (ret < 0) {
                RTE_LOG(ERR, LDNS, "Cannot init RX queue %u for port %u (%d)\n",
                        (unsigned)queue, (unsigned)port, ret);
                return -1;
            }
        }

        /* Init TX queues */
        for (queue = 0; queue < MAX_TX_QUEUES_PER_NIC_PORT; queue++) {
            if (app.nic_tx_queue_mask[port][queue] == 0) {
                continue;
            }

            ret = get_lcore_for_nic_tx(port, queue, &lcore);
            if (ret < 0) {
                RTE_LOG(ERR, LDNS, "Cannot get lcore for port[%u]-queue[%u]\n",
                        (unsigned)port, (unsigned)queue);
                return -1;
            }
            socket = rte_lcore_to_socket_id(lcore);

            RTE_LOG(ERR, LDNS,
                    "Initializing NIC port %u TX queue %u On lcore[%u] ...\n",
                    (unsigned)port, (unsigned)queue, (unsigned)lcore);

            ret = rte_eth_tx_queue_setup(port,
                                         queue,
                                         (uint16_t) app.nic_tx_ring_size,
                                         socket, &tx_conf);
            if (ret < 0) {
                RTE_LOG(ERR, LDNS, "Cannot init TX queue 0 for port %d (%d)\n",
                        port, ret);
                return -1;
            }
        }
#ifndef __SUPPORT_NIC_XL710
        /* Mapping per queue stats counters.
           The per queue stats counters would be 0 except queue 0, if don't call this
           function. */
        ret = map_port_queue_stats_mapping_registers(port);
        if (ret < 0) {
            RTE_LOG(ERR, LDNS, "Cannot mapping port queue stats registers for port %d (%d)\n", port, ret);
            return -1;
        }
#endif

        /* Start port */
        ret = rte_eth_dev_start(port);
        if (ret < 0) {
            RTE_LOG(ERR, LDNS, "Cannot start port %d (%d)\n", port, ret);
            return -1;
        }

        ret = adns_port_rss_config(port, n_rx_queues);
        if (ret < 0) {
            RTE_LOG(ERR, LDNS, "Cannot int rss for port %d, ret = %d\n", port, ret);
            return -1;
        }

        if (app.allowed_tcp_port[0] == 0) {
            continue;
        } else {
            ret = adns_port_fdir_config(port);
            if (ret < 0) {
                RTE_LOG(ERR, LDNS, "Cannot int fdir for port %d, ret = %d\n", port, ret);
                return -1;
            }
        }
    }

    check_all_ports_link_status(RTE_MAX_ETHPORTS, (~0x0));

    return 0;
}

/* Callback for request of changing MTU */
int kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
    int ret;
    struct rte_eth_conf conf;

    if (port_id >= rte_eth_dev_count()) {
        printf("Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    printf("Change MTU of port %d to %u\n", port_id, new_mtu);

    /* Stop specific port */
    rte_eth_dev_stop(port_id);

    rte_memcpy(&conf, &port_conf, sizeof(conf));
    /* Set new MTU */
    if (new_mtu > ETHER_MAX_LEN)
        conf.rxmode.jumbo_frame = 1;
    else
        conf.rxmode.jumbo_frame = 0;

    /* mtu + length of header + length of FCS = max pkt length */
    conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
        KNI_ENET_FCS_SIZE;
    ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
    if (ret < 0) {
        printf("Fail to reconfigure port %d\n", port_id);
        return ret;
    }

    /* Restart specific port */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        printf("Fail to restart port %d\n", port_id);
        return ret;
    }

    return 0;
}

int kni_running = 1;

/* Callback for request of configuring network interface up/down */
int kni_config_network_interface(uint8_t port_id, uint8_t if_up)
{
    int ret = 0;

    if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
        RTE_LOG(ERR, LDNS, "Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    RTE_LOG(INFO, LDNS, "Configure network interface of %d %s\n", port_id,
            if_up ? "up" : "down");

    if (if_up != 0) { /* Configure network interface up */
        kni_port_info[port_id].is_running = 1;
    } else
        /* Configure network interface down */
        kni_port_info[port_id].is_running = 0;

    if (ret < 0)
        RTE_LOG(ERR, LDNS, "Failed to start port %d\n", port_id);

    return ret;
}

uint8_t nb_sys_ports;

static struct rte_kni *kni_alloc(uint8_t port_id) {
    uint8_t i;
    struct rte_kni *kni;
    struct rte_kni_conf conf;
    uint8_t nb_kni = 1;
    uint32_t lcore_k = 0;
    uint32_t lcore = 0;

    for (i = 0; i < nb_kni; i++) {
        // The index of kni port should be corresponding to the same index queue
        if (get_lcore_for_nic_rx(port_id, i, &lcore) < 0) {
            rte_exit(EXIT_FAILURE, "Cannot get lcore for port[%u]-queue[%u]\n",
                    port_id, i);
        }
        /* Clear conf at first */
        memset(&conf, 0, sizeof(conf));
        lcore_k = kni_port_info[port_id].lcore_id;
        if (i > 0) {
            snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u_%u", port_id, i);
        } else {
            snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);
        }
        // should not use core 0 for kni, 0 means no lcore bind
        if (lcore_k != 0) {
            conf.core_id = lcore_k;
            conf.force_bind = kni_port_info[port_id].force_bind;
        }

        conf.group_id = (uint16_t) port_id;
        conf.mbuf_size = KNI_MAX_PACKET_SZ;
        /*
         * The first KNI device associated to a port
         * is the master, for multiple kernel thread
         * environment.
         */
        if (i == 0) {
            struct rte_kni_ops ops;
            struct rte_eth_dev_info dev_info;

            memset(&dev_info, 0, sizeof(dev_info));
            rte_eth_dev_info_get(port_id, &dev_info);
            conf.addr = dev_info.pci_dev->addr;
            conf.id = dev_info.pci_dev->id;

            memset(&ops, 0, sizeof(ops));
            ops.port_id = port_id;
            ops.change_mtu = kni_change_mtu;
            ops.config_network_if = kni_config_network_interface;

            kni = rte_kni_alloc(app.lcore_params[lcore].pool, &conf, &ops);
        } else
            kni = rte_kni_alloc(app.lcore_params[lcore].pool, &conf, NULL);

        if (!kni)
            rte_exit(EXIT_FAILURE, "Fail to create kni for "
                    "port: %d\n", port_id);
    }

    return kni;
}


/* Initialize KNI interface */
static int app_init_knis(void)
{
    unsigned int i;
    uint8_t port, cfg_ports = 0;

    kni_ops.change_mtu = kni_change_mtu;
    kni_ops.config_network_if = kni_config_network_interface;

    /* Get number of ports found in scan */
    nb_sys_ports = rte_eth_dev_count();
    if (nb_sys_ports == 0) {
        RTE_LOG(ERR, LDNS, "No supported Ethernet devices found - "
                "check that CONFIG_RTE_LIBRTE_IGB_PMD=y and/or "
                "CONFIG_RTE_LIBRTE_IXGBE_PMD=y in the config file");
        return-1;
    }
    rte_kni_init(nb_sys_ports);

    /* Find the number of configured ports in the port mask */
    for (i = 0; i < sizeof(app.portmask) * 8; i++)
        cfg_ports += !! (app.portmask & (1 << i));

    if (cfg_ports > nb_sys_ports) {
        RTE_LOG(ERR, LDNS, "Port mask requires more ports than available");
        return -1;
    }

    int lcore_id;
    /* Initialise each port */
    for (port = 0; port < nb_sys_ports; port++) {
        struct rte_kni *kni;
        struct rte_eth_link link;

        /* Skip ports that are not enabled */
        if ((app.portmask & (1 << port)) == 0) {
            continue;
        }

        if (port >= RTE_MAX_ETHPORTS) {
            RTE_LOG(ERR, LDNS, "Can not use more than "
                    "%d ports for kni\n", RTE_MAX_ETHPORTS);
            return -1;
        }

        kni = kni_alloc(port);
        if (kni == NULL) {
            RTE_LOG(ERR, LDNS, "Fail to create kni dev " "for port: %d\n",
                    port);
            return -1;
        }

        rte_eth_link_get_nowait(port, &link);
        if (rte_kni_update_link(kni, link.link_status) != 0) {
            RTE_LOG(ERR, LDNS, "Failed to set the carrier status %s on %s.\n",
                    link.link_status ? "on" : "off", rte_kni_get_name(kni));
        } else {
            RTE_LOG(INFO, LDNS, "Set the carrier status %s on %s.\n",
                    link.link_status ? "on" : "off", rte_kni_get_name(kni));
        }

        kni_port_info[port].kni = kni;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id ++) {
            struct lcore_params *lp = &app.lcore_params[lcore_id];
            if (lp->type == e_LCORE_KNI) {
                kni_lcore_port_map[port] = lcore_id;
            }
        }
    }
    return 0;
}

/*
 * LDNS main initialization routine.
 */

static int adns_health_check_init()
{
    int i, lcore_id, idx = 0;
    forwarder *fwder;
    for (i = 0; i < gio_count; i++) {
        lcore_id = gio_id[i];
        if (health_check_init(lcore_id) < 0)
            return -1;
    }
    struct list_head *head = &g_fwder_mgr[gio_id[0]].list;
    for (fwder = list_entry(head->next, forwarder, fwder_list);
         &fwder->fwder_list != head;
         fwder = list_entry(fwder->fwder_list.next, forwarder, fwder_list)) {
        /* only use recursive query do health check */
        if (health_check_add(gio_id[idx], fwder->ip, fwder->port, SRV_TYPE_REC/* fwder->views->srv_type */) < 0)
            return -1;
        idx++;
        if (idx >= gio_count)
            idx = 0;
    }
    return 0;
}

static void glog_lcore_init()
{
    int i;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        struct lcore_params *lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO || lp->type == e_LCORE_MISC
            || lp->type == e_LCORE_ADMIN || lp->type == e_LCORE_KNI) {
            glog_lcore_id[glog_lcore_count++] = i;
            printf("Add glog lcore %d, glog lcore count %d now\n", i,
                   glog_lcore_count);
        }
    }
}

int ldns_init(void)
{
    /* create LPM object */
    RTE_LOG(ERR, LDNS, "start ldns init\n");
    if (view_init() < 0) {
        return -1;
    }
    RTE_LOG(INFO, LDNS, "app init view done\n");

    if (view_map_init() < 0) {
        return -2;
    }
    RTE_LOG(INFO, LDNS, "app init view map done\n");

    if (iplib_init() < 0) {
        return -3;
    }
    RTE_LOG(INFO, LDNS, "app init ip lib done\n");

    /* some memset */
    stat_init();
    RTE_LOG(INFO, LDNS, "app init statistics done\n");

    /* init dns_qtype[][] */
    init_dns_qtype();
    RTE_LOG(INFO, LDNS, "app init dns qtype done\n");


    if (app_load_cfg_profile() < 0) {
        return -4;
    }
    RTE_LOG(INFO, LDNS, "app load cfg done\n");

    if (fwd_qps_limit_init() < 0) {
        return -18;
    }
    RTE_LOG(INFO, LDNS, "app init qps limit done\n");

    glog_lcore_init();
    RTE_LOG(INFO, LDNS, "app init glog lcore done\n");

    if (node_db_init() <0) {
        return -5;
    }
    RTE_LOG(INFO, LDNS, "app init view hash done\n");

    if (g_pool_init() < 0) {
        return -6;
    }
    RTE_LOG(INFO, LDNS, "app init g pool done\n");

    if (log_init() < 0) {
        return -7;
    }
    RTE_LOG(INFO, LDNS, "init log done\n");

    app_io_misc_init();
    RTE_LOG(INFO, LDNS, "app init io misc done\n");

    assert(init_man_whitelist() >= 0);
    assert(init_man_blacklist() >= 0);
    assert(init_ip_filter() >= 0);
    //assert(init_oversealist() >= 0);

    if (app_init_mbuf_pools() < 0) {
        return -8;
    }
    RTE_LOG(INFO, LDNS, "app init mbuf done\n");

    if (assign_lcore_forward_ports() < 0) {
        return -9;
    }
    RTE_LOG(INFO, LDNS, "assign init done\n");

    if (app_init_nics() < 0) {
        return -10;
    }
    RTE_LOG(INFO, LDNS, "app init nics done\n");

    if (app_init_knis() < 0) {
        return -11;
    }
    RTE_LOG(INFO, LDNS, "app init kni done\n");

    if (socket_init() < 0) {
        return -13;
    }
    RTE_LOG(INFO, LDNS, "adns fdir init done\n");

    if (admin_init(NULL, 0) < 0) {
        return -14;
    }
    RTE_LOG(INFO, LDNS, "admin init done\n");

    if (lcore_msg_init() < 0) {
        return -15;
    }
    RTE_LOG(INFO, LDNS, "msg init done\n");

    if (adns_health_check_init() < 0)
        return -16;
    RTE_LOG(INFO, LDNS, "health check init done\n");

    if (hijack_init() < 0) {
        return -19;
    }
    RTE_LOG(ERR, LDNS, "hijack init done\n");

    if (dnscache_init(&g_dnscache_node_tbl) < 0) {
        return -20;
    }
    RTE_LOG(ERR, LDNS, "dnscache init done\n");

    if (fwd_user_db_init() < 0) {
        return -21;
    }
    RTE_LOG(ERR, LDNS, "user init done\n");

    RTE_LOG(INFO, LDNS, "Initialization completed.\n");

    return 0;
}

void ldns_cleanup(void)
{
    log_cleanup();
}
