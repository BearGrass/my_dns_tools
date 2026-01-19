#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_core.h>
#include <rte_kni.h>
#include <rte_ip.h>
#include <rte_ethdev.h>


#include "ae.h"
#include "admin.h"
#include "adns.h"
#include "msg.h"
#include "cfg_file.h"
#include "iplib.h"
#include "log.h"
#include "view_maps.h"
#include "init_zone.h"
#include "descriptor.h"
#include "utili_base.h"
#include "adns_stats.h"
#include "adns_conf.h"
#include "syslog.h"
#include "mbuf.h"
#include "adns_counter.h"
#include "networking.h"
#include "rcu.h"
#include "common_value.h"
#include "dnssec.h"
#include "dnssec_cache.h"
#include "dnssec_cache_msg.h"
#include "qps_limit.h"
#include "zone.h"

#define ADNS_COUNTER_NUM 64 


extern int sysctl_tcp_in_53_drop;
extern int sysctl_tcp_in_53_rate;
extern int sysctl_tcp_in_53_quota;
extern int sysctl_tcp_in_53_total_quota;
extern int sysctl_tcp_in_53_total_pps_quota;
extern int qps_limit_init();

struct rte_kni_ops kni_ops;
struct rte_kni *kni_port_info[RTE_MAX_ETHPORTS];
uint32_t kni_port_info_kcore[RTE_MAX_ETHPORTS];
struct rte_mempool *kni_pktmbuf_pool;
struct sys_admin admin;
uint32_t g_zone_max_num = 0;
uint32_t g_private_route_zone_max_num = 0;
adns_private_route_id_t g_private_route_per_zone_max_num = 0;
uint8_t g_ip_segment_per_route_max_num = 0;
adns_viewid_t g_view_max_num = 0;
uint32_t g_domain_max_num = 0;
uint32_t g_rr_max_num = 0;
uint32_t g_rrset_memory_max_num = 0;
uint32_t g_rdata_ctl_max_num = 0;
uint32_t g_private_rdata_ctl_max_num = 0;

uint8_t  g_response_answer_max_record_num = 0;
uint8_t  g_response_authority_max_record_num = 0;
uint8_t  g_response_additional_max_record_num = 0;

uint32_t  g_ns_group_max_num = 0;

uint32_t g_dnssec_zone_max_num = 0;
uint32_t g_dnssec_cache_max_num = 0;
// Shared with NDNS
uint8_t *g_p_dnnssec_cache_switch = NULL;


struct adns_syslog g_syslog_ctl;

uint32_t g_domain_name_max_num[NAME_LEN_TYPE_NUM] = {0};
uint32_t g_domain_name_used_num[NAME_LEN_TYPE_NUM] = {0};
uint32_t g_zone_name_max_num[NAME_LEN_TYPE_NUM] = {0};
uint32_t g_zone_name_used_num[NAME_LEN_TYPE_NUM] = {0};
uint64_t g_zone_qps_quota;
uint64_t g_zone_bps_quota;
uint64_t g_domain_qps_quota;
uint64_t g_domain_bps_quota;
uint64_t g_time_interval;
//char g_hostname[MAX_HOSTNAME_LEN] = {0};
char *g_hostname = NULL;
uint8_t g_hostname_len = 0;
char g_idcname[MAX_HOSTNAME_LEN] = {0};
char g_time_str[40] = {0};
adns_weight_t g_large_weight;

uint64_t g_node_qps_valid_duration;


int name_len_to_index[NAME_LEN_TYPE_NUM] = {
    ADNS_DOMAIN_MAX_LEN_32,
    ADNS_DOMAIN_MAX_LEN_64,
    ADNS_DOMAIN_MAX_LEN_128,
    ADNS_DOMAIN_MAX_LEN_256
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

static int str_to_unsigned_array(
        const char *s, size_t sbuflen,
        char separator,
        unsigned num_vals,
        unsigned *vals)
{
    char str[sbuflen+1];
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

static int str_to_unsigned_vals(
        const char *s,
        size_t sbuflen,
        char separator,
        unsigned num_vals, ...)
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

int parse_log_switch(const char *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(log_switch_maps); i++) {
        if (strcasecmp(log_switch_maps[i].name, name) == 0)
            return log_switch_maps[i].id;
    }

    return -1;
}

size_t parse_log_rotate_max_size(const char *name)
{
    size_t len = 0;;
    char unit;
    unsigned int i = 0;
    size_t number;
    char num_str[ADNS_ROTATE_SIZE_MAX_LEN + 5];

    if ((name == NULL) || (name[0] == '-')) {
        return LOG_ROTATE_DISABLE;
    }
    len = strlen(name);
    if(len > ADNS_ROTATE_SIZE_MAX_LEN) {
        return LOG_ROTATE_DISABLE;
    } 
 
    for(i = 0; i < len; ++i) {
        num_str[i] = name[i];
    }
   unit = name[len - 1];

    num_str[len - 1] = '\0';
    errno = 0;
    sscanf(num_str,"%zd", &number);
    if (errno != 0 || number > 1024) {
        return LOG_ROTATE_DISABLE;
    }
    if (unit == 'B') {
        return number;
    }
    if (unit == 'K') {
        return number *1024;
    }
    if (unit == 'M') {
        return number * 1024 * 1024;
    }
    if (unit == 'G') {
        return number * 1024 * 1024 * 1024;
    }
    return LOG_ROTATE_DISABLE;
}

uint32_t parse_log_rotate_max_count(const char *name)
{
    uint32_t number;
    errno = 0;
    sscanf(name,"%u", &number);
    if (errno != 0) {
        return LOG_ROTATE_DISABLE;
    }
   return number;
}
int parse_log_level(const char *name)
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(log_level_maps); i++) {
        if (strcasecmp(log_level_maps[i].name, name) == 0)
            return log_level_maps[i].id;
    }

    return -1;
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
    while ((p = strchr(p0,'(')) != NULL) {
        struct lcore_params *lp;
        uint32_t port, queue, lcore, i;

        p0 = strchr(p++, ')');
        if ((p0 == NULL) ||
                (str_to_unsigned_vals(p, p0 - p, ',', 3, &port, &queue, &lcore) !=  3)) {
            return -2;
        }

        /* Enable port and queue for later initialization */
        if ( ((port >= RTE_MAX_ETHPORTS) || (queue >= MAX_RX_QUEUES_PER_NIC_PORT) || (app.portmask & (1 << port)) == 0) ) {
            return -3;
        }
        if (app.nic_rx_queue_mask[port][queue] != 0) {
            return -4;
        }
        app.nic_rx_queue_mask[port][queue] = 1;

        if (app.port_enabled[port] == 0)
            app.port_enabled[port] = 1;

        /* Check and assign (port, queue) to I/O lcore */
        if (rte_lcore_is_enabled(lcore) == 0) {
            return -5;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -6;
        }
        lp = &app.lcore_params[lcore];
        if (lp->type == e_LCORE_ADMIN
                || lp->type == e_LCORE_MISC) {
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
        lp->io.rx_queues[lp->io.n_rx_queues].port_id = (uint8_t)port;
        lp->io.rx_queues[lp->io.n_rx_queues].queue_id = (uint8_t)queue;
        lp->io.n_rx_queues++;

        n_tuples++;
        if (n_tuples > ETH_RX_MAX_TUPLES) {
            return -10;
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
    while ((p = strchr(p0,'(')) != NULL) {
        struct lcore_params *lp;
        uint32_t port, queue, lcore, i;

        p0 = strchr(p++, ')');
        if ((p0 == NULL) ||
                (str_to_unsigned_vals(p, p0 - p, ',', 3, &port, &queue, &lcore) !=  3)) {
            return -2;
        }

        /* Enable port and queue for later initialization */
        if ( ((port >= RTE_MAX_ETHPORTS) || (queue >= MAX_RX_QUEUES_PER_NIC_PORT) || (app.portmask & (1 << port)) == 0) ) {
            return -3;
        }
        if (app.nic_tx_queue_mask[port][queue] != 0) {
            return -4;
        }
        app.nic_tx_queue_mask[port][queue] = 1;

        if (app.port_enabled[port] == 0)
            app.port_enabled[port] = 1;

        /* Check and assign (port, queue) to I/O lcore */
        if (rte_lcore_is_enabled(lcore) == 0) {
            return -5;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -6;
        }
        lp = &app.lcore_params[lcore];
        if (lp->type == e_LCORE_ADMIN
                || lp->type == e_LCORE_MISC) {
            return -7;
        }
        lp->type = e_LCORE_IO;
        /* check whether have assigned a queue on the port */
        for (i = 0; i < lp->io.n_tx_ports; i ++) {
            if (lp->io.tx_ports[i] == port) {
                return -8;
            }
        }
        if (lp->io.n_tx_ports >= MAX_NIC_TX_QUEUES_PER_IO_LCORE) {
            return -9;
        }
        lp->io.tx_ports[lp->io.n_tx_ports] = (uint8_t)port;
        lp->io.tx_queues[(uint8_t)port] = (uint8_t)queue;
        lp->io.n_tx_ports++;

        n_tuples++;
        if (n_tuples > ETH_TX_MAX_TUPLES) {
            return -10;
        }
    }

    if (n_tuples == 0) {
        return -11;
    }

    return 0;
}

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
                || lp->type ==  e_LCORE_MISC) {
            return -5;
        }
        lp->type = e_LCORE_ADMIN;

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

static int parse_eth_tcp(const char *arg)
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
                || lp->type ==  e_LCORE_MISC || lp->type == e_LCORE_ADMIN) {
            return -5;
        }
        lp->type = e_LCORE_TCP;

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

static int parse_lcore_kni(const char *arg)
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
                || lp->type ==  e_LCORE_MISC || lp->type == e_LCORE_ADMIN) {
            return -5;
        }

        if (lcore >= RTE_MAX_LCORE) {
            return -10; 
        }
        kni_port_info_kcore[n_tuples] = lcore;
        n_tuples++;
        if (n_tuples == 2) {
            return 0;
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
                || lp->type ==  e_LCORE_ADMIN) {
            return -5;
        }
        lp->type = e_LCORE_MISC;

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
        if (app.port_enabled[port] == 0)
            continue;

        if (app.nic_tx_queue_mask[port][queue] != 0) {
            return -9;
        }
        app.nic_tx_queue_mask[port][queue] = 1;
        app.nic_rx_queue_mask[port][queue] = 1;
    }

    return 0;
}

/* load nic about configuration */
static int cfg_load_nic(struct cfg_file *cfg)
{
    int ret;
    const char *entry;
    char sec_name[CFG_NAME_LEN];
    uint32_t nic_rx = 0; /* nic section must specify rx/tx entry */
    uint32_t nic_tx = 0;
    uint32_t nic_admin = 0;
    uint32_t nic_misc = 0;

    snprintf(sec_name, sizeof(sec_name), "nic");

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    /* parse rx param, then fill configuration */
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

    /* parse tx param, then fill configuration */
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

    /* parse tcp_port_allowed param, then fill configuration */
    entry = cfg_get_entry(cfg, sec_name, "tcp_port_allowed");
    if (entry == NULL) {
        printf("Cannot get [%s]-%s configuration\n", sec_name, "tcp_port_allowed");
        return -1;
    }

    printf("\nentry[tcp_port_allowed]: === %s\n", entry);
    nic_tx = 1;
    ret = parse_allowed_tcp_port((char *)entry);
    if (ret) {
        printf("Incorrect value for --tcp_port_allowed argument (%d)\n", ret);
        return -1;
    }

    /* parse rss_port_conf param, then fill configuration */
    entry = cfg_get_entry(cfg, sec_name, "rss_port_conf");
    ret = parse_rss_conf((char *)entry);
    if (ret) {
        printf("Incorrect value for --rss_port_conf argument (%d)\n", ret);
        return -1;
    }

    /* parse admin param, then fill configuration */
    entry = cfg_get_entry(cfg, sec_name, "admin");
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
    }

    /* parse admin param, then fill configuration */
    entry = cfg_get_entry(cfg, sec_name, "lcore_tcp");
    if (entry == NULL) {
        printf("no %s configuration\n", "lcore_tcp");
    } else {
        printf("\nentry[nic_tcp]: === %s\n", entry);
        ret = parse_eth_tcp(entry);
        if (ret) {
            printf("Incorrect value for --admin argument (%d)\n", ret);
            return -1;
        }
    }

    /* parse admin param, then fill configuration */
    entry = cfg_get_entry(cfg, sec_name, "lcore_kni");
    if (entry == NULL) {
        printf("no %s configuration\n", "lcore_kni");
    } else {
        printf("\nentry[lcore_kni]: === %s\n", entry);
        ret = parse_lcore_kni(entry);
        if (ret) {
            printf("Incorrect value for --admin argument (%d)\n", ret);
            return -1;
        }
    }

    /* parse misc param, then fill configuration */
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

    /* Check that all mandatory arguments are provided */
    if ((nic_rx == 0) || (nic_tx == 0) || (nic_admin == 0) || (nic_misc == 0)){
        printf("Not all mandatory arguments are present\n");
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "tcp_in_53_drop");
    if (entry != NULL) {
        sysctl_tcp_in_53_drop = (uint32_t) atoi(entry);
    }

    entry = cfg_get_entry(cfg, sec_name, "tcp_in_53_rate");
    if (entry != NULL) {
        sysctl_tcp_in_53_rate = (uint32_t) atoi(entry);
    }

    entry = cfg_get_entry(cfg, sec_name, "tcp_in_53_quota");
    if (entry != NULL) {
        sysctl_tcp_in_53_quota = (uint32_t) atoi(entry);
    }

    entry = cfg_get_entry(cfg, sec_name, "tcp_in_53_total_quota");
    if (entry != NULL) {
        sysctl_tcp_in_53_total_quota = (uint32_t) atoi(entry);
    }

    entry = cfg_get_entry(cfg, sec_name, "tcp_in_53_total_pps_quota");
    if (entry != NULL) {
        sysctl_tcp_in_53_total_pps_quota = (uint32_t) atoi(entry);
    }

    app.lcore_num = get_lcore_num();
    app.lcore_io_num = get_io_lcore_num();
    app.lcore_io_start_id = get_io_lcore_start_id();

    return 0;
}

uint32_t ospf_ips[RTE_MAX_ETHPORTS] = { 0 };
/* load ospf configuration */
static int cfg_load_ospf(struct cfg_file *cfg)
{
    int i;
    char sec_name[CFG_NAME_LEN];
    const char *entry;
    char port_str[64];
    uint32_t tmp_ip;

    snprintf(sec_name, sizeof(sec_name), "ospf");
    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    /* conform again */
    memset(ospf_ips, 0, sizeof(uint32_t) * RTE_MAX_ETHPORTS);

    for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
        snprintf(port_str, 64, "%d", i);
        entry = cfg_get_entry(cfg, sec_name, port_str);
        if (entry == NULL) {
            continue;
        }

        /* convert address */
        tmp_ip = inet_addr(entry);
        ospf_ips[i] = rte_be_to_cpu_32(tmp_ip);	
    }

    return 0;
}


#if 0
static int cfg_load_zone(struct cfg_file *cfg)
{
    int ret;
    const char *entry;
    char sec_name[CFG_NAME_LEN];

    snprintf(sec_name, sizeof(sec_name), "zone");

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    /* parse zone path param, then fill configurature */
    entry = cfg_get_entry(cfg, sec_name, "path");
    if (entry == NULL) {
        printf("Cannot get [%s]-%s configuration\n", sec_name, "path");
        return -1;
    }
    /*zones_dir_path = strdup(entry);*/
    /*assert(zones_dir_path);*/

    return 0;
}
#endif

/* Load server about configure, such as log setting, pid file, etc. */
char *adns_log_path = NULL;
int adns_log_level = ADNS_LOG_LEVEL_INFO;
int adns_log_switch = ADNS_LOG_SWITCH_UP;
size_t g_log_rotate_max_size = LOG_ROTATE_DISABLE;
uint32_t g_log_rotate_max_count = LOG_ROTATE_DISABLE;
/* ip geo info file */
char *g_ipfile_path = NULL;
char *g_ipv6file_path = NULL;
char *g_view_map_file = NULL;
/* common ns list info file */
char *g_ns_list_file = NULL;

static int cfg_load_server(struct cfg_file *cfg)
{
    const char *entry;
    char sec_name[CFG_NAME_LEN];

    snprintf(sec_name, sizeof(sec_name), "server");

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    /* command-control bind addr */
    entry = cfg_get_entry(cfg, sec_name, "bind_addr");
    if (entry == NULL)
        return -1;
    admin.bind_addr = strdup(entry);
    assert(admin.bind_addr);

    /* command-control bind port */
    entry = cfg_get_entry(cfg, sec_name, "bind_port");
    if (entry == NULL)
        return -1;
    admin.bind_port = (uint16_t)atoi(entry);

    /* log store path */
    entry = cfg_get_entry(cfg, sec_name, "log_path");
    if (entry == NULL)
        return -1;
    adns_log_path = strdup(entry);
    assert(adns_log_path);

    /* log level */
    entry = cfg_get_entry(cfg, sec_name, "log_level");
    if (entry == NULL) {
        // default log level
        adns_log_level = ADNS_LOG_LEVEL_INFO;
    } else {
        if((adns_log_level = parse_log_level(entry)) < 0)
        {
            printf("Waring: log_level Format erro in conf: [%s]\n", entry);
            adns_log_level = ADNS_LOG_LEVEL_INFO;
        }
    }

    /* log switch*/
    entry = cfg_get_entry(cfg, sec_name, "log_switch");
    if (entry == NULL) {
        // default log switch
        adns_log_switch = ADNS_LOG_SWITCH_UP;
    } else {
        if((adns_log_switch = parse_log_switch(entry)) < 0)
        {
            printf("log_switch Format erro in conf: [%s]\n", entry);
            adns_log_switch = ADNS_LOG_SWITCH_UP;
        }
    }

    /* log rotate max size */
    entry = cfg_get_entry(cfg, sec_name, "log_rotate_max_size");
    if (entry == NULL) {
        // default log rotate max size
        g_log_rotate_max_size = LOG_ROTATE_DISABLE;
    } else {
        if((g_log_rotate_max_size = parse_log_rotate_max_size(entry)) == LOG_ROTATE_DISABLE)
        {
            printf("log_rotate_max_size Format erro in conf: [%s]\n", entry);
        }
    }
    /* log rotate max count */
    entry = cfg_get_entry(cfg, sec_name, "log_rotate_max_count");
    if (entry == NULL) {
        // default log rotate max count
        g_log_rotate_max_count = LOG_ROTATE_DISABLE;
    } else {
        if((g_log_rotate_max_count = parse_log_rotate_max_count(entry)) == LOG_ROTATE_DISABLE)
        {
            printf("log_rotate_max_count Format erro in conf: [%s]\n", entry);
        }
    }
    /* log files, server, query, answer log facility */

    /* ip geo info file path */
    entry = cfg_get_entry(cfg, sec_name, "ipfile_path");
    if (entry == NULL)
        return -1;
    g_ipfile_path = strdup(entry);
    assert(g_ipfile_path);

#ifdef __IPV6_SUPPORT
    /* ipv6 geo info file path */
    entry = cfg_get_entry(cfg, sec_name, "ipv6file_path");
    if (entry == NULL)
        return -1;
    g_ipv6file_path = strdup(entry);
    assert(g_ipv6file_path);
#endif

    /* view map file path */
    entry = cfg_get_entry(cfg, sec_name, "view_map");
    if (entry == NULL)
        return -1;
    g_view_map_file = strdup(entry);
    assert(g_view_map_file);

    /* common ns list file path */
    entry = cfg_get_entry(cfg, sec_name, "ns_list");
    if (entry == NULL)
        return -1;
    g_ns_list_file = strdup(entry);
    assert(g_ns_list_file);

    return 0;
}

static int cfg_load_conf(struct cfg_file *cfg)
{
    const char *entry;
    char sec_name[CFG_NAME_LEN];
    char temp_name[CFG_NAME_LEN];
    int j, k, val;
    uint32_t i, domain_sum, zone_sum;

    snprintf(sec_name, sizeof(sec_name), "conf");

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "zone_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry zone_max_num\n", sec_name);
        return -1;
    }
    g_zone_max_num = (uint32_t)atoi(entry);
    if (g_zone_max_num == 0) {
        printf("section[%s]: g_zone_max_num = %d\n", sec_name, g_zone_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "private_route_zone_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry private_route_zone_max_num\n", sec_name);
        return -1;
    }
    g_private_route_zone_max_num = (uint32_t)atoi(entry);
    if (g_private_route_zone_max_num == 0) {
        printf("section[%s]: g_private_route_zone_max_num = %d\n", sec_name, g_private_route_zone_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "max_route_num_per_zone");
    if (entry == NULL) {
        printf("section[%s]: missing entry max_route_num_per_zone\n", sec_name);
        return -1;
    }
    g_private_route_per_zone_max_num = (adns_private_route_id_t)atoi(entry);
    if (g_private_route_per_zone_max_num == 0) {
        printf("section[%s]: g_private_route_per_zone_max_num = %d\n", sec_name, g_private_route_per_zone_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "max_ip_segment_per_route");
    if (entry == NULL) {
        printf("section[%s]: missing entry max_ip_segment_per_route\n", sec_name);
        return -1;
    }
    g_ip_segment_per_route_max_num = (uint8_t)atoi(entry);
    if (g_ip_segment_per_route_max_num == 0) {
        printf("section[%s]: g_ip_segment_per_route_max_num = %d\n", sec_name, g_ip_segment_per_route_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "view_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry view_max_num\n", sec_name);
        return -1;
    }
    val = atoi(entry);
    if (val < VIEW_ID_MIN || val >= VIEW_ID_MAX) {
        printf("section[%s]: g_view_max_num = %d\n", sec_name, val);
        return -1;
    }
    g_view_max_num = (adns_viewid_t)val;

    entry = cfg_get_entry(cfg, sec_name, "domain_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry domain_max_num\n", sec_name);
        return -1;
    }
    g_domain_max_num = (uint32_t)atoi(entry);
    if (g_domain_max_num == 0) {
        printf("section[%s]: g_domain_max_num = %d\n", sec_name, g_domain_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "rr_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry rr_max_num\n", sec_name);
        return -1;
    }
    g_rr_max_num = (uint32_t)atoi(entry);
    if (g_rr_max_num == 0) {
        printf("section[%s]: g_rr_max_num = %d\n", sec_name, g_rr_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "rrset_memory_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry rrset_memory_max_num\n", sec_name);
        return -1;
    }
    g_rrset_memory_max_num = (uint32_t)atoi(entry);
    if(g_rrset_memory_max_num == 0) {
        printf("section[%s]: g_rrset_memory_max_num = %d\n", sec_name, g_rrset_memory_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "rdata_ctl_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry rdata_ctl_max_num\n", sec_name);
        return -1;
    }
    g_rdata_ctl_max_num = (uint32_t)atoi(entry);
    if(g_rdata_ctl_max_num == 0) {
        printf("section[%s]: g_rdata_ctl_max_num = %d\n", sec_name, g_rdata_ctl_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "ns_group_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry ns_group_max_num\n", sec_name);
        return -1;
    }
    g_ns_group_max_num = (uint32_t)atoi(entry);
    if(g_ns_group_max_num == 0) {
        printf("section[%s]: g_ns_group_max_num = %d\n", sec_name, g_ns_group_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "dnssec_zone_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry dnssec_zone_max_num\n", sec_name);
        return -1;
    }
    g_dnssec_zone_max_num = (uint32_t)atoi(entry);
    if(g_dnssec_zone_max_num == 0) {
        printf("section[%s]: g_dnssec_zone_max_num = %d\n", sec_name, g_dnssec_zone_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "dnssec_cache_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry dnssec_cache_max_num\n", sec_name);
        return -1;
    }
    g_dnssec_cache_max_num = (uint32_t)atoi(entry);
    if(g_dnssec_cache_max_num == 0) {
        printf("section[%s]: g_dnssec_cache_max_num = %d\n", sec_name, g_dnssec_cache_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "private_rdata_ctl_max_num");
    if (entry == NULL) {
        printf("section[%s]: missing entry private_rdata_ctl_max_num\n", sec_name);
        return -1;
    }
    g_private_rdata_ctl_max_num = (uint32_t)atoi(entry);
    if(g_private_rdata_ctl_max_num == 0) {
        printf("section[%s]: g_private_rdata_ctl_max_num = %d\n", sec_name, g_private_rdata_ctl_max_num);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "response_answer_max_record_num");
    if (entry == NULL) {
        printf("Entry %s missing for section [%s], default value is 0\n", "response_answer_max_record_num", sec_name);
        g_response_answer_max_record_num = 0;
    } else {
        g_response_answer_max_record_num = (uint8_t)atoi(entry);
    }

    entry = cfg_get_entry(cfg, sec_name, "response_authority_max_record_num");
    if (entry == NULL) {
        printf("Entry %s missing for section [%s], default value is 0\n", "response_authority_max_record_num", sec_name);
        g_response_authority_max_record_num = 0;
    } else {
        g_response_authority_max_record_num = (uint8_t)atoi(entry);
    }

    entry = cfg_get_entry(cfg, sec_name, "response_additional_max_record_num");
    if (entry == NULL) {
        printf("Entry %s missing for section: [%s], default value is 0\n", "response_additional_max_record_num", sec_name);
        g_response_additional_max_record_num = 0;
    } else {
        g_response_additional_max_record_num = (uint8_t)atoi(entry);
    }

    j = -1;
    k = -1;
    domain_sum = 0;
    zone_sum = 0;
    for (i = 32; i <= 256; i *= 2) {
        snprintf(temp_name, sizeof(temp_name), "domain_len_%d", i);
        entry = cfg_get_entry(cfg, sec_name, temp_name);
        if (entry == NULL) {
            g_domain_name_max_num[++j] = 0;
        } else {
            g_domain_name_max_num[++j] = (uint32_t)atoi(entry);
        }
        printf("section[%s]: domain_len_%u = %u\n", sec_name, i, g_domain_name_max_num[j]);
        domain_sum += g_domain_name_max_num[j];

        snprintf(temp_name, sizeof(temp_name), "zone_len_%d", i);
        entry = cfg_get_entry(cfg, sec_name, temp_name);
        if (entry == NULL) {
            g_zone_name_max_num[++k] = 0;
        } else {
            g_zone_name_max_num[++k] = (uint32_t)atoi(entry);
        }
        printf("section[%s]: zone_len_%u = %u\n", sec_name, i, g_zone_name_max_num[k]);
        zone_sum += g_zone_name_max_num[k];
    }

    if (domain_sum != g_domain_max_num) {
        printf("section[%s]: the sum(%u) of domain_len_32,64,128,256 is not equal with domain_max_num(%u)\n", sec_name, domain_sum, g_domain_max_num);
    }
    if (zone_sum != g_zone_max_num) {
        printf("section[%s]: the sum(%u) of zone_len_32,64,128,256 is not equal with zone_max_num(%u)\n", sec_name, zone_sum, g_zone_max_num);
    }

    entry = cfg_get_entry(cfg, sec_name, "zone_qps_quota");
    if(entry == NULL) {
        printf("section[%s]: missing entry zone_qps_quota\n", sec_name);
        return -1;
    }
    g_zone_qps_quota = (uint64_t)atoi(entry);
    if(g_zone_qps_quota == 0) {
        printf("section[%s]:g_zone_qps_quota = %lu\n", sec_name, g_zone_qps_quota);
        return -1;
    }

    entry  = cfg_get_entry(cfg, sec_name, "zone_bps_quota");
    if(entry == NULL) {
        printf("section[%s]: missing entry zone_bps_quota\n", sec_name);
        return -1;
    }
    g_zone_bps_quota = (uint64_t)atoi(entry);
    if(g_zone_bps_quota == 0) {
        printf("section[%s]:g_zone_bps_quota = %lu\n", sec_name, g_zone_bps_quota);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "domain_qps_quota");
    if(entry == NULL) {
        printf("section[%s]: missing entry domain_qps_quota\n", sec_name);
        return -1;
    }
    g_domain_qps_quota = (uint64_t)atoi(entry);
    if(g_domain_qps_quota == 0) {
        printf("section[%s]:g_domain_qps_quota = %lu\n", sec_name, g_domain_qps_quota);
        return -1;
    }

    entry  = cfg_get_entry(cfg, sec_name, "domain_bps_quota");
    if(entry == NULL) {
        printf("section[%s]: missing entry domain_bps_quota\n", sec_name);
        return -1;
    }
    g_domain_bps_quota = (uint64_t)atoi(entry);
    if(g_domain_bps_quota == 0) {
        printf("section[%s]:g_domain_bps_quota = %lu\n", sec_name, g_domain_bps_quota);
        return -1;
    }

    entry  = cfg_get_entry(cfg, sec_name, "time_interval");
    if(entry == NULL) {
        printf("section[%s]: missing entry time_interval\n", sec_name);
        return -1;
    }
    g_time_interval = (uint64_t)atoi(entry);
    if(g_time_interval == 0) {
        printf("section[%s]: g_time_interval = %lu\n", sec_name, g_time_interval);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "large_weight");
    if (entry == NULL) {
        printf("section[%s]: missing entry large_weight\n", sec_name);
        return -1;
    }
    g_large_weight = (uint32_t)atoi(entry);
    if (g_large_weight == 0 || g_large_weight > 100) {
        printf("section[%s]: g_large_weight = %d\n", sec_name, g_large_weight);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "node_qps_valid_duration");
    if(entry == NULL) {
        printf("section[%s]: missing entry node_qps_valid_duration\n", sec_name);
        return -1;
    }
    g_node_qps_valid_duration = (uint64_t)atoi(entry);
    if(g_node_qps_valid_duration == 0) {
        printf("section[%s]: g_node_qps_valid_duration = %lu\n", sec_name, g_node_qps_valid_duration);
        return -1;
    }
    g_node_qps_valid_duration *= 1L * rte_get_timer_hz();

    return 0;
}

static int cfg_load_qps_limit(struct cfg_file *cfg)
{
    const char *entry;
    char sec_name[CFG_NAME_LEN];

    snprintf(sec_name, sizeof(sec_name), "qps_limit");

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "dnssec_qps_limit_on");
    if (entry == NULL) {
        printf("section[%s]: missing entry dnssec_qps_limit_on\n", sec_name);
        return -1;
    }
    g_dnssec_qps_limit_on = (uint32_t) atoi(entry);

    entry = cfg_get_entry(cfg, sec_name, "dnssec_zone_qps_quota");
    if (entry == NULL) {
        printf("section[%s]: missing entry dnssec_zone_qps_quota\n", sec_name);
        return -1;
    }
    g_dnssec_zone_qps_quota = (uint32_t) atoi(entry);

    entry = cfg_get_entry(cfg, sec_name, "dnssec_ip_qps_quota");
    if (entry == NULL) {
        printf("section[%s]: missing entry dnssec_ip_qps_quota\n", sec_name);
        return -1;
    }
    g_dnssec_ip_qps_quota = (uint32_t) atoi(entry);

    entry = cfg_get_entry(cfg, sec_name, "dnssec_qps_quota");
    if (entry == NULL) {
        printf("section[%s]: missing entry dnssec_qps_quota\n", sec_name);
        return -1;
    }
    g_dnssec_qps_quota = (uint32_t) atoi(entry);

    return 0;
}


static int cfg_load_syslog(struct cfg_file *cfg)
{
    int i, j;
    uint32_t client_start_port, client_end_port;
    const char *entry;
    char sec_name[CFG_NAME_LEN];

    memset((void*)&g_syslog_ctl, 0, sizeof(struct adns_syslog));

    snprintf(sec_name, sizeof(sec_name), "syslog");

    if (cfg_has_section(cfg, sec_name) == 0) {
        printf("Cannot get section: [%s]\n", sec_name);
        return -1;
    }

    entry = cfg_get_entry(cfg, sec_name, "syslog_server_ip");
    if (entry == NULL) {
        return -2;
    }
    g_syslog_ctl.ipv4_dst_addr = inet_addr(entry);
    if (g_syslog_ctl.ipv4_dst_addr == INADDR_NONE) {
        printf("section[%s]: syslog_server_ip ERROR\n", sec_name);
        return -3;
    }

    entry = cfg_get_entry(cfg, sec_name, "syslog_server_port");
    if (entry == NULL) {
        printf("section[%s]: syslog_server_port ERROR\n", sec_name);
        return -4;
    }
    g_syslog_ctl.dst_port = (uint16_t)atoi(entry);

    entry = cfg_get_entry(cfg, sec_name, "syslog_client_port_range");
    if (entry == NULL) {
        printf("section[%s]: syslog_client_port_range ERROR\n", sec_name);
        return -5;
    }

    printf("entry[syslog_client_port_range]: %s\n", entry);
    if (str_to_unsigned_vals(entry, strlen(entry), ',', 2, &client_start_port, &client_end_port) !=  2) {
        return -6;
    }

    if (client_end_port < client_start_port) {
        return -7;
    }

    g_syslog_ctl.max_port = client_end_port - client_start_port + 1;
    if (g_syslog_ctl.max_port >= ADNS_SYSLOG_PORT_SIZE) {
        return -8;
    }

    for (i = 0; i < g_syslog_ctl.max_port; i++) {
        for (j = 0; j < RTE_MAX_LCORE; j++) {
            g_syslog_ctl.current_port[j] = 0;
            g_syslog_ctl.src_port[j][i] = client_start_port + i;
        }
    }

    entry = cfg_get_entry(cfg, sec_name, "syslog_tag");
    if (entry == NULL) {
        return -9;
    }

    if (strlen(entry) >= ADNS_SYSLOG_TAG_MAX_LEN) {
        printf("section[%s]: syslog_tag ERROR\n", sec_name);
        return -10;
    }
    strcpy(g_syslog_ctl.tag, entry);

    entry = cfg_get_entry(cfg, sec_name, "estimated_domain_num");
    if (entry == NULL) {
        printf("section[%s]: estimated_domain_num ERROR\n", sec_name);
        return -11;
    }
    g_syslog_ctl.estimated_domain_num = (uint32_t)atoi(entry);

    entry = cfg_get_entry(cfg, sec_name, "domain_sta_on");
    if (entry == NULL) {
        printf("section[%s]: domain_sta_on ERROR\n", sec_name);
        return -12;
    }
    g_syslog_ctl.domain_sta_on = (uint32_t)atoi(entry);

    entry = cfg_get_entry(cfg, sec_name, "domain_sta_log_on");
    if (entry == NULL) {
        printf("section[%s]: domain_sta_log_on ERROR\n", sec_name);
        return -13;
    }
    g_syslog_ctl.domain_sta_log_on = (uint32_t)atoi(entry);

    entry = cfg_get_entry(cfg, sec_name, "sta_send_interval");
    if (entry == NULL) {
        printf("section[%s]: sta_send_interval ERROR\n", sec_name);
        return -14;
    }
    g_syslog_ctl.sta_send_interval = (uint32_t) atoi(entry);

    printf("cfg_log_syslog success!\n");
    return 0;
}


/* load configuration profile */
static int app_load_cfg_profile(void)
{
    struct cfg_file *cfg_file;

    if (cfg_profile == NULL) {
        RTE_LOG(ERR, ADNS, "No configuration profile\n");
        return -1;
    }

    cfg_file = cfg_load(cfg_profile, 0);
    if (cfg_file == NULL) {
        RTE_LOG(ERR, ADNS, "Cannot load configuration profile %s\n", cfg_profile);
        return -2;
    }

    /* for nic */
    if (cfg_load_nic(cfg_file) < 0) {
        RTE_LOG(ERR, ADNS, "Failed to load section[%s] of %s\n", "NIC", cfg_profile);
        return -3;
    }

    /* for ospf */
    if (cfg_load_ospf(cfg_file) < 0) {
        RTE_LOG(ERR, ADNS, "Failed to load section[%s] of %s\n", "OSPF", cfg_profile);
        return -4;
    }

    /* for server */
    if (cfg_load_server(cfg_file) < 0) {
        RTE_LOG(ERR, ADNS, "Failed to load section[%s] of %s\n", "SERVER", cfg_profile);
        return -6;
    }

    /* for conf*/
    if (cfg_load_conf(cfg_file) < 0) {
        RTE_LOG(ERR, ADNS, "Failed to load section[%s] of %s\n", "CONF", cfg_profile);
        return -7;
    }

    /* for syslog*/
    if (cfg_load_syslog(cfg_file) < 0) {
        RTE_LOG(ERR, ADNS, "Failed to load section[%s] of %s\n", "SYSLOG", cfg_profile);
        return -8;
    }

    /* for qps limit */
    if (cfg_load_qps_limit(cfg_file) < 0) {
        RTE_LOG(ERR, ADNS, "Failed to load section[%s] of %s\n", "QPS_LIMIT",  cfg_profile);
        return -8;
    }

    cfg_close(cfg_file);

    return 0;
}

static void app_assign_io_ids(void)
{
    uint32_t lcore, io_id;

    /* Assign ID for each ioer */
    io_id = 0;
    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore ++) {
        struct lcore_params_io *lp_io = &app.lcore_params[lcore].io;

        if (app.lcore_params[lcore].type != e_LCORE_IO) {
            continue;
        }

        lp_io->io_id = io_id;
        io_id++;
    }
}


/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
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
                            "Mbps - %s\n", (uint8_t)portid,
                            (unsigned)link.link_speed,
                            (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                            ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                            (uint8_t)portid);
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
			RTE_LOG(ERR, ADNS, "TX queue stats mapping not supported port id=%d\n",
                    port_id);
		}
		else
			RTE_LOG(ERR, ADNS, "set_tx_queue_stats_mapping_registers "
					"failed for port id=%d diag=%d\n", port_id, diag);

        return diag;
	}

	diag = set_rx_queue_stats_mapping_registers(port_id);
	if (diag != 0) {
		if (diag == -ENOTSUP) {
			RTE_LOG(ERR, ADNS, "RX queue stats mapping not supported port id=%d\n",
                    port_id);
		}
		else
			RTE_LOG(ERR, ADNS, "set_rx_queue_stats_mapping_registers "
					"failed for port id=%d diag=%d\n", port_id, diag);
	}
    return diag;
}

static void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
    printf("%s%02X:%02X:%02X:%02X:%02X:%02X", name,
            eth_addr->addr_bytes[0],
            eth_addr->addr_bytes[1],
            eth_addr->addr_bytes[2],
            eth_addr->addr_bytes[3],
            eth_addr->addr_bytes[4],
            eth_addr->addr_bytes[5]);
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

void print_reta_conf(int port_id, int reta_size)
{
    unsigned i, ret, idx, shift;
    struct rte_eth_rss_reta_entry64 reta_conf[8];

    for (i = 0; i < reta_size / RTE_RETA_GROUP_SIZE; i++) {
        reta_conf[i].mask = ~0LL;
    }

    ret = rte_eth_dev_rss_reta_query(port_id, reta_conf, reta_size);
    if (ret != 0) {
        printf("Failed to get RSS RETA info, return code = %d\n", ret);
        return;
    }

    for (i = 0; i < reta_size; i++) {
        idx = i / RTE_RETA_GROUP_SIZE;
        shift = i % RTE_RETA_GROUP_SIZE;
        printf("RSS RETA configuration: port=%u, hash index=%u, queue=%u\n",
                    port_id, i, reta_conf[idx].reta[shift]);
    }
    return;
}

static int adns_port_rss_config(int port_id, int nb_rx_queue)
{
    int ret;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rss_reta_entry64 reta_conf[8];

    /* get reta size */
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    if (dev_info.reta_size == 0) {
        RTE_LOG(ERR, ADNS, "Redirection table size is 0 which is invalid for RSS\n");
        return -1;
    } else if (dev_info.reta_size > ETH_RSS_RETA_SIZE_512) {
        RTE_LOG(ERR, ADNS, "Currently do not support more than %u entries of "
            "redirection table\n", ETH_RSS_RETA_SIZE_512);
        return -2;
    } else {
        RTE_LOG(ERR, ADNS, "The reta size of port %d is %u\n", port_id, dev_info.reta_size);
    }

    gen_reta_conf(nb_rx_queue, reta_conf, dev_info.reta_size);
    ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, dev_info.reta_size);
    if (ret != 0) {
        RTE_LOG(ERR, ADNS, "Bad redirection table parameter, return code = %d \n", ret);
        return -3;
    }
    //print_reta_conf(port_id, dev_info.reta_size);
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
    int i;
    int ret = -1;
    struct rte_eth_fdir_filter entry;

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
    inset_conf->field[0] = RTE_ETH_INPUT_SET_L4_TCP_DST_PORT;
    inset_conf->op = RTE_ETH_INPUT_SET_SELECT;

    ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_SET, &fdir_info);
    if (ret < 0) {
        printf("flow director programming error: (%s)\n", strerror(-ret));
        return -4;
    }

    memset(&fdir_info6, 0, sizeof(struct rte_eth_fdir_filter_info));
    fdir_info6.info_type = RTE_ETH_FDIR_FILTER_INPUT_SET_SELECT;
    inset_conf = &(fdir_info6.info.input_set_conf);
    inset_conf->flow_type = RTE_ETH_FLOW_NONFRAG_IPV6_TCP;
    inset_conf->inset_size = 1;
    inset_conf->field[0] = RTE_ETH_INPUT_SET_L4_TCP_DST_PORT;
    inset_conf->op = RTE_ETH_INPUT_SET_SELECT;

    ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_SET, &fdir_info6);
    if (ret < 0) {
        printf("flow director programming error: (%s)\n", strerror(-ret));
        return -5;
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
            return -2;
        }

#ifdef __SUPPORT_NIC_XL710
        entry6.soft_id = soft_id ++;
        entry6.input.flow.tcp6_flow.dst_port = rte_cpu_to_be_16(tcp_port);

        ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_ADD, &entry6);
        if (ret < 0) {
            printf("flow director programming error: (%s)\n", strerror(-ret));
            return -3;
        }
#endif

        printf("FDIR accept TCP port %u\n", tcp_port);
    }

    fdir_get_infos(port);
    return 0;
}

/* Initialize all NIC port */
static int app_init_nics(void)
{
    uint32_t lcore;
    uint8_t port, queue;
    int ret;
    uint32_t n_rx_queues, n_tx_queues;

    if (rte_eth_dev_count() == 0) {
        RTE_LOG(ERR, ADNS, "No Ethernet port - bye\n");
        return -1;
    }

    /* Init NIC ports and queues, then start the ports */
    for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
        struct rte_mempool *pool;

        n_rx_queues = get_nic_rx_queues_per_port(port);
        n_tx_queues = get_nic_tx_queues_per_port(port);

        if (app.port_enabled[port] == 1)
            RTE_LOG(ERR, ADNS, "Port[%d]: rx queues - %d, tx queues - %d\n",
                    port, n_rx_queues, n_tx_queues);

        if ((n_rx_queues == 0) && (n_tx_queues == 0)) {
            continue;
        }

        /* Init port */
        RTE_LOG(ERR, ADNS, "Initializing NIC port %u ...\n", (unsigned) port);
        ret = rte_eth_dev_configure(
                port,
                (uint8_t) n_rx_queues,
                (uint8_t) n_tx_queues,
                &port_conf);
        if (ret < 0) {
            RTE_LOG(ERR, ADNS, "Cannot init NIC port %u (%d)\n", (unsigned) port, ret);
            return -1;
        }

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
                RTE_LOG(ERR, ADNS, "Cannot get lcore for port[%u]-queue[%u]\n",
                        (unsigned)port, (unsigned)queue);
                return -1;
            }

            if (queue == 0) {
                pool = kni_pktmbuf_pool;
            } else
                pool = app.lcore_params[lcore].pool;

            RTE_LOG(ERR, ADNS, "Initializing NIC port %u RX queue %u On lcore[%u] ...\n",
                    (unsigned) port, (unsigned) queue, (unsigned)lcore);
            ret = rte_eth_rx_queue_setup(
                    port,
                    queue,
                    (uint16_t) app.nic_rx_ring_size,
                    0,
                    &rx_conf,
                    pool);
            if (ret < 0) {
                RTE_LOG(ERR, ADNS, "Cannot init RX queue %u for port %u (%d)\n",
                        (unsigned) queue, (unsigned) port, ret);
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
                RTE_LOG(ERR, ADNS, "Cannot get lcore for port[%u]-queue[%u]\n",
                        (unsigned)port, (unsigned)queue);
                return -1;
            }

            RTE_LOG(ERR, ADNS, "Initializing NIC port %u TX queue %u On lcore[%u] ...\n",
                    (unsigned) port, (unsigned) queue, (unsigned)lcore);

            ret = rte_eth_tx_queue_setup(
                    port,
                    queue,
                    (uint16_t) app.nic_tx_ring_size,
                    0,
                    &tx_conf);
            if (ret < 0) {
                RTE_LOG(ERR, ADNS, "Cannot init TX queue 0 for port %d (%d)\n",
                        port, ret);
                return -1;
            }
        }

        #ifndef __SUPPORT_NIC_MLX
        #ifndef __SUPPORT_NIC_XL710
        /* Mapping per queue stats counters.
        The per queue stats counters would be 0 except queue 0, if don't call this
        function. */
        ret = map_port_queue_stats_mapping_registers(port);
        if (ret < 0) {
            RTE_LOG(ERR, ADNS, "Cannot mapping port queue stats registers for port %d (%d)\n", port, ret);
            return -1;
        }
        #endif
        #endif

        /* Start port */
        ret = rte_eth_dev_start(port);
        if (ret < 0) {
            RTE_LOG(ERR, ADNS, "Cannot start port %d (%d)\n", port, ret);
            return -1;
        }

        ret = adns_port_rss_config(port, n_rx_queues);
        if (ret < 0) {
            RTE_LOG(ERR, ADNS, "Cannot int rss for port %d, ret = %d\n", port, ret);
            return -1;
        }

        if (app.allowed_tcp_port[0] == 0) {
            continue;
        } else {
            ret = adns_port_fdir_config(port);
            if (ret < 0) {
                RTE_LOG(ERR, ADNS, "Cannot int fdir for port %d, ret = %d\n", port, ret);
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

    memcpy(&conf, &port_conf, sizeof(conf));
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
        printf("Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    printf(" ==== Configure network interface of %d %s\n",
            port_id, if_up ? "up" : "down");

    if (if_up != 0) { /* Configure network interface up */
        kni_running = 1;
        /*
         *rte_eth_dev_stop(port_id);
         *ret = rte_eth_dev_start(port_id);
         */
    } else /* Configure network interface down */
        kni_running = 0;
    /*rte_eth_dev_stop(port_id);*/

    if (ret < 0)
        printf("Failed to start port %d\n", port_id);

    return ret;
}

uint8_t nb_sys_ports;

/* port rte_kni_create() from older version of dpdk,
 * which is now deprecated and removed out,
 * for api compatibility with other adns code. */
static struct rte_kni *
adns_kni_create(uint8_t port_id,
           unsigned mbuf_size,
           struct rte_mempool *pktmbuf_pool,
           struct rte_kni_ops *ops)
{
    uint32_t lcore_k = 0;
    struct rte_kni_conf conf;
    struct rte_eth_dev_info info;

    memset(&info, 0, sizeof(info));
    memset(&conf, 0, sizeof(conf));
    rte_eth_dev_info_get(port_id, &info);

    snprintf(conf.name, sizeof(conf.name), "vEth%u", port_id);
    conf.addr = info.pci_dev->addr;
    conf.id = info.pci_dev->id;
    conf.group_id = (uint16_t)port_id;
    conf.mbuf_size = mbuf_size;

    lcore_k = kni_port_info_kcore[port_id];
    if (lcore_k != 0) {
        conf.core_id = lcore_k;
        conf.force_bind = 1; 
    }

    /* Save the port id for request handling */
    ops->port_id = port_id;

    return rte_kni_alloc(pktmbuf_pool, &conf, ops);
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
        RTE_LOG(ERR, ADNS, "No supported Ethernet devices found - "
                "check that CONFIG_RTE_LIBRTE_IGB_PMD=y and/or "
                "CONFIG_RTE_LIBRTE_IXGBE_PMD=y in the config file");
        return-1;
    }
    rte_kni_init(nb_sys_ports);

    /* Find the number of configured ports in the port mask */
    for (i = 0; i < sizeof(app.portmask) * 8; i++)
        cfg_ports += !! (app.portmask & (1 << i));

    if (cfg_ports > nb_sys_ports) {
        RTE_LOG(ERR, ADNS, "Port mask requires more ports than available");
        return -1;
    }

    /* Initialise each port */
    for (port = 0; port < nb_sys_ports; port++) {
        struct rte_kni *kni;

        /* Skip ports that are not enabled */
        if ((app.portmask & (1 << port)) == 0) {
            continue;
        }

        if (port >= RTE_MAX_ETHPORTS) {
            RTE_LOG(ERR, ADNS, "Can not use more than "
                    "%d ports for kni\n", RTE_MAX_ETHPORTS);
            return -1;
        }

        kni = adns_kni_create(port, KNI_MAX_PACKET_SZ, kni_pktmbuf_pool,
                &kni_ops);
        if (kni == NULL) {
            RTE_LOG(ERR, ADNS, "Fail to create kni dev "
                    "for port: %d\n", port);
            return -1;
        }
        kni_port_info[port] = kni;
    }
    return 0;
}

static int init_hostname()
{
    int ret;
    const char *last_dot;

    ret = gethostname(g_hostname, MAX_HOSTNAME_LEN);
    printf("System's host name is %s\n", g_hostname);
    if (ret != 0) {
        return ret;
    }
    g_hostname_len = strlen(g_hostname);

    /* If g_hostname is r10l19274.sqa.zmf, last_dot point to the second dot */
    last_dot = strrchr(g_hostname, '.');
    if (last_dot == NULL) {
        return -1;
    }

    /* If g_hostname is r10l19274.sqa.zmf, g_idcname is zmf */
    memcpy(g_idcname, last_dot + 1, strlen(g_hostname) - (last_dot - g_hostname) - 1);
    printf("IDC name is %s\n", g_idcname);
    return 0;
}


/*
 * ADNS main initialization routine.
 */
int adns_init(void)
{
    uint32_t total_counter;

    if (app_load_cfg_profile() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to load config file\n");
        return -1;
    }

    if (log_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init log\n");
        return -2;
    }

    app_assign_io_ids();

    if (app_init_mbuf_pools() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init mbuf mempool\n");
        return -3;
    }

    if (app_init_knis() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init knis\n");
        return -4;
    }

    if (app_init_nics() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init nics\n");
        return -5;
    }

    if (qps_limit_init() < 0) { 
        RTE_LOG(ERR, ADNS, "Failed to init qps limit\n");
        return -11; 
    }

    if (msg_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init msg\n");
        return -6;
    }

    if (view_map_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to load view map file: %s\n", g_view_map_file);
        return -7;
    }

    if (iplib_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init ip geo info lib\n");
        return -8;
    }

    if (adns_zonedb_load_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init zonedb\n");
        return -9;
    }

    #if ZONE_CNT  
    total_counter = g_zone_max_num + g_domain_max_num + ADNS_RCODE_COUNTER_MAX + ADNS_PKT_DROP_COUNTER_MAX;
    #else
    total_counter = g_domain_max_num + ADNS_RCODE_COUNTER_MAX + ADNS_PKT_DROP_COUNTER_MAX;
    #endif
    if(adns_counter_init(total_counter) < 0){
        RTE_LOG(ERR, ADNS, "Failed to init adns counter\n");
        return -1;
    }

    if(adns_rcode_counter_init() < 0){
		RTE_LOG(ERR, ADNS, "Failed to init adns rcode counter\n");
		return -1;
	}
    if(adns_drop_pkt_counter_init() < 0){
        RTE_LOG(ERR, ADNS, "Failed to init adns drop packet counter\n");
        return -1; 
    }    

    if (admin_init(NULL) < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init admin lcore\n");
        return -1;
    }
    
    if(init_mbuf() < 0){
        RTE_LOG(ERR, ADNS, "Failed to init mbuf\n");
        return -1;
    }

    if(init_hostname() < 0){
        RTE_LOG(ERR, ADNS, "Failed to init hostname\n");
        return -1;
    }

	if (adns_stats_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init stats\n");
        return -1;
    }

    if(rcu_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init rcu\n");
        return -1;
    }

    if (admin_init_client_extbuf_pool() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init client pool\n");
        return -1;
    }

    // Register DPDK mem functions so that openssl can use huge page memory
    if (adns_register_openssl_mem_functions() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to register new mem functions\n");
        return -1;
    }

    // Init adns dnssec key
    if (adns_init_dnssec_key() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init dnssec key pool\n");
        return -1;
    }

    // Init adns zsk ctrl
    if (adns_zone_zsk_ctr_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init zone zsk ctr pool\n");
        return -1;
    }

    // Init nsec bitmap
    if (adns_init_nsec_bit_map() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init NSEC bit map table\n");
        return -1;
    }

    // Init DNSSEC cache db
    if (adns_dnssec_cache_db_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init DNSSEC cache db\n");
        return -1;
    }

    // Init DNSSEC cache msg
    if (dnssec_cache_msg_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init DNSSEC cache msg\n");
        return -1;
    }

    // Init qps quota
    if (qps_limit_init() < 0) {
        RTE_LOG(ERR, ADNS, "Failed to init qps limit\n");
        return -1;
    }

    RTE_LOG(INFO, ADNS, "Initialization completed.\n");

    return 0;
}

void adns_cleanup(void)
{
	adns_stats_cleanup();
    log_cleanup();
}

