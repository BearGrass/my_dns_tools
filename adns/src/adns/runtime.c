#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>

#include <rte_kni.h>
#include <rte_core.h>
#include <rte_ip.h>
#include <rte_ethdev.h>

#include "datapath.h"
#include "net_debug.h"
#include "adns.h"
#include "ae.h"
#include "admin.h"
#include "msg.h"
#include "adns_utili.h"
#include "syslog.h"
#include "log.h"
#include "utili_base.h"
#include "adns_stats.h"
#include "ring_list.h"
#include "syslog.h"
#include "adns_counter.h"
#include "rcu.h"
#include "consts.h"
#include "dns_pkt.h"
#include "qps_limit.h"
#include "dnssec_cache_msg.h"

extern char g_time_str[40];

uint64_t HZ = 0;
uint64_t tsc_per_us = 0;
uint16_t RCU_INTER = 0;

extern int tcp_send_rst53_kni(struct rte_mbuf *m, struct tcp_hdr * tcph, union common_ip_head *ip_head, struct ether_hdr * eth_hdr, uint8_t port, int isipv6);
extern int tcp_in_rate(struct rte_mbuf *m, struct tcp_hdr * tcph, union common_ip_head* ip_head, uint8_t port, int isipv6);
extern int kni_in_pps_pass(uint8_t *print);
extern int tcp_kni_in(struct rte_mbuf *m, union common_ip_head *ip_head, int isipv6);

/* Send burst of packets on an output interface */
static inline int send_burst(struct lcore_params_io *qconf, uint16_t n, uint8_t port,
        uint16_t queueid)
{
    struct rte_mbuf **m_table;
    int ret;

    m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

    ret = rte_eth_tx_burst(port, queueid, m_table, n);
    if (unlikely(ret < n)) {
        /* Retry until send all packets completely */
        do {
            n -= ret;
            m_table += ret;
            ret = rte_eth_tx_burst(port, queueid, m_table, n);
        } while (ret < n);
    }

    return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
int send_single_packet(struct rte_mbuf *m, uint8_t port)
{
    uint16_t len;
    struct lcore_params_io *qconf;

    qconf = &app.lcore_params[rte_lcore_id()].io;
    len = qconf->tx_mbufs[port].len;
    qconf->tx_mbufs[port].m_table[len] = m;
    len++;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst(qconf, MAX_PKT_BURST, port, qconf->tx_queues[port]);
        len = 0;
    }

    qconf->tx_mbufs[port].len = len;
    return 0;
}

/* Send burst of packets on an output interface */
static inline int send_burst_misc(struct lcore_params_misc *qconf, uint16_t n,
        uint8_t port, uint16_t queueid)
{
    struct rte_mbuf **m_table;
    int ret;

    m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

    ret = rte_eth_tx_burst(port, queueid, m_table, n);
    if (unlikely(ret < n)) {
        do {
            rte_pktmbuf_free(m_table[ret]);
        } while (++ret < n);
    }

    return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
int send_single_packet_misc(struct rte_mbuf *m, uint8_t port)
{
    uint16_t len;
    struct lcore_params_misc *qconf;

    qconf = &app.lcore_params[rte_lcore_id()].misc;
    len = qconf->tx_mbufs[port].len;
    qconf->tx_mbufs[port].m_table[len] = m;
    len++;

    /* enough pkts to be sent */
    if (unlikely(len == MAX_PKT_BURST)) {
        send_burst_misc(qconf, MAX_PKT_BURST, port, 0);
        len = 0;
    }

    qconf->tx_mbufs[port].len = len;
    return 0;
}

static void lcore_main_loop_io(void)
{
    int i, nb_rx;
    uint8_t port, queue;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct lcore_params_io *lp;
    struct cycle_use *_cycle_use;
    const uint64_t drain_tsc = (HZ + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    uint64_t prev_tsc = 0, cur_tsc = 0, cur_tsc_1 = 0, rlist_prev_tsc = 0, rcu_tsc = 0;
    const uint64_t sta_slot_tsc = QUERY_STA_BURST_SLOT;

    lp = &app.lcore_params[rte_lcore_id()].io;
    _cycle_use = &g_cycle_usage[rte_lcore_id()];

    if (lp->n_rx_queues == 0) {
        RTE_LOG(INFO, ADNS, "lcore %u has nothing to do\n", rte_lcore_id());
        return;
    }

    RTE_LOG(INFO, ADNS, "entering main loop on I/O lcore %u\n",
            rte_lcore_id());

    /* init which TX <port, queue> pair this lcore used */
    for (i = 0; i < lp->n_rx_queues; i++) {
        RTE_LOG(INFO, ADNS, "-- lcoreid=%u portid=%hhu rxqueueid=%hhu\n",
                rte_lcore_id(), lp->rx_queues[i].port_id,
                lp->rx_queues[i].queue_id);
    }

    /* Main work routine */
    while (1) {
        /* Read packet from RX queues */
        cur_tsc = rte_rdtsc();
        for (i = 0; i < lp->n_rx_queues; ++i) {
            port = lp->rx_queues[i].port_id;
            queue = lp->rx_queues[i].queue_id;
            if ((nb_rx = rte_eth_rx_burst(port, queue, pkts_burst,
                    MAX_PKT_BURST)) > 0) {
                raw_input_bulk(pkts_burst, nb_rx, port);
            }
        }
        _cycle_use->recv += rte_rdtsc() - cur_tsc;


        /* TX burst queue drain */
        if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
            cur_tsc_1 = rte_rdtsc();

            for (i = 0; i < lp->n_tx_ports; i++) {
                port = lp->tx_ports[i];
                queue = lp->tx_queues[port];
                if (lp->tx_mbufs[port].len != 0) {
                    send_burst(lp, lp->tx_mbufs[port].len, port, queue);
                    lp->tx_mbufs[port].len = 0;
                }
            }

            _cycle_use->send += (rte_rdtsc() - cur_tsc_1);
            prev_tsc = cur_tsc;
        }

        /* rlist iteration for query statistics */
        if (unlikely(cur_tsc - rlist_prev_tsc > sta_slot_tsc)) {
            rlist_iterate(rte_lcore_id() - app.lcore_io_start_id);
            rlist_prev_tsc = cur_tsc;
        }

        if (unlikely(cur_tsc - rcu_tsc > RCU_INTER)) {
            do_rcu_other_lcore(rte_lcore_id());
            rcu_tsc = cur_tsc;
        }
    }
}

/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

static void burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
    unsigned i;

    if (pkts == NULL)
        return;

    for (i = 0; i < num; i++) {
        rte_pktmbuf_free(pkts[i]);
        pkts[i] = NULL;
    }
}

//for misc pps
#define pps_check_misc do { if (kni_in_pps_pass(&print)) {j++;\
                            } else { rte_pktmbuf_free(m); \
                                    log_server_info(rte_lcore_id(), "[%s]: exceed_pps_misc\n", __FUNCTION__);\
                            } } while(0);
static void kni_getmac_and_firewall(uint8_t port_id, struct rte_mbuf **pkts_burst, unsigned nb_rx, 
        struct rte_mbuf **pkts_burst_filtered, unsigned *nb_rx_filtered)
{
    unsigned int i, ret, j=0;
    uint16_t ether_type, l4_proto;
    union common_ip_head *ip_head;
    struct tcp_hdr * tcph;
    struct ether_hdr *eth_hdr;
    struct rte_mbuf *m;
    uint8_t print = 0;

    *nb_rx_filtered = 0;
    if (port_id >= ADNS_SYSLOG_MAX_PORTS) {
        return;
    }

    for (i = 0; i < nb_rx; i++) {
        m = pkts_burst[i];
        pkts_burst_filtered[j] = m;
        eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
        ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
        if (unlikely(ether_type == ETHER_TYPE_ARP)) {
            j++;
            continue;
        } else if (unlikely(ether_type != ETHER_TYPE_IPv4 && ether_type != ETHER_TYPE_IPv6)) {
            pps_check_misc;
            continue;
        }

        ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) + sizeof(struct ether_hdr));
        if (unlikely(is_valid_ipv4v6_pkt(m, ip_head, ether_type == ETHER_TYPE_IPv6) < 0)) {
            pps_check_misc;
            continue;
        }

        l4_proto = (ether_type == ETHER_TYPE_IPv4) ? ip_head->ipv4_hdr.next_proto_id : ip_head->ipv6_hdr.proto; 
        if (l4_proto != IPPROTO_OSPFIGP && l4_proto!= IPPROTO_TCP) {
            /*for pkts not ospf or tcp */
            pps_check_misc;
            continue;
        }

        ether_addr_copy(&eth_hdr->s_addr, &g_syslog_ctl.d_addr[port_id]);

        if (unlikely(l4_proto == IPPROTO_OSPFIGP)) { //ospf received here 
            j++;
            continue;
        }

        STATS_INC(tcp_in);
        if (unlikely(is_valid_tcp_pkt(m, &tcph, ether_type == ETHER_TYPE_IPv6) < 0)) {
            pps_check_misc;
            continue;
        }

        if (BE_BGP_PORT == tcph->dst_port) { //for bgp
            j++;
            continue;
        }

        //for kni pps
        if (tcp_kni_in(m, ip_head, ether_type == ETHER_TYPE_IPv6) == ADNS_PKT_DROP) {
            rte_pktmbuf_free(m);
            continue;
        }

        if (unlikely(sysctl_tcp_in_53_drop)) {
            ret = tcp_send_rst53_kni(m, tcph, ip_head, eth_hdr, port_id, ether_type == ETHER_TYPE_IPv6);
            if (ADNS_PKT_DROP == ret) {
                STATS_INC(tcp_in_53_drop);
            }else {
                j++;
            }
        } else if(sysctl_tcp_in_53_rate) {
            ret = tcp_in_rate(m, tcph, ip_head, port_id, ether_type == ETHER_TYPE_IPv6);
            if (ADNS_PKT_DROP == ret) {
                STATS_INC(tcp_in_53_drop);
                rte_pktmbuf_free(m);
            } else {
                j++;
            }
        } else {
            j++;
        }
    }

    *nb_rx_filtered = j;
}


/*
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static void kni_egress(uint8_t port_id, struct rte_kni *kni)
{
    unsigned nb_tx, num;
    struct rte_mbuf *pkts_burst[KNI_PKT_BURST_SZ];

    if (kni == NULL || port_id >= RTE_MAX_ETHPORTS)
        return;

    /* Burst rx from kni */
    num = rte_kni_rx_burst(kni, pkts_burst, KNI_PKT_BURST_SZ);
    if (num > KNI_PKT_BURST_SZ) {
        return;
    }

    if (num == 0)
        return;

#if 0
    /* Dump packet info */
    RTE_LOG(INFO, ADNS, "Port[%"PRIu8"], === OUTPUT, num: %u\n", port_id, num);
    for (i = 0; i < num; i++)
        adns_pkt_dump(port_id, pkts_burst[i]);
#endif

    /* Burst tx to eth */
    nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, (uint16_t)num);
    kni_stats[port_id].tx_packets += nb_tx;

    if (unlikely(nb_tx < num)) {
        /* Free mbufs not tx to NIC */
        burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
        kni_stats[port_id].tx_dropped += num - nb_tx;
    }
}

/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
static void kni_ingress(uint8_t port_id, struct rte_kni *kni)
{
    unsigned nb_rx, num, nb_rx_filtered;
    struct rte_mbuf *pkts_burst[KNI_PKT_BURST_SZ];
    struct rte_mbuf *pkts_burst_filtered[KNI_PKT_BURST_SZ];

    if (kni == NULL || port_id >= RTE_MAX_ETHPORTS)
        return;

    rte_kni_handle_request(kni);

    /* Burst rx from eth */
    nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, KNI_PKT_BURST_SZ);
    if (nb_rx > 0 && nb_rx <= KNI_PKT_BURST_SZ) {
        kni_getmac_and_firewall(port_id, pkts_burst, nb_rx, pkts_burst_filtered, &nb_rx_filtered);
        STATS_ADD(drop, nb_rx-nb_rx_filtered);

#if 0
        /* Dump packet info */
        RTE_LOG(INFO, ADNS, "Port[%"PRIu8"], === INPUT nb_rx is %d\n", port_id, nb_rx);
        int i;
        for (i = 0; i < nb_rx; i++)
            net_pkt_dump(rte_pktmbuf_mtod(pkts_burst[i], struct ether_hdr *));
#endif

        /* Burst tx to kni */
        num = rte_kni_tx_burst(kni, pkts_burst_filtered, nb_rx_filtered);
        kni_stats[port_id].rx_packets += num;

        if (unlikely(num < nb_rx_filtered)) {
            /* Free mbufs not tx to kni interface */
            burst_free_mbufs(&pkts_burst_filtered[num], nb_rx_filtered - num);
            kni_stats[port_id].rx_dropped += nb_rx_filtered - num;
        }

    }
}

static void msg_ingress(struct msg_info *msg)
{
    unsigned num;
    struct rte_kni *kni;
    uint8_t port_id = msg->port_id;
    struct rte_mbuf *m = msg->m;

    kni = kni_port_info[port_id];
    num = rte_kni_tx_burst(kni, &m, 1);
    kni_stats[port_id].rx_packets += num;
    if (unlikely(num < 1)) {
        rte_pktmbuf_free(m);
        kni_stats[port_id].rx_dropped += 1;
    }
}

static void charge_syslog_time()
{
    struct timeval tv;
    struct tm tm;

    gettimeofday(&tv, NULL);
    localtime_r((const time_t *)&(tv.tv_sec), &tm);
    sprintf(g_time_str, "%04d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900,
            tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void
lcore_main_loop_misc(void)
{
    int i;
    struct lcore_params_misc *lp;
    struct rte_kni *kni;
	struct cycle_use *_cycle_use;
    const uint64_t drain_tsc = (HZ + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    const uint64_t drain_syslog_tsc = (HZ + MS_PER_S - 1) / MS_PER_S * 50;
    uint64_t prev_tsc = 0, cur_tsc = 0, prev_syslog_tsc = 0, rcu_tsc = 0, prev_log_tsc = 0;
	tsc_per_us = (HZ + US_PER_S - 1) / US_PER_S;

    lp = &app.lcore_params[rte_lcore_id()].misc;
	_cycle_use = &g_cycle_usage[rte_lcore_id()];

    while (1) {

        /* Read packet from RX queues */
        cur_tsc = rte_rdtsc();
        for (i = 0; i < nb_sys_ports; i++) {
            kni = kni_port_info[i];
            kni_ingress(i, kni);
        }
        _cycle_use->recv += rte_rdtsc() - cur_tsc;


        /* TX burst queue drain */
        cur_tsc = rte_rdtsc();
        if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
            for (i = 0; i < nb_sys_ports; i++) {
                if (lp->tx_mbufs[i].len == 0)
                    continue;
                send_burst_misc(lp, lp->tx_mbufs[i].len, i, 0);
                lp->tx_mbufs[i].len = 0;
            }
            for (i = 0; i < nb_sys_ports; i++) {
                /* KNI packet process */
                kni = kni_port_info[i];
                kni_egress(i, kni);
            }

            _cycle_use->send += rte_rdtsc() - cur_tsc;
            prev_tsc = cur_tsc;
        }


        if (cur_tsc - prev_syslog_tsc > drain_syslog_tsc) {
            charge_syslog_time();
            prev_syslog_tsc = cur_tsc;
        }

        if(unlikely(cur_tsc - rcu_tsc > RCU_INTER)){
            do_rcu_other_lcore(rte_lcore_id());
            rcu_tsc = cur_tsc;
        }

		/*for log */
        cur_tsc = rte_rdtsc();
        if (unlikely(cur_tsc - prev_log_tsc > drain_tsc * 10)) {
            adns_log_flush();
            _cycle_use->app += (rte_rdtsc() - cur_tsc);
            prev_log_tsc = cur_tsc;
        }

        /* lcore work --> misc packet process */
        {
            struct msg_info *msg;
            msg = msg_w2m_recv();
            if (msg == NULL)
                continue;
            msg_ingress(msg);
        }

    }
}

static void
lcore_main_loop_admin(void)
{
    uint32_t lcore = rte_lcore_id();
    uint64_t prev_tsc = 0, prev2_tsc = 0, cur_tsc = 0, rcu_tsc = 0;
    uint64_t cur_dnssec_cache_handle_tsc = 0, cur_dnssec_cache_clean_tsc = 0;
    uint64_t dnssec_cache_handle_tsc = 0, dnssec_cache_clean_tsc = 0;
    struct cycle_use *_cycle_use = &g_cycle_usage[lcore];
    const uint64_t admin_10us_tsc = (HZ + US_PER_S - 1) / US_PER_S * 10;
    const uint64_t dnssec_cache_50us_tsc = (HZ + US_PER_S - 1) / US_PER_S * 50;
    const uint64_t dnssec_cache_100us_tsc = (HZ + US_PER_S - 1) / US_PER_S * 100;

    while (1) {
        cur_tsc = rte_rdtsc();

        if (unlikely(cur_tsc - prev_tsc > admin_10us_tsc)) {
            aeMain(admin.el);
            if(unlikely(1 == g_exit_now)) {
                // Invoke aeMain again to send response to adns_adm
                aeMain(admin.el);
                rte_exit(0, "Bye!\n");
            }
            _cycle_use->app += (rte_rdtsc() - cur_tsc);
            prev_tsc = cur_tsc;
        }

        /* Handle DNSSEC cache msg */
        if (unlikely(cur_tsc - dnssec_cache_handle_tsc > dnssec_cache_50us_tsc)) {
            cur_dnssec_cache_handle_tsc = rte_rdtsc();
            if (unlikely(handle_dnssec_cache_msg() > 0)) {
                _cycle_use->app += (rte_rdtsc() - cur_dnssec_cache_handle_tsc);
                dnssec_cache_handle_tsc = cur_dnssec_cache_handle_tsc;
            }
        }

        /* Clean DNSSE cache node */
        if (unlikely(cur_tsc - dnssec_cache_clean_tsc > dnssec_cache_100us_tsc)) {
            cur_dnssec_cache_clean_tsc = rte_rdtsc();
            if (adns_dnssec_cache_clean(ADNS_DNSSEC_CLEAN_BULK_NUM) > 0) {
                _cycle_use->app += (rte_rdtsc() - cur_dnssec_cache_clean_tsc);
                dnssec_cache_clean_tsc = cur_dnssec_cache_clean_tsc;
            }
        }

        if (unlikely(cur_tsc - prev2_tsc > CPU_UTILI_INTER * HZ) ) {
            cpu_utili_process();
            adns_stats_qps(CPU_UTILI_INTER);
            prev2_tsc = cur_tsc;
        }

        if(unlikely(cur_tsc - rcu_tsc > RCU_INTER)){
            do_rcu_first_lcore();
            rcu_tsc = cur_tsc;
        }
    }
}

int lcore_main_loop(__attribute__((unused)) void *arg)
{
    struct lcore_params *lp;
    unsigned lcore;
    HZ = rte_get_tsc_hz();
	tsc_per_us = (HZ + US_PER_S - 1) / US_PER_S;
    RCU_INTER = (HZ / 1000);

    lcore = rte_lcore_id();
    lp = &app.lcore_params[lcore];

    gettimeofday(&lp->start_time, NULL);
    lp->start_cycles = rte_get_timer_cycles();

    if (lp->type == e_LCORE_IO) {
        RTE_LOG(INFO, ADNS, "Logical core %u (I/O %u) main loop.\n",
                lcore, lp->io.io_id);
        lcore_main_loop_io();
    }

    if (lp->type == e_LCORE_ADMIN) {
        RTE_LOG(INFO, ADNS, "Logical core %u (worker) main loop.\n", lcore);
        lcore_main_loop_admin();
    }

    if (lp->type == e_LCORE_MISC) {
        RTE_LOG(INFO, ADNS, "Logical core %u (MISC) main loop.\n", lcore);
        lcore_main_loop_misc();
    }

    return 0;
}


int adns_istcpcore(int i)
{
    struct lcore_params *lp;
	if ((i < RTE_MAX_LCORE) && (i>=0)) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_TCP)
            return 1;
    }

    return 0;
}

int tcp_send_rst53_kni_v4(struct rte_mbuf *m, struct tcp_hdr * tcph, struct ipv4_hdr * iph, struct ether_hdr * eth_hdr, uint8_t port)
{
    if (BE_53 != tcph->dst_port) {
        return ADNS_PKT_ACCEPT;
    }

    STATS_INC(tcp_in_53);
    m->l4_len = sizeof(struct tcp_hdr);
    // tcp checksum
    m->ol_flags = PKT_TX_IPV4 | PKT_TX_TCP_CKSUM;
    tcph->cksum = get_psd_sum((void *)iph, ETHER_TYPE_IPv4, m->ol_flags);
    //set rst packets
    l4_rst_output(tcph);

    /* updata ip header total length field */
    //do nothing for total_length,  ip_head->ipv4_hdr.total_length = xx;
    iph->hdr_checksum = 0;
    iph->time_to_live = IPV4_TTL;
    /* L3 layer output process */
    l3_output(iph);
    /* L2 layer output process */
    l2_output(eth_hdr);

    m->ol_flags |= PKT_TX_IP_CKSUM;
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = sizeof(struct ipv4_hdr);

    if(likely(MTU_SIZE >= ((int)m->pkt_len - (int)sizeof(struct ether_hdr)))){
        send_single_packet_misc(m, port);
    } else {
        //drop frag syn
        STATS_INC(fragment_out);
        rte_pktmbuf_free(m);
    }
    return ADNS_PKT_DROP;
}

int tcp_send_rst53_kni_v6(struct rte_mbuf *m, struct tcp_hdr * tcph, union common_ip_head *ip_head, struct ether_hdr * eth_hdr, uint8_t port)
{
    if (BE_53 != tcph->dst_port) {
        return ADNS_PKT_ACCEPT;
    }
    
    STATS_INC(tcp_in_53);

    ip_head->ipv6_hdr.hop_limits = IPV6_TTL;
    /* L2 layer output process */
    l2_output(eth_hdr);
    m->l2_len = sizeof(struct ether_hdr);

    /* L3 layer output process */
    l3_output_ipv6(&(ip_head->ipv6_hdr));
    m->l3_len = sizeof(struct ipv6_hdr);
    m->ol_flags = PKT_TX_IPV6 | PKT_TX_TCP_CKSUM;

    // tcp checksum
    tcph->cksum = get_psd_sum((void *)&ip_head->ipv6_hdr, ETHER_TYPE_IPv6, m->ol_flags);
    //set rst packets
    l4_rst_output(tcph);
    send_single_packet_misc(m, port);

    return ADNS_PKT_DROP;
}

int tcp_send_rst53_kni(struct rte_mbuf *m, struct tcp_hdr * tcph, union common_ip_head *ip_head, struct ether_hdr * eth_hdr, uint8_t port, int isipv6)
{
    if (isipv6)
        return tcp_send_rst53_kni_v6(m, tcph, ip_head, eth_hdr, port);
    else 
        return tcp_send_rst53_kni_v4(m, tcph, &ip_head->ipv4_hdr, eth_hdr, port);
}

int tcp_kni_in(struct rte_mbuf *m, union common_ip_head *ip_head, int isipv6)
{
    uint8_t print = 0;
    uint32_t *sip;

    //for kni
    if (!kni_in_pps_pass(&print)) {
        if (unlikely(print)) {
            if (isipv6) {
                sip = (uint32_t*)ip_head->ipv6_hdr.src_addr; 
                log_server_info(rte_lcore_id(), "[%s]: exceed_pps_tcptotal %x-%x-%x-%x\n", __FUNCTION__, *sip, *(sip+1), *(sip+2), *(sip+3));
            }
            else {
                log_server_info(rte_lcore_id(), "[%s]: exceed_pps_tcptotal %x\n", __FUNCTION__, ip_head->ipv4_hdr.src_addr);
            }
        }
        return ADNS_PKT_DROP;
    }

    return ADNS_PKT_CONTINUE;
}

int tcp_in_rate(struct rte_mbuf *m, struct tcp_hdr * tcph, union common_ip_head* ip_head, uint8_t port, int isipv6)
{
	uint32_t sipv4 = 0;
	uint32_t *sipv6 = 0;
	uint32_t index = 0;
    uint8_t print = 0;
    int ret = 0;

    //for not tcp53_syn
    if ((BE_53 != tcph->dst_port) || !(tcph->tcp_flags & TCP_SYN_FLAG)) {
        return ADNS_PKT_ACCEPT;
    }
    
    //for tcp53_syn
    STATS_INC(tcp_in_53);
    if (isipv6) {
	    ret = rate_proc(ip_limit_tbl + IPLIMIT_SIZE, sysctl_tcp_in_53_total_quota, &print);
    } else {
        sipv4 = ip_head->ipv4_hdr.src_addr; 
	    index = rte_jhash_1word(sipv4, 0) % IPLIMIT_SIZE;
	    ret = rate_proc(ip_limit_tbl + index, sysctl_tcp_in_53_quota, &print) && 
	        rate_proc(ip_limit_tbl + IPLIMIT_SIZE, sysctl_tcp_in_53_total_quota, &print);
    }

    if (!ret) {
        if (unlikely(print)) {
            if (isipv6) {
                sipv6 = (uint32_t*)ip_head->ipv6_hdr.src_addr; 
                log_server_info(rte_lcore_id(), "[%s]: exceed_pps_tcptotal %x-%x-%x-%x\n", __FUNCTION__, 
                    *sipv6, *(sipv6+1), *(sipv6+2), *(sipv6+3));
            } else {
                log_server_info(rte_lcore_id(), "[%s]: exceed_pps_tcptotal %x\n", __FUNCTION__, sipv4);
            }
        }

        STATS_INC(tcp_in_53_drop);
        return ADNS_PKT_DROP;
    }

    return ADNS_PKT_ACCEPT;
}
