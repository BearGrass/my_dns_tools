
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/epoll.h>

#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_kni.h>
#include "rte_core.h"
#include <rte_cycles.h>
#include <rte_timer.h>
#include "common.h"
#include "net_debug.h"
#include "user_config.h"
#include "ldns.h"
#include "view.h"
#include "request.h"
#include "storage.h"
#include "msg.h"
#include "adns_fdir.h"
#include "ae.h"
#include "admin.h"
#include "whitelist.h"
#include "man_whitelist.h"
#include "man_blacklist.h"
#include "blacklist.h"
#include "oversealist.h"
#include "stats.h"
#include "health_check.h"
#include "log.h"
#include "gen_pkt.h"
#include "ipv6_fwd.h"
#include "ip_filter.h"
#include "qos.h"
#include "datapath.h"

/* around 1ms at 2 Ghz */
#define US_BASE ((HZ + US_PER_S - 1) / US_PER_S )
#define MSG_QUEUE_SIZE 32
#define MAX_EVENTS  1000 /* max epoll_event size */
#define MTU_SIZE  1500
#define IPV4_TTL 128
#define DEFAULT_FWD_IP 0x08080808

/*
 * 0: is not dns packet
 * 1: is dns packet
 */
static inline int dns_filter(struct rte_mbuf *m, struct ether_hdr **eth_hdr, union common_ip_head **ip_head,
        struct udp_hdr **uh, struct dns_header **dnh, int *is_ipv6) {
    uint16_t ether_type, ip_pld_len;
    uint8_t l4_proto, l6_proto, offset;
    int ret;
    *is_ipv6 = 0;
    if (m->pkt_len < sizeof(struct ether_hdr)) {
        return 0;
    }
    (*eth_hdr) = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_type = rte_be_to_cpu_16((*eth_hdr)->ether_type);
    switch (ether_type) {
        case ETHER_TYPE_IPv4:
            (*ip_head) = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
                    sizeof(struct ether_hdr));
            if (unlikely(is_valid_ipv4_pkt(&((*ip_head)->ipv4_hdr), m->pkt_len - ETH_HLEN,
                            &ip_pld_len, &offset) < 0)) {
                return 0;
            }
            l4_proto = (*ip_head)->ipv4_hdr.next_proto_id;
            if (l4_proto != IPPROTO_UDP) {
                return 0;
            }
            break;
        case ETHER_TYPE_IPv6:
            *is_ipv6 = 1;
            (*ip_head) = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
                    sizeof(struct ether_hdr));
            if (unlikely((ret = is_valid_ipv6_pkt(&((*ip_head)->ipv6_hdr), m->pkt_len - ETH_HLEN,
                                &ip_pld_len, &offset)) < 0)) {
                return 0;
            }
            l6_proto = (uint8_t)ret;
            if (l6_proto != IPPROTO_UDP) {
                return 0;
            }
            break;
        default:
            return 0;
    }
    (*uh) = (struct udp_hdr*)((uint8_t*)(*ip_head)+ offset);
    if (unlikely(adns_ntohs((*uh)->dgram_len) <= UDP_HLEN + DNS_HLEN)) {
        return 0;
    }
    if (adns_ntohs((*uh)->dst_port) != DNS_PORT) {
        return 0;
    }
    (*dnh) = (struct dns_header *) ((uint8_t *)(*uh) + UDP_HLEN);
    return 1;
}

static inline void msg_output(struct rte_mbuf *m, struct ether_hdr *eth_hdr,
        union common_ip_head *ip_head, struct udp_hdr *udh, int need_swap) {
    if (need_swap) {
        l4_udp_output(udh);
        l3_output(&(ip_head->ipv4_hdr));
        l2_output(eth_hdr);
    }
    m->ol_flags = PKT_TX_IPV4;
    udh->dgram_cksum = 0;
    ip_head->ipv4_hdr.hdr_checksum = 0;
    ip_head->ipv4_hdr.time_to_live = IPV4_TTL;
    m->ol_flags |= PKT_TX_IP_CKSUM;
    m->l2_len = sizeof(struct ether_hdr);
    m->l3_len = sizeof(struct ipv4_hdr);
    ip_head->ipv4_hdr.hdr_checksum = rte_ipv4_cksum(&ip_head->ipv4_hdr);
}

/* Send burst of packets on an output interface */
static inline int send_burst(struct mbuf_table *m_tbl,
                             uint8_t port, uint16_t queueid)
{
    int ret;
    struct rte_mbuf **mbufs = m_tbl->m_table;

    ret = rte_eth_tx_burst(port, queueid, m_tbl->m_table, m_tbl->len);
    if (unlikely(ret < m_tbl->len)) {
/*        RTE_LOG(INFO, LDNS,
                "send_burst fail,send = %d, total = %d,port =%d,queueid = %d\n ",
                ret, n, port, queueid);*/
        STATS(SEND_PKT_FAIL);
        /* Retry until send all packets completely */
        do {
            m_tbl->len -= ret;
            mbufs += ret;
            ret = rte_eth_tx_burst(port, queueid, mbufs, m_tbl->len);
        } while (ret < m_tbl->len);
    }
    m_tbl->len = 0;

    return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline void __send_single_frame(struct mbuf_table *m_tbl,
        struct rte_mbuf *m, uint8_t port, uint16_t queueid)
{
    m_tbl->m_table[m_tbl->len++] = m;

    /* enough pkts to be sent */
    if (unlikely(m_tbl->len == MAX_PKT_BURST)) {
        send_burst(m_tbl, port, queueid);
    }
}

/* Enqueue a single packet, and send burst if queue is filled */
void send_single_frame(struct rte_mbuf *m, uint8_t port)
{
    uint32_t lcore_id;
    struct lcore_params_io *qconf;

    lcore_id = rte_lcore_id();
    qconf = &app.lcore_params[lcore_id].io;
    __send_single_frame(&qconf->tx_mbufs[port], m, port,
            qconf->tx_port_queue[port]);
}

static inline int msg_process(void)
{
    int i, num;
    struct lcore_msg_info *msg_queue[MSG_QUEUE_SIZE];

    /*
    if(charge_task_pending()){
        return 0;
    }
    */
    num = lcore_msg_bulk_recv(msg_queue);

    if (num != 0) {
        for (i = 0; i < num; i++) {
            struct lcore_msg_info *msg = msg_queue[i];
            switch (msg->opcode) {
                case MSG_FORWARDER_STATE:
                    lcore_forwarder_state_share((uint8_t *)msg->pcmd.data, msg->pcmd.len);
                    put_cmd_msg(msg);
                    break;
                case MSG_DEL_KEY:
                    del_key((uint8_t *)msg->pcmd.data, msg->pcmd.len);
                    put_cmd_msg(msg);
                    break;
                case MSG_DEL_REG_KEYS:
                    del_reg_keys(msg->pcmd.data, msg->pcmd.len);
                    break;
                case MSG_PRO_START:
                    build_protect_regex(msg->pcmd.data, msg->pcmd.len);
                    put_cmd_msg(msg);
                    break;
                case MSG_PRO_STOP:
                    clean_protect_regex();
                    put_cmd_msg(msg);
                    break;
                case MSG_DEL_ALL_KEY:
                    del_all_key();
                    put_cmd_msg(msg);
                    break;
                case MSG_PREFETCH_NODE:
                    specified_node_prefetch(&msg->pnode);
                    lcore_msg_free(msg);
                    break;
                case MSG_REQ_FWD:
                    STATS(IPC_MSG_REVC);
                    msg_input(&msg->pfwd);
                    lcore_msg_free(msg);
                    break;
                default:
                    STATS(UNKNOWN_IPC_MSG);
                    lcore_msg_free(msg);
            }
        }
    } else {
        return -1;
    }
    return 0;
}

static void lcore_main_loop_io(void)
{
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S
        * BURST_TX_DRAIN_US;

    uint64_t diff_tsc, cur_tsc, diff_timer_tsc, diff_ttl_tracker_tsc,
        diff_forwarder_tsc, diff_msg_tsc;
    uint64_t prev_tsc = 0;
    uint64_t pre_timer_tsc = 0;
    uint64_t pre_ttl_tracker_tsc = 0;
    uint64_t pre_forwarder_tsc = 0;
    uint64_t prev_msg_tsc = 0;
    int i, nb_rx, lcore_id, ret;
    int port_id = 0, queue_id;
    uint64_t c1, c2;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct lcore_params_io *lp;
    if (lcore_io_init() < 0) {
        RTE_LOG(ERR, LDNS, "lcore init mempool fail in %s\n", __func__);
        assert(0);
        return;
    }
    lcore_id = rte_lcore_id();
    lp = &app.lcore_params[lcore_id].io;

    if (lp->n_rx_queues == 0) {
        RTE_LOG(INFO, LDNS, "lcore %u has nothing to do\n", lcore_id);
        return;
    }
    gcpu_util[lcore_id].lcore_id = lcore_id;
    cur_tsc = rte_rdtsc();

    while(1) {
        c2 = rte_rdtsc();
        gcpu_util[lcore_id].all += (c2 - cur_tsc);
        cur_tsc = c2;

        /* Read packet from RX queues */
        for (i = 0; i < lp->n_rx_queues; ++i) {
            port_id = lp->rx_queues[i].port_id;
            queue_id = lp->rx_queues[i].queue_id;
            nb_rx =
                rte_eth_rx_burst(port_id, queue_id, pkts_burst, MAX_PKT_BURST);
            if (nb_rx > 0) {
                raw_input_bulk(pkts_burst, nb_rx, port_id);
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].recv += (c2 - c1);
            } else {
                c2 = rte_rdtsc();
            }
        }

        /* TX burst queue drain */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            prev_tsc = cur_tsc;
            for (i = 0; i < lp->n_tx_queues; i++) {
                port_id = lp->tx_queues[i].port_id;
                queue_id = lp->tx_queues[i].queue_id;
                if (lp->tx_mbufs[port_id].len != 0) {
                    send_burst(&lp->tx_mbufs[port_id], port_id, queue_id);
                    c1 = c2;
                    c2 = rte_rdtsc();
                    gcpu_util[lcore_id].send += (c2 - c1);
                } else {
                    c2 = rte_rdtsc();
                }
            }
        }

        diff_timer_tsc = cur_tsc - pre_timer_tsc;
        if (unlikely(diff_timer_tsc > g_timer_exec_interval* US_BASE)) {
            pre_timer_tsc = cur_tsc;
            ret = health_check_manage();
            if (ret == 0) {
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].hc_send += (c2 - c1);
            } else {
                c2 = rte_rdtsc();
            }

            node_timer_manage(g_forwarder_retry_interval * HZ, 15);
            c1 = c2;
            c2 = rte_rdtsc();
            gcpu_util[lcore_id].retry += (c2 - c1);
        }

        diff_ttl_tracker_tsc = cur_tsc - pre_ttl_tracker_tsc;
        if (unlikely
                (diff_ttl_tracker_tsc >
                        g_ttl_expire_clean_exec_interval * US_BASE)) {
            pre_ttl_tracker_tsc = cur_tsc;
            ttl_expire_check(g_ttl_expire_clean_hash_size);
            c1 = c2;
            c2 = rte_rdtsc();
            gcpu_util[lcore_id].ttl_ck += (c2 - c1);
        }

        diff_forwarder_tsc = cur_tsc - pre_forwarder_tsc;
        if (unlikely(diff_forwarder_tsc > US_BASE * 100)) {
            pre_forwarder_tsc = cur_tsc;
            ret = health_check_timer_manage(g_forwarder_retry_interval * HZ, 1);
            if (ret == 0) {
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].hc_tw += (c2 - c1);
            } else {
                c2 = rte_rdtsc();
            }
        }

        diff_msg_tsc = cur_tsc - prev_msg_tsc;
        if (unlikely(diff_msg_tsc > US_BASE)) {
            prev_msg_tsc = cur_tsc;
            ret = msg_process();
            if (ret == 0) {
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].msg += (c2 - c1);
            } else {
                c2 = rte_rdtsc();
            }
        }
    }
}

static inline void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
    unsigned i;

    for (i = 0; i < num; i++) {
        rte_pktmbuf_free(pkts[i]);
        //pkts[i] = NULL;
    }
}

/*
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static inline int kni_egress(struct lcore_params_kni *lp, uint8_t port_id,
        struct rte_kni *kni)
{
    unsigned nb_rx, num;
    struct rte_mbuf *pkts_burst[KNI_PKT_BURST_SZ];
    struct rte_mbuf *dns_pkts_burst[KNI_PKT_BURST_SZ];

    /* Burst rx from kni */
    nb_rx = rte_kni_rx_burst(kni, pkts_burst, KNI_PKT_BURST_SZ);
    if (nb_rx == 0)
        return 0;

    int i, dns_cnt = 0, ret;
    for (i = 0; i < nb_rx; i ++) {
        struct ether_hdr *eth_hdr = NULL;
        union common_ip_head *ip_head = NULL;
        struct udp_hdr *uh = NULL;
        struct dns_header *dnh = NULL;
        int is_ipv6 = 0;
        int is_tcp = 0;
        int is_dns;
        uint16_t l4_len;
        is_dns = dns_filter(pkts_burst[i], &eth_hdr, &ip_head, &uh, &dnh, &is_ipv6);
        if (is_dns) {
            if (ip_head->ipv4_hdr.dst_addr == DEFAULT_FWD_IP) {
                l4_len = Lntohs(uh->dgram_len) - UDP_HLEN;
                STATS(KNI_DNS_IN);
                ret = dns_input(pkts_burst[i], eth_hdr, ip_head, (union common_l4_head *)uh, l4_len,
                        dnh, port_id, is_ipv6, is_tcp, 1);
                if (ret == IO_RET_ANSWER) {
                    msg_output(pkts_burst[i], eth_hdr, ip_head, uh, 1);
                    dns_pkts_burst[dns_cnt ++] = pkts_burst[i];
                } else if (ret == IO_RET_DROP || ret == IO_RET_FREE) {
                    rte_pktmbuf_free(pkts_burst[i]);
                    continue;
                }
                continue;
            }
        }
        __send_single_frame(&lp->tx_mbufs[port_id], pkts_burst[i], port_id, 0);
    }
    num = rte_kni_tx_burst(kni, dns_pkts_burst, dns_cnt);

    if (unlikely(num < dns_cnt)) {
        /* Free mbufs not tx to kni interface */
        //printf("in %s,tx(dot or doh) to kni fail,ok num is %d/%d\n", __func__, dns_cnt, num);
        kni_burst_free_mbufs(&dns_pkts_burst[num], dns_cnt - num);
        STATS_ADD(KNI_DROP, dns_cnt - num);
    }

    return nb_rx;
}

/* calc icmp chksum.
 * length : byte length of data for checksum */
static inline uint16_t
calc_icmp_chksum(uint8_t *buf, size_t length)
{
    uint32_t cksum;

    cksum = rte_raw_cksum(buf, length);

    cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
    cksum = (~cksum) & 0xffff;
    if (cksum == 0)
        cksum = 0xffff;

    return cksum;
}

/* calc icmpv6 pseudo-header chksum. */
static inline uint16_t
calc_icmpv6_psd_cksum(const struct ipv6_hdr *ipv6_hdr)
{
    uint32_t sum;
    struct {
        uint32_t len;   /* L4 length. */
        uint32_t proto; /* L4 protocol - top 3 bytes must be zero */
    } psd_hdr;

    psd_hdr.len = ipv6_hdr->payload_len;
    psd_hdr.proto = (IPPROTO_ICMPV6 << 24);

    sum = __rte_raw_cksum(ipv6_hdr->src_addr,
        sizeof(ipv6_hdr->src_addr) + sizeof(ipv6_hdr->dst_addr),
        0);
    sum = __rte_raw_cksum(&psd_hdr, sizeof(psd_hdr), sum);
    return __rte_raw_cksum_reduce(sum);
}

/* calc icmpv6 chksum.
 * length : byte length of data for checksum */
static inline uint16_t
calc_icmpv6_chksum(const struct ipv6_hdr *ipv6_hdr, const void *l4_hdr, size_t l4_len)
{
    uint32_t cksum;

    cksum = rte_raw_cksum(l4_hdr, l4_len);
    cksum += calc_icmpv6_psd_cksum(ipv6_hdr);

    cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
    cksum = (~cksum) & 0xffff;
    if (cksum == 0)
        cksum = 0xffff;

    return cksum;
}

static inline int icmp_reply(struct rte_mbuf *m, union common_ip_head *iph,
        struct ether_hdr *ether_hdr, uint16_t ip_pld_len, int is_ipv6,
        uint8_t offset) {
    struct icmp_hdr *ic;

    //the echo related fields is the same for icmpv6 and icmp
    ic = (struct icmp_hdr*)((uint8_t *)iph + offset);

    if (is_ipv6) {
        // the icmpv6 is more complex, we just reply ICMPV6_ECHO_REQUEST, other pass to kernel
        if (ic->icmp_type != ICMPV6_ECHO_REQUEST) {
            return 1;
        }
        ic->icmp_type = ICMPV6_ECHO_REPLY;
        iph->ipv6_hdr.hop_limits = IPV6_TTL;
        l3_output_ipv6(&(iph->ipv6_hdr));
        m->l3_len = sizeof(struct ipv6_hdr);
        m->ol_flags = PKT_TX_IPV6;
        ic->icmp_cksum= 0;
        ic->icmp_cksum= calc_icmpv6_chksum(&(iph->ipv6_hdr), (uint8_t*)ic, ip_pld_len);
    } else {
        if (ic->icmp_code != 0) {
            return -1;
        }
        if (ic->icmp_type == IP_ICMP_ECHO_REPLY) {
            return 1;
        } else if (ic->icmp_type != IP_ICMP_ECHO_REQUEST) {
            return -1;
        }
        ic->icmp_type = IP_ICMP_ECHO_REPLY;
        iph->ipv4_hdr.hdr_checksum = 0;
        iph->ipv4_hdr.time_to_live = IPV4_TTL;
        l3_output(&(iph->ipv4_hdr));
        m->l3_len = sizeof(struct ipv4_hdr);
        m->ol_flags |= PKT_TX_IP_CKSUM;
        ic->icmp_cksum= 0;
        ic->icmp_cksum= calc_icmp_chksum((uint8_t *)ic, ip_pld_len);
    }

    l2_output(ether_hdr);
    m->l2_len = sizeof(struct ether_hdr);
    if(likely(MTU_SIZE < (m->pkt_len - sizeof(struct ether_hdr)))){
        return -2;
    }

    return 0;
}

static int qos_proto_check(struct rte_mbuf *m, int *is_icmp, int *qos_type) {
    uint16_t ether_type, ip_pld_len;
    union common_ip_head *ip_head;
    struct ether_hdr *eth_hdr;
    struct tcp_hdr *th;
    uint8_t l4_proto, l6_proto, offset;
    int ret, is_tcp = 0;
    *is_icmp = 0;

    *qos_type = OTHER_QPSLIMIT_ID;
    if (m->pkt_len < sizeof(struct ether_hdr)) {
        return IO_RET_CONTINUE;
    }
    eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    if (ether_type == ETHER_TYPE_IPv4) {
        ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
                sizeof(struct ether_hdr));
        if (unlikely(is_valid_ipv4_pkt(&(ip_head->ipv4_hdr), m->pkt_len - ETH_HLEN,
                        &ip_pld_len, &offset) < 0)) {
            return IO_RET_CONTINUE;
        }

		if (g_fwd_qps_limit_on[IP_QPSLIMIT_ID]
				&& (ipv4_pass(ip_head->ipv4_hdr.src_addr,
						g_fwd_qps_quota[IP_QPSLIMIT_ID]) == IO_RET_DROP)) {
			return IO_RET_DROP;
		}

        l4_proto = ip_head->ipv4_hdr.next_proto_id;
        switch (l4_proto) {
            case IPPROTO_OSPF:
                return IO_RET_PASS;
            case IPPROTO_ICMP:
                ret = icmp_reply(m, ip_head, eth_hdr, ip_pld_len, 0, offset);
                if (ret < 0) {
                    return IO_RET_DROP;
                } else if (ret == 0) {
                    *is_icmp = 1;
                    return IO_RET_PASS;
                }
                break;
            case IPPROTO_TCP:
                is_tcp = 1;
                break;
            default:
                break;
        }
    } else if (ether_type == ETHER_TYPE_IPv6) {
        ip_head = (union common_ip_head*)(rte_pktmbuf_mtod(m, unsigned char *) +
                sizeof(struct ether_hdr));
        if (unlikely((ret = is_valid_ipv6_pkt(&(ip_head->ipv6_hdr), m->pkt_len - ETH_HLEN,
                            &ip_pld_len, &offset)) < 0)) {
            return IO_RET_CONTINUE;
        }

		if (g_fwd_qps_limit_on[IP_QPSLIMIT_ID]
				&& (ipv6_pass(ip_head->ipv6_hdr.src_addr,
						g_fwd_qps_quota[IP_QPSLIMIT_ID]) == IO_RET_DROP)) {
			return IO_RET_DROP;
		}

        l6_proto = (uint8_t)ret;
        switch (l6_proto) {
            case IPPROTO_OSPF:
                return IO_RET_PASS;
            case IPPROTO_ICMPV6:
                ret = icmp_reply(m, ip_head, eth_hdr, ip_pld_len, 1, offset);
                if (ret < 0) {
                    return IO_RET_DROP;
                } else if (ret == 0) {
                    *is_icmp = 1;
                    return IO_RET_PASS;
                }
                break;
            case IPPROTO_TCP:
                is_tcp = 1;
                break;
            default:
                break;
        }
    } else {
        return IO_RET_CONTINUE;
    }

    if (!g_kni_qps_limit_on_status) {
        return IO_RET_PASS;
    }
    if (!is_tcp) {
        return IO_RET_CONTINUE;
    }
    th = (struct tcp_hdr*)((uint8_t*)ip_head+ offset);
    if (likely((m->pkt_len - ((uint8_t *)th - rte_pktmbuf_mtod(m, uint8_t *))) >= sizeof(struct tcp_hdr))) {
        /* SYN and SYN,ACK and FIN,ACK length will be euqal to sizeof(struct tcp_hdr) */
        switch (th->dst_port) {
            case PROTO_BGP_BE:
                return IO_RET_PASS;
            case PROTO_DOH_BE:
                *qos_type = DOH_QPSLIMIT_ID;
                return IO_RET_CONTINUE;
            case PROTO_DOHS_BE:
                *qos_type = DOHS_QPSLIMIT_ID;
                return IO_RET_CONTINUE;
            case PROTO_DOT_BE:
                *qos_type = DOT_QPSLIMIT_ID;
                return IO_RET_CONTINUE;
            default:
                return IO_RET_CONTINUE;
        }
    }
    return IO_RET_CONTINUE;
}


/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */

/*
 * kni qos logic:
 * start
 *  |
 *  --illegal eth--all qps limit
 *  |
 *  --illegal ipv4/ipv6--all qps limit
 *  |
 *  --ospf--pass though
 *  |
 *  --icmp--all qps limit
 *  |
 *  --other internet layer--all qps limit
 *  |
 *  --tcp (udp will not be send to kni)
 *     |
 *     --bgp--pass through
 *     |
 *     --dot--dot qps limit
 *     |
 *     --doh-doh qps limit
 *     |
 *     --other-all qps limit
 */
static inline int kni_ingress(struct lcore_params_kni *lp, uint8_t port_id,
        struct rte_kni *kni)
{
    unsigned nb_rx, nb_other, num;
    struct rte_mbuf *pkts_burst[KNI_PKT_BURST_SZ];
    struct rte_mbuf *pkts_burst_other[KNI_PKT_BURST_SZ];
    int qos_type, ret, j, is_icmp;

    /* Burst rx from eth */
    nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, KNI_PKT_BURST_SZ);
    if (nb_rx == 0)
        return 0;

    nb_other = 0;
    for (j = 0 ; j < nb_rx; j++) {
        struct rte_mbuf *m = pkts_burst[j];
        ret = qos_proto_check(m, &is_icmp, &qos_type);
        switch (ret) {
            case IO_RET_DROP:
                rte_pktmbuf_free(m);
                STATS(KNI_DROP);
                continue;
            case IO_RET_PASS:
                if (is_icmp) {
                    __send_single_frame(&lp->tx_mbufs[port_id], m, port_id, 0);
                } else {
                    pkts_burst_other[nb_other++] = m;
                }
                continue;
            case IO_RET_CONTINUE:
                if (g_fwd_qps_limit_on[qos_type]
                        && (kni_pass(qos_type) == IO_RET_DROP)) {
                    rte_pktmbuf_free(m);
                    STATS(KNI_DROP);
                    continue;
                }
                break;
            default:
                break;
        }
        pkts_burst_other[nb_other++] = m;
    }

    //LOG("burst tx num = %d to kni\n",nb_rx);
    /* Burst tx to kni */
    num = rte_kni_tx_burst(kni, pkts_burst_other, nb_other);

    if (unlikely(num < nb_other)) {
        /* Free mbufs not tx to kni interface */
        //printf("in %s,tx to kni fail,ok num is %d/%d\n", __func__, nb_other, num);
        kni_burst_free_mbufs(&pkts_burst_other[num], nb_other- num);
        STATS_ADD(KNI_DROP, nb_other- num);
    }

    return nb_rx;
}

static inline int kni_msg_handle() {
    unsigned i, num;
    struct rte_mbuf *pkts_burst[nb_sys_ports][KNI_PKT_BURST_SZ];
    unsigned pkts_num[RTE_MAX_ETHPORTS] = {0};
    /* receive pkt from IO core, and send them to KNI */
    struct lcore_msg_info *msg[MSG_QUEUE_SIZE];
    int rc = lcore_msg_bulk_recv(msg);

    if (rc > 0) {
        STATS_ADD(IPC_MSG_REVC, rc);
        for (i = 0; i < rc; i++) {
            if (likely(msg[i]->opcode == MSG_RESP_KNI)) {
                msg_output(msg[i]->pkni.m, msg[i]->pkni.eth_hdr,
                        msg[i]->pkni.ip_head,
                        (struct udp_hdr *) msg[i]->pkni.l4_head,
                        msg[i]->pkni.need_swap);
                pkts_burst[msg[i]->pkni.port_id][pkts_num[msg[i]->pkni.port_id]++] =
                        msg[i]->pkni.m;
            }
            lcore_msg_free(msg[i]);
        }
        for (i = 0; i < nb_sys_ports; i++) {
            if (pkts_num[i] > 0) {
                num = rte_kni_tx_burst(kni_port_info[i].kni, pkts_burst[i],
                        pkts_num[i]);

                if (unlikely(num < pkts_num[i])) {
                    /* Free mbufs not tx to kni interface */
                    //printf("in %s,tx(dot or doh) to kni fail,ok num is %d/%d\n",
                    //        __func__, rc, num);
                    kni_burst_free_mbufs(&pkts_burst[i][num], pkts_num[i] - num);
                    STATS_ADD(KNI_DROP, pkts_num[i] - num);
                }
            }
        }
    }

    return rc;
}

static void lcore_main_loop_kni(void)
{
    int i, lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc, c2, c1;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S
        * BURST_TX_DRAIN_US;
    struct lcore_params_kni *lp;
    struct rte_kni *kni;

    prev_tsc = 0;
    lcore_id = rte_lcore_id();
    lp = &app.lcore_params[lcore_id].kni;
    gcpu_util[lcore_id].lcore_id = lcore_id;
    cur_tsc = rte_rdtsc();

    while (1) {
        c2 = rte_rdtsc();
        gcpu_util[lcore_id].all += (c2 - cur_tsc);
        cur_tsc = c2;

        /* TX burst queue drain */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (i = 0; i < nb_sys_ports; i++) {
                if (lp->tx_mbufs[i].len == 0)
                    continue;
                /* from kni to tx */
                send_burst(&lp->tx_mbufs[i], i, 0);
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].send += (c2 - c1);
            }
            prev_tsc = cur_tsc;
        }

        for (i = 0; i < nb_sys_ports; i++) {
            kni = kni_port_info[i].kni;
            rte_kni_handle_request(kni);

            if (kni_egress(lp, i, kni) > 0) {
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].send += (c2 - c1);
            } else {
                c2 = rte_rdtsc();
            }

            if (kni_ingress(lp, i, kni) > 0) {
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].recv += (c2 - c1);
            } else {
                c2 = rte_rdtsc();
            }
        }

        if (kni_msg_handle() > 0) {
            c1 = c2;
            c2 = rte_rdtsc();
            gcpu_util[lcore_id].msg += (c2 - c1);
        } else {
            c2 = rte_rdtsc();
        }
    }
}

static void lcore_main_loop_misc(void)
{
    uint64_t cur_tsc, prev_tsc, diff_tsc, c1, c2;
    uint64_t prev_black_tsc, prev_log_time, prev_admin_tsc;
    const uint64_t drain_tsc =
            (HZ + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    const uint64_t drain_admin_tsc = (HZ + MS_PER_S - 1) / MS_PER_S;
    const uint64_t drain_syslog_tsc = (HZ + MS_PER_S - 1) / MS_PER_S * 50;
    int lcore_id = rte_lcore_id();
    gcpu_util[lcore_id].lcore_id = lcore_id;

    prev_black_tsc = 0;
    prev_log_time = 0;
    prev_admin_tsc = 0;
    prev_tsc = 0;
    charge_log_time();
    cur_tsc = rte_rdtsc();

    while (1) {
        c2 = rte_rdtsc();
        gcpu_util[lcore_id].all += (c2 - cur_tsc);
        cur_tsc = c2;

        diff_tsc = cur_tsc - prev_admin_tsc;
        if (unlikely(diff_tsc > drain_admin_tsc)) {
            if (aeMain(admin.el) > 0) {
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].recv += (c2 - c1);
            } else {
                c2 = rte_rdtsc();
            }
            prev_admin_tsc = cur_tsc;
        }

        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            if(logs_flush() > 0) {
                c1 = c2;
                c2 = rte_rdtsc();
                gcpu_util[lcore_id].msg += (c2 - c1);
            } else {
                c2 = rte_rdtsc();
            }
            prev_tsc = cur_tsc;
        }

        diff_tsc = cur_tsc - prev_log_time;
        if (diff_tsc > drain_syslog_tsc) {
            charge_log_time();
            c1 = c2;
            c2 = rte_rdtsc();
            gcpu_util[lcore_id].ttl_ck += (c2 - c1);
            prev_log_time = cur_tsc;
        }

        diff_tsc = cur_tsc - prev_black_tsc;
        if (unlikely(diff_tsc > g_charge_file_interval * HZ)) {
            charge_man_whitelist_state();
            charge_man_blacklist_state();
            charge_man_ip_blacklist_state();
            //charge_oversealist_state();
            c1 = c2;
            c2 = rte_rdtsc();
            gcpu_util[lcore_id].retry += (c2 - c1);
            prev_black_tsc = cur_tsc;
        }
    }
}

int lcore_main_loop( __attribute__ ((unused))
                    void *arg)
{
    struct lcore_params *lp;
    unsigned lcore;

    lcore = rte_lcore_id();
    lp = &app.lcore_params[lcore];

    gettimeofday(&lp->start_time, NULL);
    lp->start_cycles = rte_get_timer_cycles();

    if (lp->type == e_LCORE_IO) {
        RTE_LOG(INFO, LDNS, "Logical core %u (I/O %u) main loop.\n",
                lcore, lp->io.io_id);

        lcore_main_loop_io();
    }

    if (lp->type == e_LCORE_MISC) {
        RTE_LOG(INFO, LDNS, "Logical core %u (MISC) main loop.\n", lcore);
        lcore_main_loop_misc();
    }

    if (lp->type == e_LCORE_KNI) {
        RTE_LOG(INFO, LDNS, "Logical core %u (KNI) main loop.\n", lcore);
        lcore_main_loop_kni();
    }
    return 0;
}
