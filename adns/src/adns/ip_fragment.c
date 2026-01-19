#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>

#include "mbuf.h"
#include "inttypes.h"
#include "log.h"
#include "adns.h"
#include "consts.h"
#include "wire.h"
//#include "dns_pkt.h"


#define IPV4_HDR_DF_SHIFT           14
#define IPV4_HDR_MF_SHIFT           13
#define IPV4_HDR_FO_SHIFT           3

#define IPV4_HDR_DF_MASK            (1 << IPV4_HDR_DF_SHIFT)
#define IPV4_HDR_FO_MASK            ((1 << IPV4_HDR_FO_SHIFT) - 1)

#define IPV4_FRAG_UNIT              8

inline uint16_t get_ipv4_cksum(const struct ipv4_hdr *ipv4_hdr);

static inline void __fill_ipv4hdr_frag(struct ipv4_hdr *dst,
                                       const struct ipv4_hdr *src, uint16_t len, uint16_t fofs,
                                       uint16_t dofs, uint32_t mf)
{
    rte_memcpy(dst, src, sizeof(*dst));

    fofs = (uint16_t) (fofs & (0 << IPV4_HDR_DF_SHIFT));
    fofs = (uint16_t) (fofs + (dofs >> IPV4_HDR_FO_SHIFT));
    fofs = (uint16_t) (fofs | mf << IPV4_HDR_MF_SHIFT);

    dst->fragment_offset = rte_cpu_to_be_16(fofs);
    dst->total_length = rte_cpu_to_be_16(len);
    dst->hdr_checksum = 0;
    return;
}

/*
 * This function is written much alike rte_ipv4_fragment_packet().
 * Maybe it's ported from dpdk code and add our own customization
 * (append the mac header). It is not a clean way, i think,
 * using standard rte_ipv4_fragment_packet() and add our appending code
 * outside would be somehow better, leave it for future work
 */
void fragment_output(struct rte_mbuf *m, uint8_t port, uint16_t mtu_size)
{
    uint16_t flag_offset, fragment_offset;
    uint32_t data_pos, len, more_in_segs;
    struct ipv4_hdr *out_hdr;
    struct rte_mbuf *in_seg = NULL;
    struct rte_mbuf *out_pkt = NULL;
    struct ipv4_hdr *iph;
    uint16_t add_len, total_len;

    if(unlikely(m == NULL)){
        fprintf(stderr, "Error! Input rte_mbuf is NULL\n");
        return;
    }

    if(unlikely(0 >= mtu_size)){
        rte_pktmbuf_free(m);
        return;
    }

    iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, char *) + sizeof(struct ether_hdr));
    flag_offset = rte_cpu_to_be_16(iph->fragment_offset);

    in_seg = m;
    fragment_offset = 0;
    data_pos = sizeof(struct ipv4_hdr) + sizeof(struct ether_hdr);
    more_in_segs = 1;

    while(more_in_segs){
        out_pkt = mbuf_alloc();
        if(unlikely(out_pkt == NULL)){
            log_server_warn(rte_lcore_id(), "%s: mbuf_alloc failed!\n", __FUNCTION__);
            rte_pktmbuf_free(m);
            return;
        }

        out_pkt->data_len = sizeof(struct ipv4_hdr);
        out_pkt->pkt_len = sizeof(struct ipv4_hdr);

        len = mtu_size - sizeof(struct ipv4_hdr);
        len = len - len % IPV4_FRAG_UNIT;
        if((int)len > ((int)in_seg->data_len - (int)data_pos)){
            len = in_seg->data_len - data_pos;
        }

        rte_memcpy(rte_pktmbuf_mtod(out_pkt, char *), rte_pktmbuf_mtod(in_seg, char *) + (uint16_t) data_pos, len);
        out_pkt->data_len = len;
        out_pkt->pkt_len = len;
        data_pos += len;

        if(unlikely(data_pos >= in_seg->data_len)){
            in_seg = in_seg->next;
            data_pos = 0;

            if(unlikely(in_seg == NULL)){
                more_in_segs = 0;
            }
        }

        /*The out_pkt->pkt.pkt_len will also increase add_len */
        add_len = (uint16_t) sizeof(struct ether_hdr) + (uint16_t) sizeof(struct ipv4_hdr);
        rte_pktmbuf_prepend(out_pkt, add_len);

        /* Build the IP header */
        out_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(out_pkt, char *) + sizeof(struct ether_hdr));
        /*The ether_hdr is not in MTU */
        total_len = (uint16_t) (out_pkt->pkt_len) - (uint16_t) sizeof(struct ether_hdr);
        __fill_ipv4hdr_frag(out_hdr, iph, total_len, flag_offset, fragment_offset, more_in_segs);

        fragment_offset = (uint16_t) (fragment_offset +
                                      out_pkt->pkt_len - (uint16_t) sizeof(struct ether_hdr) -
                                      (uint16_t) sizeof(struct ipv4_hdr));

        out_pkt->ol_flags |= PKT_TX_IP_CKSUM;
        out_pkt->l3_len = sizeof(struct ipv4_hdr);
        out_pkt->l2_len = sizeof(struct ether_hdr);

        rte_memcpy(rte_pktmbuf_mtod(out_pkt, char *), rte_pktmbuf_mtod(m, char *), sizeof(struct ether_hdr));

        send_single_packet(out_pkt, port);
    }

    rte_pktmbuf_free(m);
    return;
}
