/*
 * Copyright (C)
 * Filename: dataplane.c
 * Author:
 * mogu<mogu.lwp@alibaba-inc.com>
 * Description: netfilter framework main process file
 */

#include <net/ip.h>

#include "util.h"
#include "stats.h"
#include "dns.h"
#include "control.h"
#include "manage.h"
#include "vxlan.h"
#include "edns.h"
#include "pvt_tnl_db.h"

/* ASMEGA may invoke netif_rx to pass the new skb_buf to network stack,
 * in this case, ASMEGA must mark datagram by ASMEGA_SKB_CB to prevent
 * dealing with it in NF_INET_PRE_ROUTING hook again.
 */
#define ASMEGA_SKB_CB(skb) ((skb)->cb[47])
#define IO_TYPE_RX 0
#define IO_TYPE_TX 1

static inline int __attribute__ ((always_inline))
is_pointer(uint8_t in)
{
    return ((in & 0xc0) == 0xc0);
}

static inline int __attribute__ ((always_inline))
asmega_dname_size(const uint8_t *dname, uint16_t datagram_len)
{
    /* Count name size without terminal label. */
    int name_len = 1;
    uint8_t label_len;

    while (*dname != '\0') {
        /* Compression pointer is 2 octets. */
        if (is_pointer(*dname)) {
            name_len += 1;

            if (unlikely(name_len > datagram_len)) {
                AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
                return -1;
            } else {
                return name_len;
            }
        }

        /* Check label length (maximum 63 bytes allowed). */
        if (unlikely(*dname > MAX_DOMAIN_LABEL_LEN)) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_ILLEGAL_DNAME_LEN);
            return -1;
        }

        label_len = *dname + 1;
        name_len += label_len;

        if (unlikely(name_len > MAX_DNAME_LEN)) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_ILLEGAL_DNAME_LEN);
            return -1;
        }

        if (unlikely(name_len > datagram_len)) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
            return -1;
        }
        dname += label_len;
    }

    return name_len;
}

/*
 * check whether or not it's a reasonable dns header
 * input: dnshdr: pointer to dns header
 *        dns_len: total dns payload length
 *        io_type: rx or tx
 */
int check_dns_header(struct as_dnshdr *dnshdr, uint16_t dns_len, uint8_t io_type)
{
    if(unlikely(dns_len < (sizeof(struct as_dnshdr)))) {
        AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
        return AS_ERROR;
    }

    /* some illegal scenes */
    if (dnshdr->opcode != 0) {
        AS_INC_ESTATS(as_esmib, AS_NONSUP_OPCODE);
        return AS_NONSUPPORT;
    }

    if (ntohs(dnshdr->questions) != 1) {
        AS_INC_ESTATS(as_esmib, AS_NONSUP_QUESTIONS);
        return AS_NONSUPPORT;
    }

    if (dnshdr->qr == AS_DNSQUERY) {
        /* Localout get DNS query package */
        if(io_type == IO_TYPE_TX) {
            return AS_NONSUPPORT;
        }
    } else {
        /* Prerouting get DNS replay package */
        if (io_type == IO_TYPE_RX) {
            return AS_NONSUPPORT;
        }
    }

    return AS_SUCCESS;
}

/*
 * parse dns data, check whether or not it's a reasonable dns data
 * input: dnshdr: pointer to dns header
 *        dns_len: total dns payload length
 * output:wire: pointer to the additional section
 */
int parse_dns_data(struct as_dnshdr *dnshdr, uint16_t data_len,
        uint8_t **wire)
{
    uint8_t *pos = *wire;
    uint32_t datalen, rr_num;
    int label_len, i, name_len, ret;
    //struct as_dnsans dnsans;
    name_len = 1;

    if (unlikely(data_len < 5)) {
        AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
        return AS_ERROR;
    }

    /* get query domain name */
    pos = dnshdr->data;
    while (*pos != '\0') {
        /* Check label length (maximum 63 bytes allowed). */
        if (*pos > MAX_DOMAIN_LABEL_LEN) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_ILLEGAL_DNAME_LEN);
            return AS_ERROR;
        }
        label_len = *pos + 1;
        name_len += label_len;

        if (unlikely(name_len > MAX_DNAME_LEN)) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_ILLEGAL_DNAME_LEN);
            return AS_ERROR;
        }

        if (name_len > data_len) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
            return AS_ERROR;
        }

        pos += label_len;
    }
    data_len -= name_len;

    if (unlikely(data_len < 4)) {
        AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
        return AS_ERROR;
    }
    pos ++;
    //dnsques->qtype = ntohs(*(uint16_t*)pos);
    pos += 2;
    //dnsques->qclass = ntohs(*(uint16_t*)pos);
    if (unlikely(ntohs(*(uint16_t*)pos) != RR_CLASS_IN)) {
        AS_INC_ESTATS(as_esmib, AS_NONSUP_CLASS);
        return AS_NONSUPPORT;
    }
    pos += 2;
    data_len -= 4;

    /* find edns section */
    rr_num = ntohs(dnshdr->answer_rrs) + ntohs(dnshdr->authority_rrs)
            + ntohs(dnshdr->additional_rrs);
    for (i = 0; i < rr_num; i ++) {
        if(unlikely(data_len == 0)) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
            return AS_ERROR;
        }
        ret = asmega_dname_size(pos, data_len);
        if (unlikely(ret < 0)) {
            return AS_ERROR;
        }
        data_len -= ret;
        pos += ret;

        if (unlikely(data_len < 10)) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
            return AS_ERROR;
        }
        // check rr_type whether is edns
        if (htons(*(uint16_t*)pos) == EDNS_OPT) {
            *wire = pos - ret;
            return AS_HAS_EDNS;
        }
        pos += 2;
        //dnsans.class = htons(*(uint16_t*)pos);
        pos += 2;
        //dnsans.ttl = htonl(*(uint32_t*)pos);
        pos += 4;
        datalen = ntohs(*(uint16_t*)pos);
        pos += 2;
        data_len -= 10;
        if (unlikely(data_len < datalen)) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_DATAGRAM_SMALL);
            return AS_ERROR;
        }
        pos += datalen;
        data_len -= datalen;
    }
    *wire = pos;

    return AS_SUCCESS;
}

int as_shrink_linear_skb(struct sk_buff *skb, uint16_t size, struct iphdr *iph, struct udphdr *uh)
{
    if (size > skb->len) {
        return AS_ERROR;
    }

    skb_trim(skb, skb->len - size);
    iph->tot_len = htons(ntohs(iph->tot_len) - size);
    ip_send_check(iph);
    uh->len = htons(ntohs(uh->len) - size);
    uh->check = 0;

    return AS_SUCCESS;
}

int as_expand_skb(struct sk_buff **skb, uint16_t size, struct as_dnshdr **dnshdr, int is_vxlan)
{
    struct iphdr *iph, *inner_iph;
    struct udphdr *uh, *inner_uh;
    struct sk_buff *new_skb;
    int ret = AS_SUCCESS;

    iph = ip_hdr(*skb);
    uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
    /* netfilter hook datagram at network layer
     * but ASMEGA must act as the protocal stack with
     * resetting transport headr.
     */
    (*skb)->transport_header = (unsigned char*)uh - (*skb)->head;

    if (size == 0) {
        return AS_ERROR;
    } else if (size <= skb_tailroom(*skb)) {
        skb_put(*skb, size);
    } else {
        /* original skb too short, get a longer new skb & free old skb,
         * should invoke netif_rx to pass this packet to network stack
         */
        new_skb =
            skb_copy_expand(*skb, skb_headroom(*skb), skb_tailroom(*skb) + size, GFP_ATOMIC);
        if (!new_skb) {
            AS_INC_ESTATS(as_esmib, AS_ERROR_NOMEM_SKB);
            return AS_ERROR;
        }
        kfree_skb(*skb);
        *skb = new_skb;
        skb_put(*skb, size);
        ret = AS_STOLEN;
    }
    iph = ip_hdr(*skb);
    iph->tot_len = htons(ntohs(iph->tot_len) + size);
    ip_send_check(iph);

    uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
    uh->len = htons(ntohs(uh->len) + size);
    uh->check = 0;

    if (is_vxlan) {
        inner_iph = (struct iphdr*)((void *)uh + VXLAN_HLEN);
        inner_iph->tot_len = htons(ntohs(inner_iph->tot_len) + size);
        ip_send_check(inner_iph);

        inner_uh = (struct udphdr *)((void *)inner_iph + inner_iph->ihl * 4);
        inner_uh->len = htons(ntohs(inner_uh->len) + size);
        inner_uh->check = 0;
        *dnshdr = (struct as_dnshdr *)((void *)inner_uh + sizeof(struct udphdr));
    } else {
        *dnshdr = (struct as_dnshdr *)((void *)uh + sizeof(struct udphdr));
    }

    return ret;
}

/**
 * process udp dns request
 * @eth		mac header
 * @iph		ip header
 * @uh		udp header
 * @skb		packet
 */
static unsigned int
as_dns_in(struct iphdr *iph, struct udphdr *uh, struct sk_buff **skb,
        uint16_t view_id, int skb_dns_len)
{
    uint8_t *pos;
    uint16_t dns_len, size, edns_len, edns_offset, *opt_len_pos;
    int mov_size, ret;
    struct as_dnshdr *dnshdr;
    adns_opt_rr_t edns_opt_rr;

    dns_len = ntohs(uh->len) - sizeof(struct udphdr);
    if (unlikely(sizeof(struct as_dnshdr) > skb_dns_len
            || dns_len > skb_dns_len)) {
        AS_INC_ESTATS(as_esmib, AS_DROP_PAC_INCOMPLETE);
        goto drop;
    }
    dnshdr = (struct as_dnshdr *) ((void *) uh + sizeof(struct udphdr));

    /* check the validity of dns header */
    ret = check_dns_header(dnshdr, dns_len, IO_TYPE_RX);
    if (ret == AS_NONSUPPORT) {
        AS_INC_ESTATS(as_esmib, AS_ACCEPT_NOSUPPORT);
        goto accept;
    } else if (ret == AS_ERROR) {
        AS_INC_ESTATS(as_esmib, AS_DROP_PARSE_ERROR);
        goto drop;
    }

    adns_edns_init(&edns_opt_rr, sysctl_as_edns_code,
            sysctl_as_edns_len, view_id);

    /* parse the query, answer, authority and additional sections of dns packet,
         * check validity and return the edns pointer */
    ret = parse_dns_data(dnshdr, dns_len - sizeof(struct as_dnshdr), &pos);
    if (ret == AS_NONSUPPORT) {
        AS_INC_ESTATS(as_esmib, AS_ACCEPT_NOSUPPORT);
        goto accept;
    } else if (ret == AS_ERROR) {
        AS_INC_ESTATS(as_esmib, AS_DROP_PARSE_ERROR);
        goto drop;
    } else if (ret == AS_HAS_EDNS) {
        size = PVT_EDNS_OPT_SIZE;
    } else {
        size = edns_opt_rr.size;
    }
    edns_offset = pos - (uint8_t *)dnshdr;

    ret = as_expand_skb(skb, size, &dnshdr, AS_VXLAN);
    if (ret == AS_ERROR) {
        goto accept;
    }

    edns_len = dns_len - edns_offset;
    /* as_expand_skb function may create  a new skb, so all pointer to the
     * old skb buffer should be recalculated.
     */
    pos = (uint8_t *)dnshdr + edns_offset;
    if (size == PVT_EDNS_OPT_SIZE) {
        ret = parse_dns_additional(&pos, &opt_len_pos, edns_len);
        if (ret == AS_ERROR) {
            AS_INC_ESTATS(as_esmib, AS_DROP_PARSE_EDNS);
            goto drop;
        } else if(ret == AS_PVT_EDNS) {
            /* should drop if user intent to query with pvt edns options */
            AS_INC_ESTATS(as_esmib, AS_DROP_QR_WITH_PVT_EDNS);
            goto drop;
        }

        mov_size = dns_len - (pos - (uint8_t *)dnshdr);
        if(mov_size > 0) {
            AS_INC_ESTATS(as_esmib, AS_REQUEST_MEM_MOV);
            memmove(pos + PVT_EDNS_OPT_SIZE, pos, mov_size);
        }
        adns_view_id_to_edns_option(&edns_opt_rr, opt_len_pos, pos);
    } else {
        dnshdr->additional_rrs = htons(ntohs(dnshdr->additional_rrs) + 1);
        adns_edns_to_wire(&edns_opt_rr, pos);
    }
    AS_INC_ESTATS(as_esmib, AS_REQUEST_IN);

accept:
    AS_INC_ESTATS(as_esmib, AS_ACCEPT_LOCAL_IN_L7);
    return NF_ACCEPT;
drop:
    AS_INC_ESTATS(as_esmib, AS_DROP_LOCAL_IN_L7);
    return NF_DROP;
}

unsigned int as_udp_in(struct iphdr *iph, struct udphdr *uh,
        struct sk_buff **skb, uint16_t view_id, int skb_udp_len)
{
    if (unlikely(sizeof(struct udphdr) > skb_udp_len))
        goto accept;

    /* check if it's a dns packet */
    if (uh->dest != htons(sysctl_as_dns_port))
        goto accept;

    return as_dns_in(iph, uh, skb, view_id, (skb_udp_len - sizeof(struct udphdr)));
accept:
    AS_INC_ESTATS(as_esmib, AS_ACCEPT_LOCAL_IN_L4);
    return NF_ACCEPT;
}

static unsigned int
as_ipv4_in(struct iphdr *iph, struct sk_buff **skb, uint16_t view_id, int skb_len)
{
    int len, iph_len;

    /* check we have sizeof(iphdr) in the first */
    if (unlikely(sizeof(struct iphdr) > skb_len))
        goto accept;

    /* check the ip header arg */
    if (iph->ihl < 5 || iph->version != 4)
        goto accept;
    iph_len = iph->ihl * 4;

    /* check we have total ip header in the first */
    if (unlikely(iph_len > skb_len))
        goto accept;

    /* Now we don't support IP fragment */
    if (iph->frag_off & htons(IP_OFFSET | IP_MF))
        goto accept;

    /* check the len is ok */
    len = ntohs(iph->tot_len);
    if (skb_len < len || len < iph_len)
        goto accept;

    switch (iph->protocol) {
        case IPPROTO_UDP:
            return as_udp_in(iph, (struct udphdr *) ((void *) iph + iph_len),
                    skb, view_id, (skb_len - iph_len));
        default:
            break;
    }

accept:
    AS_INC_ESTATS(as_esmib, AS_ACCEPT_LOCAL_IN_L3);
    return NF_ACCEPT;
}

static unsigned int as_vxlan_in(struct sk_buff *skb, uint16_t *view_id, struct iphdr **inner_iph)
{
    struct iphdr *iph;
    struct udphdr *uh;
    struct vxlanhdr *vxh;
    int len;
    unsigned atype;

    *inner_iph = NULL;
    *view_id = 0;
    /* only PACKET_HOST */
    if (unlikely(skb->pkt_type != PACKET_HOST))
        return AS_ACCEPT;

    iph = ip_hdr(skb);
    len = iph->ihl * 4;
    /* only care udp packets */
    if (iph->protocol != IPPROTO_UDP)
        return AS_ACCEPT;

    /* ip fragment */
    if ( (iph->frag_off & htons(IP_MF | IP_OFFSET) ) ) {
        //VCTK_INC_STATS(vctk_counter, VXLAN_IN_IP_FRAGMENT);
        return AS_ACCEPT;
    }

    /* Need Udp and inner Vxlan hdr */
    if (!pskb_may_pull(skb, len + VXLAN_HLEN + sizeof(struct iphdr)))
        return AS_ACCEPT;

    /* pskb_may_pull may change the iph */
    iph = ip_hdr(skb);
    uh = (struct udphdr*)(skb_network_header(skb) + len);
    /* only care packets to vxlan listen port */
    if (!sysctl_vctk_vxlan_another_dport) {
        if (uh->dest != VXLAN_LISTEN_PORT)
            return AS_ACCEPT;
    } else {
        if (uh->dest != VXLAN_LISTEN_PORT &&
                uh->dest != htons(sysctl_vctk_vxlan_another_dport))
            return AS_ACCEPT;
    }

    vxh = (struct vxlanhdr *)(uh + 1);
    if (vxh->flags != VXLAN_FLAGS || vxh->version != 1 ||
            (vxh->vid & htonl(0xff))) {
        /* not a vxlan package */
        return AS_ACCEPT;
    }

    /* check the daddr */
    /*
    if (vxlan_bind && (iph->daddr != vxlan_bind)) {
        VCTK_INC_STATS(vctk_counter, VXLAN_DST_UNMATCH);
        goto drop;
    }
    */
    atype = inet_addr_type(&init_net, iph->daddr);
    if (atype != RTN_LOCAL && atype != RTN_UNICAST) {
        return AS_ERROR;
    }

    *view_id = as_pvt_tnl_get_view_id(&g_tnl_db, vxlan_id(vxh));
    if (*view_id == 0) {
        AS_INC_ESTATS(as_esmib, AS_ACCEPT_NOT_FIND_VIEW_ID);
        return AS_ACCEPT;
    }
    *inner_iph = (struct iphdr*)((void *)uh + VXLAN_HLEN);
    return AS_SUCCESS;
}


unsigned int
as_local_in(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn) (struct sk_buff *))
{
    struct iphdr *iph = NULL;
    int inner_skb_len;
    unsigned int ret;
    struct sk_buff *as_skb = skb;
    uint16_t view_id;

    if (unlikely(!sysctl_as_on)) {
        return NF_ACCEPT;
    }

    /* if a skb come from asmega, its cb[47] would be DNS_MAGIC
     * so don't hook the package from myself */
    if (ASMEGA_SKB_CB(skb) == DNS_MAGIC) {
        return NF_ACCEPT;
    }

    if (skb_is_nonlinear(skb)) {
        return NF_ACCEPT;
    }

    ret = as_vxlan_in(skb, &view_id, &iph);
    if (ret == AS_ACCEPT) {
        return NF_ACCEPT;
    } else if (ret == AS_ERROR) {
        return NF_DROP;
    }

    inner_skb_len = skb->len - ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct vxlanhdr);
    ret = as_ipv4_in(iph, &as_skb, view_id, inner_skb_len);
    if (skb == as_skb) {
        return ret;
    } else {
        if (ret == NF_ACCEPT) {
            ASMEGA_SKB_CB(as_skb) = DNS_MAGIC;
            AS_INC_ESTATS(as_esmib, AS_STOLEN_NEW_SKB);
            netif_rx(as_skb);
        } else {
            kfree_skb(as_skb);
        }

        return NF_STOLEN;
    }
}

/**
 * process udp dns request
 * @eth		mac header
 * @iph		ip header
 * @uh		udp header
 * @skb		packet
 */
unsigned int as_dns_out(struct iphdr *iph, struct udphdr *uh,
        struct sk_buff *skb, int skb_dns_len)
{
    uint8_t *pos;
    uint16_t edns_len, dns_len, *opt_len_pos;
    int mov_size, ret = 0;
    struct as_dnshdr *dnshdr;

    dns_len = ntohs(uh->len) - sizeof(struct udphdr);
    if (unlikely(
            sizeof(struct as_dnshdr) > skb_dns_len || dns_len > skb_dns_len)) {
        goto accept;
    }
    dnshdr = (struct as_dnshdr *)((void *)uh + sizeof(struct udphdr));

    /* check the validity of dns header */
    ret = check_dns_header(dnshdr, dns_len, IO_TYPE_TX);
    if (ret != AS_SUCCESS) {
        goto accept;
    }

    if (ntohs(dnshdr->additional_rrs) == 0) {
        goto accept;
    }

    /* parse the query, answer, authority and additional sections of dns packet,
     * check validity and return the edns pointer */
    ret = parse_dns_data(dnshdr, dns_len - sizeof(struct as_dnshdr), &pos);
    if (unlikely(ret != AS_HAS_EDNS)) {
        goto accept;
    }

    edns_len = dns_len - (pos - (uint8_t *)dnshdr);
    ret = parse_dns_additional(&pos, &opt_len_pos, edns_len);
    if (ret != AS_PVT_EDNS) {
        goto accept;
    }

    mov_size = dns_len - (pos - (uint8_t *)dnshdr);
    if (mov_size > 0) {
        AS_INC_ESTATS(as_esmib, AS_ANSWER_MEM_MOV);
        memmove(pos - PVT_EDNS_OPT_SIZE, pos, mov_size);
    }
    *opt_len_pos = htons(ntohs(*opt_len_pos) - PVT_EDNS_OPT_SIZE);

    ret = as_shrink_linear_skb(skb, PVT_EDNS_OPT_SIZE, iph, uh);
    if (ret != AS_SUCCESS) {
        goto accept;
    }
    AS_INC_ESTATS(as_esmib, AS_REQUEST_OUT);

accept:
    AS_INC_ESTATS(as_esmib, AS_ACCEPT_LOCAL_OUT_L7);
    return NF_ACCEPT;
}

unsigned int as_udp_out(struct iphdr *iph, struct udphdr *uh,
        struct sk_buff *skb, int skb_udp_len)
{
    if (unlikely(sizeof(struct udphdr) > skb_udp_len))
            goto accept;

    /* check if it's a dns response packet */
    if (uh->source != htons(sysctl_as_dns_port))
        goto accept;

    return as_dns_out(iph, uh, skb, (skb_udp_len - sizeof(struct udphdr)));

accept:
    AS_INC_ESTATS(as_esmib, AS_ACCEPT_LOCAL_OUT_L4);
    return NF_ACCEPT;
}

static unsigned int as_ipv4_out(struct sk_buff *skb)
{
    struct iphdr *iph;
    int len, iph_len;

    /* check we have sizeof(iphdr) in the first */
    if (unlikely(sizeof(struct iphdr) > skb->len))
        goto accept;

    /* check the ip header length and version */
    iph = (struct iphdr *)skb_network_header(skb);
    if (iph->ihl < 5 || iph->version != 4)
        goto accept;
    iph_len = iph->ihl * 4;

    /* check we have total ip header in the first */
    if (unlikely(iph_len > skb->len))
        goto accept;

    /* Now we don't support IP fragment */
    if (iph->frag_off & htons(IP_OFFSET | IP_MF))
        goto accept;

    /* check the len is ok */
    len = ntohs(iph->tot_len);
    if (skb->len < len || len < iph_len)
        goto accept;

    switch (iph->protocol) {
        case IPPROTO_UDP:
        return as_udp_out(iph, (struct udphdr *) ((void *) iph + iph_len),
                skb, (skb->len - iph_len));
        default:
            break;
    }

accept:
    AS_INC_ESTATS(as_esmib, AS_ACCEPT_LOCAL_OUT_L3);
    return NF_ACCEPT;
}

unsigned int
as_local_out(unsigned int hook, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn) (struct sk_buff *))
{
    unsigned int ret;

    if (unlikely(!sysctl_as_on))
        goto accept;

    if (skb_is_nonlinear(skb)) {
        AS_INC_ESTATS(as_esmib, AS_ACCEPT_LINEARIZE_OUT);
        goto accept;
    }

    ret = as_ipv4_out(skb);
    return ret;

accept:
    return NF_ACCEPT;
}
