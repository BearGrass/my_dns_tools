/*
 * Copyright (C)
 * Filename: dataplane.c
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description: netfilter framework main process file
 */

#include <linux/ctype.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/flow.h>

#include "util.h"
#include "stats.h"
#include "dns.h"
#include "cache.h"
#include "control.h"
#include "timer.h"
#include "lock.h"
#include "qpslimit.h"
#include "manage.h"

#define NXDOMAIN 3
#define NOERROR 0

#define QUESTION_MAX_LEN 256
#define ANSWER_MAX_LEN 1472
#define DOMAIN_LABEL_MAX_LEN 64
#define DOMAIN_LABEL_MAX_NUM 16

#define VCTK_OUT NF_IP_PRI_CONNTRACK + 1
#define IPHDR_DS(skb)	((struct iphdr *)((void*)skb_mac_header(skb) + ETH_HLEN))
/* when MEGA put datagram from local_in,  MEGA must mark
 * datagram using MEGA_SKB_CB to prevent deal with the datagram in local_out.
 */
#define MEGA_SKB_CB(skb) ((skb)->cb[47])

#define DM_XMIT(skb) \
do {                 \
    DM_INC_ESTATS(dm_esmib, DM_REQUEST_OUT); \
    ip_local_out(skb); \
} while(0)

extern int g_domain_cache_hash_size;
extern struct dm_cache_timer g_cache_timer_list;

/* clean the tso/gso feature */
static inline void update_gso(struct sk_buff *skb)
{
    if (unlikely (!skb->sk)) {
        return;
    }
    skb->sk->sk_route_caps &= ~NETIF_F_GSO_MASK;
}

#define FLOWI_INITIALIZER(_saddr, _daddr, _tos, _mark) \
    { \
    .u = { \
        .ip4 = { \
            .flowi4_oif = 0,\
            .flowi4_mark = (_mark),             \
            .daddr = (_daddr),                  \
            .saddr = (_saddr),                  \
            .flowi4_tos = (_tos),               \
        }},                                 \
    }


static inline int update_rt(struct sk_buff *skb, struct iphdr *iph) {
    struct rtable *rt;
    struct flowi fl = FLOWI_INITIALIZER(iph->saddr, iph->daddr, iph->tos, 0);

    rt = ip_route_output_key(&init_net, &fl.u.ip4);
    if (!rt) {
        return DM_ERROR;
    }
    /* drop old route */
    skb_dst_drop(skb);
    skb_dst_set(skb, &rt->dst);
    return DM_SUCCESS;
}

/*
 * parse dns request header, check whether or not it's a reasonable request
 * input: dnshdr
 *        dns_len
 * output: dnsques: store dns query section
 *         dnsans: dns answer section
 *         ansnum: number of dns answer
 */
int parse_dns_message(struct dm_dnshdr *dnshdr, uint16_t dns_len,
        struct dm_dnsques *dnsques, struct dm_dnsans dnsans[], int *ansnum) {
    char *pos;
    char domain[255];
    uint32_t datalen;
    uint16_t datagram_len;
    uint8_t dot_num;
    int label_len, domain_size, i, rr_num, name_len;

    /* some illegal scenes */
    if (dnshdr->opcode != 0)
        goto nosupport;
    if (ntohs(dnshdr->questions) != 1)
        goto nosupport;
    datagram_len = dns_len - sizeof(struct dm_dnshdr);
    if (datagram_len < 5)
        goto error;
    /* get query domain name */
    dot_num = 0;
    pos = dnshdr->data;
    domain_size = 0;
    while (pos != NULL && *pos != '\0') {
        label_len = *pos++;
        /* some illegal scense again */
        if (label_len> DOMAIN_LABEL_MAX_LEN)
            goto nosupport;
        if (dot_num > DOMAIN_LABEL_MAX_NUM)
            goto nosupport;
        if (domain_size + label_len > 254)
            goto nosupport;
        if (datagram_len < 6)
            goto error;
        dot_num ++;
        domain[domain_size++] = label_len;
        datagram_len --;
        while (datagram_len && label_len-- && pos!=NULL && *pos!='\0') {
            if (domain_size > 254 || datagram_len == 0)
                goto nosupport;
            domain[domain_size++] = tolower(*pos++);
            datagram_len--;
        }
    }
    if (!pos)
        goto error;
    domain[domain_size++] = 0;
    pos ++;
    if (dnsques == NULL) {
        pos += 4;
    } else {
        dnsques->qtype = ntohs(*(uint16_t*)pos);
        pos += 2;
        dnsques->qclass = ntohs(*(uint16_t*)pos);
        pos += 2;
        dnsques->qsize = domain_size;
        dnsques->dot_num = dot_num;
        strcpy(dnsques->qname, domain);
        if (dnsques->qclass != RR_CLASS_IN)
            goto nosupport;
    }
    /* get answer */
    rr_num = ntohs(dnshdr->answer_rrs);
    if (ansnum == NULL) {
        //dnsans = NULL;
        return DM_SUCCESS;
    } else if (rr_num < 0 || dnshdr->rcode != 0) {
        rr_num = 0;
        *ansnum = 0;
    } else if (rr_num > MAX_ANSWER_NUM) {
        *ansnum = MAX_ANSWER_NUM;
    } else {
        *ansnum = rr_num;
    }
    for (i = 0; i < *ansnum; i ++) {
        memset(dnsans[i].query, 0, sizeof(dnsans[i].query));
        name_len = 0;
        get_domain_name(dnshdr, datagram_len, &pos, dnsans[i].query, &name_len);
        if ( name_len == 0 ) {
            *ansnum = 0;
            return DM_ERROR;
        }
        dnsans[i].type = htons(*(uint16_t*)pos);
        pos += 2;
        dnsans[i].class = htons(*(uint16_t*)pos);
        pos += 2;
        dnsans[i].ttl = htonl(*(uint32_t*)pos);
        pos += 4;
        datalen = ntohs(*(uint16_t*)pos);
        pos += 2;
        dnsans[i].offset = pos - dnshdr->data;
        if (dnsans[i].type == RR_TYPE_CNAME) {
            pos += datalen;
        } else if (dnsans[i].type == RR_TYPE_ANAME) {
            if (datalen > 4) {
                goto error;
            }
            memcpy(dnsans[i].data.ip, pos, datalen);
            pos += 4;
        } else {
            pos += datalen;
            //TODO: deal with other dns answer type
        }
    }
    return DM_SUCCESS;
nosupport:
    return DM_NOSUPPORT;
error:
    return DM_ERROR;
}

/*
 * input qkey
 *       klen
 *       skb
 * output node_find
 *        l
 * return 1: has cache, or barely_trusted, already prefetched, return NF_ACCEPT
2: has cache, barely_trusted, should prefetch, return NF_ACCEPT
3: has not cache, copy skb to node & return NF_ACCEPT
4: has not cache, wait list too long, return NF_DROP
5: has not cache, already has wait request, move skb to node & return NF_STOLEN
-1: error, return NF_DROP
*/

int cache_find(const uint8_t * qkey, int klen, struct sk_buff *skb,
        struct node_t **node_find, struct dm_cache_hash *hash_bucket)
{
    int ret;
    struct node_t *n;
    *node_find = NULL;
    list_for_each_entry(n, &hash_bucket->list, node_list) {
        if (match_node(n, qkey, klen) == DM_SUCCESS) {
            if (n->val) {
                /* has cache */
                if (time_is_after_jiffies(n->cached_jiffies + sysctl_dm_barely_trusted_time * HZ)) {
                    /* trusted */
                    ret = CACHE_FIND;
                } else if (n->prefetch == 1) {
                    /* barely_trusted, already prefetched */
                    ret = CACHE_FIND;
                } else {
                    /* barely_trusted, should prefetch */
                    n->prefetch = 1;
                    ret = CACHE_UPDATE;
                }
                *node_find = n;
                return ret;
            } else {
                /* has not cache */
                if (n->wait_size >= sysctl_dm_req_waitlist_num) {
                    return CACHE_DROP;
                } else {
                    *node_find = n;
                    return CACHE_HOLD;
                }
            }
        }
    }
    return CACHE_INSERT;
}

int cache_insert(struct sk_buff *skb, const uint8_t * qkey,
        int klen, struct node_t **node_create, struct dm_cache_hash *hash_bucket)
{
    struct node_t *n, *tempn;
    struct request_t *r;
    /* add node to hash bucket */
    if (!skb) {
        return DM_ERROR;
    }
    write_trylock_bh(&hash_bucket->l);
    /* uniq node */
    list_for_each_entry(tempn, &hash_bucket->list, node_list) {
        if (match_node(tempn, qkey, klen) == DM_SUCCESS) {
            r = get_request(skb);
            if (r == NULL) {
                goto err;
            }
            if (put_request_to_node(tempn, r) == DM_ERROR) {
                put_request(r);
                goto err;
            }
            DM_INC_ESTATS(dm_esmib, DM_REQUEST_HOLD);
            goto hold;
        }
    }
    n = get_node(qkey, klen);
    if (!n) {
        goto err;
    }
    list_add(&n->node_list, &hash_bucket->list);
#ifndef DM_TEST
    forward_timer_control(n, TIMER_INSERT);
#endif
    *node_create = n;
    write_unlock_bh(&hash_bucket->l);
    return DM_SUCCESS;
err:
    write_unlock_bh(&hash_bucket->l);
    return DM_ERROR;
hold:
    write_unlock_bh(&hash_bucket->l);
    return DM_HOLD;
}

static void swap_l3_addr(struct iphdr *iph)
{
    iph->saddr ^= iph->daddr;
    iph->daddr ^= iph->saddr;
    iph->saddr ^= iph->daddr;
}

static void swap_l4_port(struct udphdr *udh)
{
    udh->source ^= udh->dest;
    udh->dest ^= udh->source;
    udh->source ^= udh->dest;
}

/*
 * Round-robin scheduling
 * only poll MAX_RR_IP_NUM(13) IPs,if ansnum bigger than it.
 */
void poll_rr(struct ip_list list, struct dm_dnshdr *dnshdr, uint16_t dns_len) {
    //int len = n->ip_list.len<MAX_RR_IP_NUM?n->ip_list.len:MAX_RR_IP_NUM;
    int len = list.len;
    int pos;
    int i, num;
    if (len == 0) return;
    pos = jiffies % len;
    for (i = 0; i < len; i ++) {
        num = (i + pos) % len;
        if (list.list[i].offset + 4 > dns_len) {
            continue;
        }
        memcpy(dnshdr->data+list.list[i].offset,
                list.list[num].value, 4);
    }
}

/*
 * return DM_SUCEESS: ok
 *        DM_ERROR: error, caller should free skb
 */
int answer_from_node(struct node_t *n, struct sk_buff **skb)
{
    struct value_t *dv;
    int old_dns_len, now_dns_len, append;
    uint16_t dnshdr_id;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct udphdr *uh;
    struct dm_dnshdr *dnshdr;
    struct sk_buff *new_skb;

    read_trylock_bh(&n->l);

    if (n->val == NULL) {
        read_unlock_bh(&n->l);
        return DM_ERROR;
    }
    eth = eth_hdr(*skb);
    iph = ip_hdr(*skb);
    uh = (struct udphdr *)((void *)iph + iph->ihl * 4);
    /* netfilter hook datagram at network floor
     * but MEGA must act as the protocal stack with
     * resetting transport headr.
     */
    (*skb)->transport_header = (unsigned char*)uh - (*skb)->head;

    /* deal with l4 payload(dns) */
    dv = n->val;
    old_dns_len = ntohs(uh->len) - sizeof(struct udphdr);
    now_dns_len = dv->len;
    append = now_dns_len - old_dns_len;
    /* SKB->len is unsigned int ,may be overflow*/
    if (append < 0) {
        skb_trim(*skb, (*skb)->len + append);
    } else if (append > (int)(ANSWER_MAX_LEN - (*skb)->len)) {
        DM_INC_ESTATS(dm_esmib, DM_ERROR_BIG_APPEND);
        read_unlock_bh(&n->l);
        return DM_ERROR;
    } else {
        if (append <= skb_tailroom(*skb)) {
            skb_put(*skb, append);
        } else {
            /* original skb too short, get a longer new skb & free old skb
             * maybe happened sending to 10G nic
             */
            new_skb =
                skb_copy_expand(*skb, skb_headroom(*skb), skb_tailroom(*skb) + append, GFP_ATOMIC);
            if (!new_skb) {
                printk("[DNS Mega] error while skb_copy_expand\n");
                DM_INC_ESTATS(dm_esmib, DM_ERROR_NOMEM_SKB);
                read_unlock_bh(&n->l);
                return DM_ERROR;
            }
            kfree_skb(*skb);
            *skb = new_skb;
            eth = eth_hdr(*skb);
            iph = ip_hdr(*skb);
            uh = udp_hdr(*skb);
            skb_put(*skb, append);
        }
    }
    dnshdr = (struct dm_dnshdr*)((void *)uh + sizeof(struct udphdr));
    dnshdr_id = dnshdr->id;
    memcpy(dnshdr, dv->buf, dv->len);
    dnshdr->id = dnshdr_id;
    poll_rr(n->ip_list, dnshdr, dv->len);
    read_unlock_bh(&n->l);

    swap_l4_port(uh);
    swap_l3_addr(iph);
    /* deal with udp */
    uh->len = htons(ntohs(uh->len) + append);
    uh->check = 0;
    (*skb)->csum_start = skb_headroom(*skb) + iph->ihl * 4;
    (*skb)->csum_offset = offsetof(struct udphdr, check);
    uh->check =
        ~csum_tcpudp_magic(iph->daddr, iph->saddr, (*skb)->len - iph->ihl * 4,
                IPPROTO_UDP, 0);
    (*skb)->ip_summed = CHECKSUM_PARTIAL;

    /* deal with ip */
    iph->ttl = IPDEFTTL;
    /* mark the skb, if dm_local_out hook it,
     * dm_local_out would return NF_ACCEPT */
    MEGA_SKB_CB(*skb) = DNS_MAGIC;
    if (update_rt(*skb, iph) == DM_ERROR) {
        DM_INC_ESTATS(dm_esmib, DM_ERROR_UPDATE_RT);
        if (unlikely(DM_GET_ESTATS(dm_esmib, DM_ERROR_UPDATE_RT) % 100 == 1)) {
                printk("ip_route_output error, dst:%pI4 src:%pI4\n",
                        &iph->daddr, &iph->saddr);
        }
        return DM_ERROR;
    }

    /* deal with mac */
    return DM_SUCCESS;
}

static void notify_request(struct node_t *n, struct sk_buff **send_skbs, int *send_num)
{
    int i, ret;
    pop_req_from_wait_list(n, send_skbs, send_num);
    for (i = 0; i < *send_num; i++) {
        ret = answer_from_node(n, &send_skbs[i]);
        if (ret == DM_ERROR) {
            /* skb is created from local_dns_in */
            kfree_skb(send_skbs[i]);
            send_skbs[i] = NULL;
            continue;
        }
    }
}

int cache_response(const uint8_t * qkey, int klen, const uint8_t * qval,
        int vlen, struct dm_dnsans dnsans[], int ansnum)
{
    struct dm_cache_hash *hash_bucket;
    int hash_index;
    int ret = DM_ERROR;
    struct node_t *n;
    int send_num = 0, i;
    struct sk_buff **send_skbs = NULL;
    send_skbs = kmalloc(sysctl_dm_req_waitlist_num * sizeof(struct sk_buff *), GFP_ATOMIC);
    if (send_skbs == NULL) {
        return ret;
    }
    hash_index = hash_val(qkey, klen);
    hash_bucket = &g_domain_cache_hash[hash_index];
    read_trylock_bh(&hash_bucket->l);
    list_for_each_entry(n, &hash_bucket->list, node_list) {
        if (match_node(n, qkey, klen) == DM_SUCCESS) {
            ret = update_node(n, qval, vlen, dnsans, ansnum);
            if (ret == DM_ERROR) {
                goto fin;
            }
            forward_timer_control(n, TIMER_INIT);
            /* In expired node list, move node from middle to tail. */
            expire_timer_control(n, TIMER_REINSERT);
            notify_request(n, send_skbs, &send_num);
            read_unlock_bh(&hash_bucket->l);
            for (i = 0; i < send_num; i ++) {
                if (send_skbs[i] != NULL)
                    DM_XMIT(send_skbs[i]);
            }
            kfree(send_skbs);
            send_skbs = NULL;
            DM_INC_ESTATS(dm_esmib, DM_FWD_REAL_RESPONSE);
            return ret;
        }
    }
    DM_INC_ESTATS(dm_esmib, DM_ERROR_RESPONSE_NO_CACHE);
fin:
    read_unlock_bh(&hash_bucket->l);
    kfree(send_skbs);
    send_skbs = NULL;
    return ret;
}

int forward_traffic_control(void)
{
    int current_qps;

    DM_INC_ESTATS(dm_esmib, DM_FWD_QUERIES);
    current_qps = fold_field(dm_esmib, DM_FWD_QUERIES);

    if (current_qps >
            sysctl_dm_forward_ratelimit_qps * sysctl_dm_forward_ratelimit_sec) {
        DM_INC_ESTATS(dm_esmib, DM_DROP_FORWARD_RATELIMIT);
        return DM_ERROR;
    }

    return DM_SUCCESS;
}

/**
 * process udp dns request
 * @eth		mac header
 * @iph		ip header
 * @uh		udp header
 * @skb		packet
 */
static unsigned int dm_dns_in(struct ethhdr *eth, struct iphdr *iph,
        struct udphdr *uh, struct sk_buff *skb)
{
    uint16_t dns_len;
    int ret = 0, rd = 0;
    struct node_t *node_find, *node_create;
    struct dm_dnshdr *dnshdr;
    struct dm_dnsques dnsques;
    struct sk_buff *new_skb;
    struct dm_cache_hash *hash_bucket = NULL;
    struct request_t *r;
    int ok;
    int hash_index;

    if (skb_is_nonlinear(skb)) {
        DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LINEARIZE_IN);
        return NF_ACCEPT;
    }
    /* Operations mates use dig @127.0.0.1 to check BIND is OK, if Mega answer
     * those queries, BIND down will not soon be found
    */
    if (unlikely(iph->saddr == 0x0100007f)) {
        return NF_ACCEPT;
    }

    /* QPS limit for single ip */
    if ( sysctl_dm_ip_ratelimit_on &&
            ip_traffic_control(iph->saddr, sysctl_dm_ip_ratelimit_qps, DM_IP_LIMIT_QPS) == DM_ERROR) {
        DM_INC_ESTATS(dm_esmib, DM_DROP_SINGLEIP_RATELIMIT);
        goto drop;
    }

    dnshdr = (struct dm_dnshdr *)((void *)uh + sizeof(struct udphdr));

    /* LOCAL_IN get DNS replay package */
    if (dnshdr->qr == DM_DNSRES) {
        goto accept;
    }

    dns_len = ntohs(uh->len) - sizeof(struct udphdr);
    if (unlikely(iph->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dm_dnshdr) > skb->len)) {
        DM_INC_ESTATS(dm_esmib, DM_DROP_PAC_INCOMPLETE);
        goto drop;
    }

    /*
     * Add question length limit, this limit is not the rfc specity.
     * As most dns req packet length less than 128-Byte, We found in
     * 90w dns request packet, only less than 100 dns req packet length
     * over 128-Byte, and most of them are malice request. So when dns attack
     * comes, we can use the limit to filte some request, this is a tradeoff
     */
    if (unlikely(dns_len > QUESTION_MAX_LEN)) {
        DM_INC_ESTATS(dm_esmib, DM_DROP_PAC_OVERSIZE);
        goto drop;
    }

    /* parse dns request, check validity, and get domain name and wild domain name */
    ret = parse_dns_message(dnshdr, dns_len, &dnsques, NULL, NULL);
    if (ret == DM_NOSUPPORT) {
        DM_INC_ESTATS(dm_esmib, DM_ACCEPT_NOSUPPORT);
        goto accept;
    } else if (ret == DM_ERROR) {
        DM_INC_ESTATS(dm_esmib, DM_DROP_PARSE_ERROR);
        goto drop;
    }

    /* key is "query domain + query opt(rd) + query type" */
    if (dnshdr->rd & 0x01) {
        rd = 1;
    }
    if (dnsques.qsize + 3 >= 255) {
        DM_INC_ESTATS(dm_esmib, DM_ACCEPT_NOSUPPORT);
        goto accept;
    }
    DM_INC_ESTATS(dm_esmib, DM_REQUEST_IN);
    memcpy(dnsques.qname + dnsques.qsize, &rd, 1);
    memcpy(dnsques.qname + dnsques.qsize+ 1, &(dnsques.qtype), 2);

    hash_index = hash_val(dnsques.qname, dnsques.qsize + 2);
    hash_bucket = &g_domain_cache_hash[hash_index];

    /* find update and hold neet in the read lock of bucket
     * insert can not in read lock,becase it will edit the link
     */
    read_trylock_bh(&hash_bucket->l);
    /* Very important function in packet process! */
    ret = cache_find(dnsques.qname, dnsques.qsize + 2, skb, &node_find, hash_bucket);
    if (ret == CACHE_FIND) {
        DM_INC_ESTATS(dm_esmib, DM_REQUEST_HIT);
        ok = answer_from_node(node_find, &skb);
        if (ok == DM_ERROR) {
            DM_INC_ESTATS(dm_esmib, DM_DROP_GENPAC_ERROR);
            kfree_skb(skb);
            goto dm_stolen;
        }
        read_unlock_bh(&hash_bucket->l);
        DM_XMIT(skb);
        goto stolen;
    } else if (ret == CACHE_UPDATE) {
        DM_INC_ESTATS(dm_esmib, DM_REQUEST_HIT);
        new_skb = skb_copy(skb, GFP_ATOMIC);
        if (new_skb == NULL) {
            DM_INC_ESTATS(dm_esmib, DM_ERROR_NOMEM_SKB);
            goto dm_accept;
        }
        DM_INC_ESTATS(dm_esmib, DM_REQUEST_PREFETCH);
        ok = answer_from_node(node_find, &new_skb);
        if (ok == DM_ERROR) {
            kfree_skb(new_skb);
            goto dm_accept;
        }
        read_unlock_bh(&hash_bucket->l);
        DM_XMIT(new_skb);
        goto accept;
    } else if (ret == CACHE_HOLD) {
        r = get_request(skb);
        if (r == NULL) {
            DM_INC_ESTATS(dm_esmib, DM_DROP_NOMEM_REQUEST);
            goto dm_accept;
        }
        if (put_request_to_node(node_find, r) == DM_ERROR) {
            put_request(r);
            goto dm_drop;
        }
        DM_INC_ESTATS(dm_esmib, DM_REQUEST_HOLD);
        goto dm_stolen;
    }
    read_unlock_bh(&hash_bucket->l);

    /* do insert */
    if (ret == CACHE_INSERT) {
        /* QPS limit for single ip's first DNS query*/
        if ( sysctl_dm_ip_rec_ratelimit_on &&
            ip_traffic_control(iph->saddr, sysctl_dm_ip_rec_ratelimit_qps, DM_IP_REC_LIMIT_QPS) == DM_ERROR) {
            DM_INC_ESTATS(dm_esmib, DM_DROP_REC_RATELIMIT);
            goto drop;
        }

        if (forward_traffic_control() == DM_SUCCESS) {
            ret = cache_insert(skb, dnsques.qname, dnsques.qsize + 2, &node_create, hash_bucket);
            if (ret == DM_HOLD) {
                /* DROP AND LOG */
                goto stolen;
            } else if (ret == DM_ERROR) {
                DM_INC_ESTATS(dm_esmib, DM_DROP_SAME_REQUEST);
                goto drop;
            } else {
                DM_INC_ESTATS(dm_esmib, DM_REQUEST_REC);
                goto accept;
            }
        } else {
            /* DM_FORWARDE_RATELIMIT counter is write in forward_traffic_control() */
            goto drop;
        }
    }
    if (ret == CACHE_DROP) {
        DM_INC_ESTATS(dm_esmib, DM_DROP_WAITLIST_FULL);
        goto drop;
    }
dm_accept:
    read_unlock_bh(&hash_bucket->l);
accept:
    DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LOCAL_IN_L7);
    return NF_ACCEPT;

dm_drop:
    read_unlock_bh(&hash_bucket->l);
drop:
    return NF_DROP;

dm_stolen:
    read_unlock_bh(&hash_bucket->l);
stolen:
    return NF_STOLEN;
}

unsigned int dm_udp_in(struct ethhdr *eth, struct iphdr *iph,
        struct sk_buff *skb)
{
    struct udphdr *uh;

    /* __skb_linearize and pskb_may_pull may expand memory of skb
     * need recalculate iph */
    iph = ip_hdr(skb);
    uh = (struct udphdr *)((void *)iph + iph->ihl * 4);

    if (unlikely(iph->ihl * 4 + sizeof(struct udphdr) > skb->len))
        goto accept;

    /* check if it's a dns packet */
    if (uh->dest != htons(sysctl_dm_dns_port))
        goto accept;

    if (unlikely(iph->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dm_dnshdr) > skb->len))
        goto accept;

    return dm_dns_in(eth, iph, uh, skb);

accept:
    DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LOCAL_IN_L4);
    return NF_ACCEPT;
}

static unsigned int dm_ipv4_in(struct ethhdr *eth, struct sk_buff *skb)
{
    struct iphdr *iph;
    int len;

    /* check we have sizeof(iphdr) in the first */
    //if (!pskb_may_pull(skb, sizeof(struct iphdr)))
    if (unlikely(sizeof(struct iphdr) > skb->len))
        goto accept;

    /* check the ip header arg */
    iph = ip_hdr(skb);
    if (iph->ihl < 5 || iph->version != 4)
        goto accept;

    /* check we have total ip header in the first */
    if (unlikely(iph->ihl * 4 > skb->len))
    //if (!pskb_may_pull(skb, iph->ihl * 4))
        goto accept;

    /* Now we don't support IP fragment */
    if (iph->frag_off & htons(IP_OFFSET | IP_MF))
        goto accept;

    /* check the len is ok */
    len = ntohs(iph->tot_len);
    if (skb->len < len || len < 4 * iph->ihl)
        goto accept;

    switch (iph->protocol) {
        case IPPROTO_UDP:
            return dm_udp_in(eth, iph, skb);
        default:
            break;
    }

accept:
    DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LOCAL_IN_L3);
    return NF_ACCEPT;
}

    unsigned int
dm_local_in(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn) (struct sk_buff *))
{
    struct ethhdr *l2hdr = eth_hdr(skb);
    unsigned int ret;

    if (unlikely(!sysctl_dm_on)) {
        return NF_ACCEPT;
    }

    if (unlikely(skb->pkt_type != PACKET_HOST))
        return NF_ACCEPT;

    if (l2hdr->h_proto != htons(ETH_P_IP))
        return NF_ACCEPT;

    if (is_multicast_ether_addr(l2hdr->h_dest))
        return NF_ACCEPT;

    ret = dm_ipv4_in(l2hdr, skb);
    return ret;
}

/**
 * process udp dns request
 * @eth		mac header
 * @iph		ip header
 * @uh		udp header
 * @skb		packet
 */
unsigned int dm_dns_out(const struct iphdr *iph, const struct udphdr *uh,
        struct sk_buff *skb)
{
    int ret = 0, rd = 0, ansnum, dns_len;
    struct dm_dnshdr *dnshdr;
    struct dm_dnsques dnsques;
    struct dm_dnsans *dnsans;

    if (skb_is_nonlinear(skb)) {
        DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LINEARIZE_OUT);
        return NF_ACCEPT;
    }
    if (iph->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dm_dnshdr) > skb->len)
        goto accept;

    /* Operations mates use dig @127.0.0.1 to check BIND is OK, if Mega answer
       those queries, BIND down will not soon be found.
       look for /etc/keepalived/keepalived.conf
     */
    if (unlikely(iph->daddr == 0x0100007f)) {
        DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LOOPBACK_OUT);
        return NF_ACCEPT;
    }

    update_gso(skb);

    dnshdr = (struct dm_dnshdr *)((void *)uh + sizeof(struct udphdr));

    /* pass dns request packet */
    if (unlikely(dnshdr->qr != DM_DNSRES)) {
        goto accept;
    }

    dns_len = ntohs(uh->len) - sizeof(struct udphdr);
    if (unlikely(iph->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dm_dnshdr) > skb->len)) {
        DM_INC_ESTATS(dm_esmib, DM_DROP_PAC_INCOMPLETE);
        return NF_DROP;
    }

    /*
     * Most packets are less than 1472. Assume MTU is 1500, 1472 = 1500 - 20 - 8
     */
    if (unlikely(dns_len > ANSWER_MAX_LEN)) {
        goto accept;
    }

    /* parse dns request, check validity, and get domain name and wild domain name */
    dnsans = (struct dm_dnsans*)kmalloc(sizeof(struct dm_dnsans)*MAX_ANSWER_NUM, GFP_ATOMIC);
    if (dnsans == NULL) {
        goto accept;
    }
    ansnum = 0;
    ret = parse_dns_message(dnshdr, dns_len, &dnsques, dnsans, &ansnum);

    if (ret != DM_SUCCESS || ansnum > MAX_ANSWER_NUM) {
        kfree(dnsans);
        goto accept;
    }

    if (dnshdr->rd & 0x01) {
        rd = 1;
    }
    if (dnsques.qsize + 3 >= 255) {
        kfree(dnsans);
        goto accept;
    }
    memcpy(dnsques.qname + dnsques.qsize, &rd, 1);
    memcpy(dnsques.qname + dnsques.qsize+ 1, &dnsques.qtype, 2);
    ret =
        cache_response(dnsques.qname, dnsques.qsize+ 2, (uint8_t *) dnshdr,
                dns_len, dnsans, ansnum);
    kfree(dnsans);
    if (ret == DM_UPDATE_NODE) {
        /* If return NF_DROP, BIND would log "error sending response: host unreachable"
           Maybe BIND check response is send or not. */
        kfree_skb(skb);
        return NF_STOLEN;
    } else if (ret == DM_NEW_NODE || ret == DM_ERROR) {
        DM_INC_ESTATS(dm_esmib, DM_REQUEST_OUT);
        goto accept;
    }

accept:
    DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LOCAL_OUT_L7);
    return NF_ACCEPT;
}

unsigned int dm_udp_out(const struct iphdr *iph, struct sk_buff *skb)
{
    const struct udphdr *uh;

    iph = ip_hdr(skb);
    if (iph->ihl * 4 + sizeof(struct udphdr) > skb->len)
        goto accept;

    uh = (const struct udphdr *)((void *)iph + iph->ihl * 4);

    /* check if it's a dns response packet */
    if (uh->source != htons(sysctl_dm_dns_port))
        goto accept;

    return dm_dns_out(iph, uh, skb);

accept:
    DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LOCAL_OUT_L4);
    return NF_ACCEPT;
}

static unsigned int dm_ipv4_out(struct sk_buff *skb)
{
    const struct iphdr *iph;
    int len;

    /* check we have sizeof(iphdr) in the first */
    if (unlikely(sizeof(struct iphdr) > skb->len))
        goto accept;

    /* check the ip header arg */
    iph = (const struct iphdr *)skb_network_header(skb);
    if (iph->ihl < 5 || iph->version != 4)
        goto accept;

    /* check we have total ip header in the first */
    if (unlikely(iph->ihl * 4 > skb->len))
        goto accept;
    iph = (const struct iphdr *)skb_network_header(skb);

    /* check the len is ok */
    len = ntohs(iph->tot_len);
    if (skb->len < len || len < 4 * iph->ihl)
        goto accept;

    /* Now we don't support IP fragment */
    if (iph->frag_off & htons(IP_OFFSET | IP_MF))
        goto accept;

    switch (iph->protocol) {
        case IPPROTO_UDP:
            return dm_udp_out(iph, skb);
        default:
            break;
    }

accept:
    DM_INC_ESTATS(dm_esmib, DM_ACCEPT_LOCAL_OUT_L3);
    return NF_ACCEPT;
}

    unsigned int
dm_local_out(unsigned int hook, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int (*okfn) (struct sk_buff *))
{
    unsigned int ret;

    if (unlikely(!sysctl_dm_on))
        goto accept;

    /* if a skb come from mega, its cb[47] would be DNS_MAGIC
     * so don't hook the package from myself */
    if (likely(MEGA_SKB_CB(skb) == DNS_MAGIC)) {
        goto accept;
    }

    ret = dm_ipv4_out(skb);
    return ret;

accept:
    return NF_ACCEPT;
}
