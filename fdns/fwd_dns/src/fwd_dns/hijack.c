#include <stdio.h>
#include <unistd.h>
#include <rte_mbuf.h>

#include "descriptor.h"
#include "dns_pkt.h"
#include "hijack.h"
#include "stats.h"
#include "log.h"
#include "utils.h"

char *chaos_type[] = {"hostname.fwd.", "client.view.", "client.ip."};
char g_hostname[MAX_HOSTNAME_LEN];

int inline is_hijacked(struct dns_packet *pkt) {
    /* CHAOS QUERY && TXT TYPE */
    if (pkt->qclass == ADNS_CLASS_CH && pkt->qtype == ADNS_RRTYPE_TXT)
        return 1;
    return 0;
}

int get_hijack_type(struct dns_packet *pkt) {
    int i;
    for (i = 0; i < MAX_CHAOS_NUM; i ++) {
        if (!strcmp(pkt->dname, chaos_type[i])) {
            return i;
        }
    }
    return -1;
}

int answer_from_hijack(struct rte_mbuf *m, struct dns_packet *query,
        union common_ip_head *ip_head, union common_l4_head *l4_head,
        struct dns_header *dnh, char *buf, int is_ipv6) {
    int append, L;
    struct dns_chaos_answer *ans;
    char *ansbuf;
    L = strlen(buf);
    if (L == 0) {
        resp_set_refuse(dnh);
        ldns_wire_set_qr((uint8_t *)dnh); /* set QR bit */
        /*
            ALOG(ANSWER, INFO,
                    "LCORE %d : AnswerQuery hijack type is not existed, return refuse",
                    rte_lcore_id());
        */
        STATS(UNSUPPORT_HIJACK);
        return 0;
    }
    append = 1 + L + sizeof(struct dns_chaos_answer);
    if (query->has_edns) {
        append -= query->parsed - query->answered;
    }
    if (unlikely(rte_pktmbuf_append(m, append) < 0)) {
        //ALOG(ANSWER, ERROR, "APPEND_FAIL");
        STATS(MBUF_APPEND_DROP);
        return -1;
    }
    resp_set_noerror(dnh);
    resp_init_header(dnh);
    ldns_wire_set_ancount((uint8_t *)dnh, 1);
    ldns_wire_set_nscount((uint8_t *)dnh, 0);
    ldns_wire_set_arcount((uint8_t *)dnh, 0);
    ans = (struct dns_chaos_answer*)((uint8_t *)dnh + query->answered);
    ansbuf = (char *)(ans->buf);
    ans->cdomain = 0x0cc0;
    ans->ctype = adns_htobe16(query->qtype);
    ans->cclass = adns_htobe16(query->qclass);
    ans->cttl = 0;
    ans->clen = adns_htobe16(L + 1);
    ansbuf[0] = L;
    rte_memcpy(ansbuf + 1, buf, L);

    if (!is_ipv6) {
        ip_head->ipv4_hdr.total_length = adns_htons(
                adns_ntohs(ip_head->ipv4_hdr.total_length) + append);
    } else {
        ip_head->ipv6_hdr.payload_len = adns_htons(
                adns_ntohs(ip_head->ipv6_hdr.payload_len) + append);
    }
    l4_head->udp_hdr.dgram_len = adns_htons(adns_ntohs(l4_head->udp_hdr.dgram_len) + append);
    /*
        ALOG(ANSWER, INFO,
                "LCORE %d : AnswerQuery from forwarder, hijack value:%s",
                rte_lcore_id(), buf);
    */
    STATS(HIJACK_ANSWER);
    return 0;
}

int hijack_init() {
    int ret;
    ret = gethostname(g_hostname, MAX_HOSTNAME_LEN);
    if (ret < 0) {
        RTE_LOG(ERR, LDNS, "Failed to get hostname\n");
        return -1;
    }
    return 0;
}
