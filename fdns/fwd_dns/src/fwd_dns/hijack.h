#ifndef __FWD_HIJACK__
#define __FWD_HIJACK__

#include <stdio.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "dns_pkt.h"
#include "consts.h"

#define MAX_HOSTNAME_LEN 255

extern char *chaos_type[];
extern char g_hostname[MAX_HOSTNAME_LEN];

enum chaos_t{
    HOSTNAME = 0,
    VIEWNAME,
    CLIENTIP,
    MAX_CHAOS_NUM,
};

extern int hijack_init();
int inline is_hijacked(struct dns_packet *pkt);
int get_hijack_type(struct dns_packet *pkt);
int answer_from_hijack(struct rte_mbuf *m, struct dns_packet *query,
        union common_ip_head *ip_head, union common_l4_head *l4_head,
        struct dns_header *dnh, char *buf, int is_ipv6);

#endif
