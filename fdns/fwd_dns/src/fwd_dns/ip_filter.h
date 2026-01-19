#ifndef __IP_FILTER_H_
#define __IP_FILTER_H_

#include<stdint.h>
#include "rte_core.h"
#include "list.h"

/*! MASK for IP filter.status */
typedef enum ip_filter_mask {
    IP_FILTER_MASK_NONE = (uint8_t)0x01U,
    IP_FILTER_MASK_BLOCK = (uint8_t)0x02U,
    IP_FILTER_MASK_RECUS = (uint8_t)0x04U,
    IP_FILTER_MASK_CACHE = (uint8_t)0x08U,
    IP_FILTER_MASK_SEC = (uint8_t)0x10U,
	IP_FILTER_MASK_VIP = (uint8_t)0x20U,
} ip_filter_mask_t;

typedef struct ipv6_filter_t{
    struct list_head list;
    uint8_t ipv6_addr[16];
    uint8_t filter;
} ipv6_filter;

extern uint8_t *g_ip_filter_db;
extern hash_table *g_ipv6_filter_db;

static inline uint8_t get_ip_filter(uint32_t ip_addr, ip_filter_mask_t mask) {
    return g_ip_filter_db[ip_addr] & (uint8_t)mask;
}

static inline void set_ip_filter(uint32_t ip_addr, ip_filter_mask_t mask) {
    g_ip_filter_db[ip_addr] |= (uint8_t)mask;
}

static inline void unset_ip_filter(uint32_t ip_addr, ip_filter_mask_t mask) {
    g_ip_filter_db[ip_addr] &= ~(uint8_t)mask;
}

static inline uint8_t man_ip_blacklist_judge(const uint32_t src_ip) {
    return get_ip_filter(src_ip, IP_FILTER_MASK_BLOCK);
}

static inline uint8_t vip_judge(const uint32_t src_ip) {
    return get_ip_filter(src_ip, IP_FILTER_MASK_VIP);
}

extern ipv6_filter *get_ipv6_filter_info(uint8_t ipv6_addr[16]);

static inline uint8_t get_ipv6_filter_by_info(ipv6_filter * ip6_info,
        ip_filter_mask_t mask) {
    if (ip6_info == NULL) {
        return 0;
    } else {
        return ip6_info->filter & (uint8_t) mask;;
    }
}

static inline uint8_t get_ipv6_filter(uint8_t ipv6_addr[16],
        ip_filter_mask_t mask) {
    ipv6_filter *ip6_info = get_ipv6_filter_info(ipv6_addr);
    return get_ipv6_filter_by_info(ip6_info, mask);
}

extern int init_ip_filter();
extern void charge_man_ip_blacklist_state();//only called at misc core
extern void set_ipv6_filter(uint8_t ipv6_addr[16], ip_filter_mask_t mask);
extern void unset_ipv6_filter(uint8_t ipv6_addr[16], ip_filter_mask_t mask);

#endif
