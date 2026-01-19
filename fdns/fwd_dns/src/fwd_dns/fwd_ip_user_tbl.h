#ifndef _FWD_IP_USER_TBL_H_
#define _FWD_IP_USER_TBL_H_

#include "fwd_user.h"

#define FWD_IP_USER_TBL_HASH_SIZE (1<<19)

struct fwd_ip_user_tbl_hash_node {
    struct list_head list;
    uint32_t size;
};

typedef struct fwd_ip_user {
    struct list_head list;
    uint8_t family;		/* address family, 1:IPv4, 2:IPv6 */
	// support both ipv4 and ipv6
	union {
		uint32_t v4; /* IPv4 address */
		uint8_t v61[16]; /* IPv6 address of uint8_t */
		uint16_t v62[8]; /* IPv6 address of uint16_t */
		uint32_t v63[4]; /* IPv6 address of uint32_t */
		uint64_t v64[2]; /* IPv6 address of uint64_t */
	} addr;
    fwd_user_t *user;
} fwd_ip_user_t;

typedef struct fwd_ip_user_tbl {
    struct fwd_ip_user_tbl_hash_node ip_nodes[FWD_IP_USER_TBL_HASH_SIZE];
    uint32_t ip_count;
} fwd_ip_user_tbl_t;
fwd_ip_user_tbl_t *g_fwd_ip_user_tbl;

extern uint32_t g_ip_user_max_num;

// for performance, the ip_addr is stored as network byte order in g_fwd_ip_user_tbl
static inline fwd_user_t* fwd_ip_user_tbl_lookup_v4_fast(uint32_t ip_addr) {
	uint32_t hash;
	fwd_ip_user_t *ip_usr;
	struct list_head *h_list;
	struct fwd_ip_user_tbl_hash_node *h_node;

	hash = rte_jhash_1word(ip_addr, 0) % FWD_IP_USER_TBL_HASH_SIZE;
	h_node = &g_fwd_ip_user_tbl->ip_nodes[hash];
	h_list = &(h_node->list);

	list_for_each_entry(ip_usr, h_list, list)
	{
		if (ip_usr->family == IP_RANGE_FAMILY_IPV4
				&& ip_usr->addr.v4 == ip_addr) {
			return ip_usr->user;
		}
	}

	return NULL;
}

int fwd_ip_user_tbl_add(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges);
int fwd_ip_user_tbl_del(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges);

int fwd_ip_user_tbl_init();
void fwd_ip_user_tbl_clear();

#endif /* _FWD_IP_USER_TBL_H_ */
