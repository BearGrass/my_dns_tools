#include "common.h"
#include "log.h"
#include "ldns.h"
#include "list.h"
#include "fwd_user.h"
#include "fwd_user_db.h"
#include "fwd_ip_user_tbl.h"
#include "ip_filter.h"
#include "dns_pkt.h"


static struct rte_mempool *g_ip_user_pools = NULL;
uint32_t g_ip_user_max_num = 1 << 20;

static inline void _fwd_ip_user_tbl_add(fwd_ip_user_t *ip_usr,
		struct fwd_ip_user_tbl_hash_node *h_node);
static inline void _fwd_ip_user_tbl_del(fwd_ip_user_t *ip_usr,
		struct fwd_ip_user_tbl_hash_node *h_node);

/*
 * Converts a given depth value to its corresponding mask value.
 *
 * depth  (IN)		: range = 1 - 32
 * mask   (OUT)		: 32bit mask
 */
static uint32_t __attribute__((pure))
depth_to_mask(uint8_t depth)
{
	/* To calculate a mask start with a 1 on the left hand side and right
	 * shift while populating the left hand side with 1's
	 */
	return (int)0x80000000 >> (depth - 1);
}

static inline fwd_ip_user_t *
_fwd_ip_user_new_v4(uint32_t ip_addr, fwd_user_t *user)
{
	fwd_ip_user_t *ip_user;

	if (rte_mempool_get(g_ip_user_pools, (void**) &ip_user) < 0) {
		ALOG(SERVER, ERROR,
				"rte_mempool_get failed, pool name = g_ip_user_pools");
		return NULL;
	}

	ip_user->family = IP_RANGE_FAMILY_IPV4;
	ip_user->addr.v4 = ip_addr;
	ip_user->user = user;

	return ip_user;
}

static inline fwd_ip_user_t *
_fwd_ip_user_new_v6(uint8_t *ip6_addr, fwd_user_t *user)
{
	fwd_ip_user_t *ip_user;

	if (rte_mempool_get(g_ip_user_pools, (void**) &ip_user) < 0) {
		ALOG(SERVER, ERROR,
				"rte_mempool_get failed, pool name = g_ip_user_pools");
		return NULL;
	}

	ip_user->family = IP_RANGE_FAMILY_IPV6;
	rte_memcpy(ip_user->addr.v61, ip6_addr, 16);
	ip_user->user = user;

	return ip_user;
}

static inline fwd_ip_user_t* _fwd_ip_user_tbl_lookup_v6(fwd_ip_user_tbl_t *tbl,
		uint8_t *ip6_addr, struct fwd_ip_user_tbl_hash_node **h_node) {
	uint32_t hash;
	fwd_ip_user_t *ip_usr;
	const struct list_head *h_list;

	hash = rte_jhash(ip6_addr, 16, 0) % FWD_IP_USER_TBL_HASH_SIZE;
	*h_node = &tbl->ip_nodes[hash];
	h_list = &((*h_node)->list);

	list_for_each_entry(ip_usr, h_list, list)
	{
		if (ip_usr->family == IP_RANGE_FAMILY_IPV6
				&& !memcmp(ip_usr->addr.v61, ip6_addr, 16)) {
			return ip_usr;
		}
	}

	return NULL;
}

static inline fwd_ip_user_t* _fwd_ip_user_tbl_lookup_v4(fwd_ip_user_tbl_t *tbl,
		uint32_t ip_addr, struct fwd_ip_user_tbl_hash_node **h_node) {
	uint32_t hash;
	fwd_ip_user_t *ip_usr;
	struct list_head *h_list;

	hash = rte_jhash_1word(ip_addr, 0) % FWD_IP_USER_TBL_HASH_SIZE;
	*h_node = &tbl->ip_nodes[hash];
	h_list = &((*h_node)->list);

	list_for_each_entry(ip_usr, h_list, list)
	{
		if (ip_usr->family == IP_RANGE_FAMILY_IPV4
				&& ip_usr->addr.v4 == ip_addr) {
			return ip_usr;
		}
	}

	return NULL;
}

static inline int _get_ip_range_v4(ip_range_t *ip_range, uint32_t *start_ip,
		uint32_t *end_ip) {
	uint32_t ip_mask;

	if (ip_range->mask > 32 || ip_range->mask < IP_RANGE_MIN_MASK_DEPTH) {
		return -1;
	}
	ip_mask = depth_to_mask(ip_range->mask);
	*start_ip = ip_range->addr.v4 & ip_mask;
	*end_ip = ip_range->addr.v4 | (~ip_mask);

	return 0;
}

int fwd_ip_user_tbl_add(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges) {
	int i;
	struct fwd_ip_user_tbl_hash_node *h_node;
	fwd_ip_user_t *old_ip_user, *new_ip_user;

	if (range_num == 0 || ip_ranges == NULL) {
		return 0;
	}

	for (i = 0; i <range_num; i++) {
		if (ip_ranges[i].family == IP_RANGE_FAMILY_IPV4) {
			uint32_t cur_ip, start_ip, end_ip, n_cur_ip;

			if (_get_ip_range_v4(&ip_ranges[i], &start_ip, &end_ip) != 0) {
				ALOG(SERVER, ERROR, "Add user %u: IP mask %u is invalid",
						user->user_id, ip_ranges[i].mask);
				// rollback
				fwd_ip_user_tbl_del(user, i, ip_ranges);
				return -1;
			}

			for (cur_ip = start_ip; cur_ip <= end_ip; cur_ip++) {
				n_cur_ip = adns_htonl(cur_ip);
				old_ip_user = _fwd_ip_user_tbl_lookup_v4(g_fwd_ip_user_tbl,
						n_cur_ip, &h_node);
				if (old_ip_user != NULL) {
					if (old_ip_user->user == user) {
						ALOG(SERVER, WARN, "Add user %u: IP %u has been assigned",
								user->user_id, cur_ip);
						/* do nothing */
						continue;
					} else {
						ALOG(SERVER, ERROR,
								"Add user %u: IP %u has been assigned to user %u",
								user->user_id, cur_ip,
								old_ip_user->user->user_id);
						// rollback
						fwd_ip_user_tbl_del(user, i + 1, ip_ranges);
						return -1;
					}
				}

				new_ip_user = _fwd_ip_user_new_v4(n_cur_ip, user);
				if (new_ip_user == NULL) {
					// rollback
					fwd_ip_user_tbl_del(user, i + 1, ip_ranges);
					return -1;
				}
				_fwd_ip_user_tbl_add(new_ip_user, h_node);
			}
		} else if (ip_ranges[i].family == IP_RANGE_FAMILY_IPV6) {
			// TODO: Support ipv6 later
			ALOG(SERVER, WARN, "Add user %u: unsupported ip family 6");
			continue;
		} else {
			ALOG(SERVER, ERROR, "Add user %u: unsupported ip family %u",
					user->user_id, ip_ranges[i].family);
			return -1;
		}
	}

	return 0;
}

int fwd_ip_user_tbl_del(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges) {
	int i;
	struct fwd_ip_user_tbl_hash_node *h_node;
	fwd_ip_user_t *old_ip_user;

	if (range_num == 0 || ip_ranges == NULL) {
		return 0;
	}

	for (i = 0; i < range_num; i++) {
		if (ip_ranges[i].family == IP_RANGE_FAMILY_IPV4) {
			uint32_t cur_ip, start_ip, end_ip, n_cur_ip;

			if (_get_ip_range_v4(&ip_ranges[i], &start_ip, &end_ip) != 0) {
				ALOG(SERVER, ERROR, "Delete user %u: IP mask %u is invalid",
						user->user_id, ip_ranges[i].mask);
				continue;
			}

			for (cur_ip = start_ip; cur_ip <= end_ip; cur_ip++) {
				n_cur_ip = adns_htonl(cur_ip);
				old_ip_user = _fwd_ip_user_tbl_lookup_v4(g_fwd_ip_user_tbl,
						n_cur_ip, &h_node);
				if (old_ip_user == NULL) {
					ALOG(SERVER, WARN, "Delete user %u: IP %u has been deleted",
							user->user_id, cur_ip);
					continue;
				}

				if (old_ip_user->user != user) {
					ALOG(SERVER, ERROR,
							"Delete user %u: IP %u has been assigned to user %u",
							user->user_id, cur_ip, old_ip_user->user->user_id);
					continue;
				}
				_fwd_ip_user_tbl_del(old_ip_user, h_node);
			}
		} else if (ip_ranges[i].family == IP_RANGE_FAMILY_IPV6) {
			// TODO: Support ipv6 later
			ALOG(SERVER, WARN, "Delete user %u: unsupported ip family 6");
			continue;
		} else {
			ALOG(SERVER, ERROR, "Delete user %u: unsupported ip family %u",
					user->user_id, ip_ranges[i].family);
			return -1;
		}
	}

	return 0;
}

static inline fwd_ip_user_tbl_t *
_fwd_ip_user_tbl_new(const char *name)
{
	fwd_ip_user_tbl_t *tbl;
    int i;

	tbl = rte_malloc_socket(name, sizeof(fwd_ip_user_tbl_t), 0,
			rte_lcore_to_socket_id(rte_lcore_id()));
    if (tbl == NULL) {
    	RTE_LOG(ERR, LDNS, "[%s]: Failed to alloc g_fwd_ip_user_tbl\n",
    				__FUNCTION__);
        return NULL;
    }

    for (i = 0; i < FWD_IP_USER_TBL_HASH_SIZE; i++) {
        INIT_LIST_HEAD(&(tbl->ip_nodes[i].list));
        tbl->ip_nodes[i].size = 0;
    }
    tbl->ip_count = 0;

    return tbl;
}

int fwd_ip_user_tbl_init() {
    fwd_ip_user_tbl_t *tbl = NULL;

	tbl = _fwd_ip_user_tbl_new("g_fwd_ip_user_tbl");
	if (tbl == NULL) {
		return -1;
	}
	g_fwd_ip_user_tbl = tbl;
	RTE_LOG(INFO, LDNS, "[%s]: Finish to new g_fwd_ip_user_tbl\n", __FUNCTION__);

	g_ip_user_pools = rte_mempool_create("g_ip_user_pools", g_ip_user_max_num,
			sizeof(fwd_ip_user_t), 32, 0, NULL, NULL,
			NULL, NULL, rte_lcore_to_socket_id(rte_lcore_id()),
			MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
	if (g_ip_user_pools == NULL) {
		RTE_LOG(ERR, LDNS, "[%s]: Failed to alloc g_ip_user_pools\n",
				__FUNCTION__);
		return -1;
	}
    g_user_queue_offset = 0;
	RTE_LOG(INFO, LDNS, "[%s]: Finish to alloc g_ip_user_pools\n", __FUNCTION__);

	return 0;
}

static inline void _fwd_ip_user_tbl_add(fwd_ip_user_t *ip_usr,
		struct fwd_ip_user_tbl_hash_node *h_node) {
	struct list_head *h_list;

	h_list = &(h_node->list);
	list_add(&(ip_usr->list), h_list);
	h_node->size++;
	g_fwd_ip_user_tbl->ip_count++;
	if (ip_usr->family == IP_RANGE_FAMILY_IPV4) {
		set_ip_filter(ip_usr->addr.v4, IP_FILTER_MASK_VIP);
	} else {
		set_ipv6_filter(ip_usr->addr.v61, IP_FILTER_MASK_VIP);
	}
}

static inline void _fwd_ip_user_tbl_del(fwd_ip_user_t *ip_usr,
		struct fwd_ip_user_tbl_hash_node *h_node) {
	if (ip_usr->family == IP_RANGE_FAMILY_IPV4) {
		unset_ip_filter(ip_usr->addr.v4, IP_FILTER_MASK_VIP);
	} else {
		unset_ipv6_filter(ip_usr->addr.v61, IP_FILTER_MASK_VIP);
	}
	list_del(&ip_usr->list);
	rte_mempool_put(g_ip_user_pools, (void*) ip_usr);

	if (unlikely(h_node->size == 0)) {
		ALOG(SERVER, WARN, "LCORE %d : FWD IP User hash node size is 0",
				rte_lcore_id());
	} else {
		h_node->size--;
	}

	if (unlikely(g_fwd_ip_user_tbl->ip_count == 0)) {
		ALOG(SERVER, WARN, "LCORE %d : FWD IP User TBL IP count is 0",
				rte_lcore_id());
	} else {
		g_fwd_ip_user_tbl->ip_count--;
	}
}

void fwd_ip_user_tbl_clear() {
	int i;
	fwd_ip_user_t *ip_usr, *ip_usr_next;

	if (g_fwd_ip_user_tbl == NULL) {
		ALOG(SERVER, WARN, "LCORE %d : FWD IP User TBL does not existed",
				rte_lcore_id());
		return;
	}

	if (g_fwd_ip_user_tbl->ip_count > 0) {
		for (i = 0; i < FWD_IP_USER_TBL_HASH_SIZE; i++) {
			list_for_each_entry_safe(ip_usr, ip_usr_next,
					&g_fwd_ip_user_tbl->ip_nodes[i].list, list)
			{
				_fwd_ip_user_tbl_del(ip_usr, &g_fwd_ip_user_tbl->ip_nodes[i]);
			}
			g_fwd_ip_user_tbl->ip_nodes[i].size = 0;
		}

		g_fwd_ip_user_tbl->ip_count = 0;
	}
}
