#include "common.h"
#include "log.h"
#include "ldns.h"
#include "list.h"
#include "snapshot.h"
#include "fwd_user.h"
#include "fwd_ip_user_tbl.h"

static struct rte_mempool *g_fwd_user_pool = NULL;
uint32_t g_fwd_user_max_num = 1 << 19;

static inline int fwd_user_cmp(const ip_range_t *fwd_user_1,
		const ip_range_t *fwd_user_2) {
	// internal function, ignore the argument validation
	if (fwd_user_1 == fwd_user_2) {
		return 0;
	}

	if ((fwd_user_1->family != fwd_user_2->family)
			|| (fwd_user_1->mask != fwd_user_2->mask)) {
		return 1;
	}

	if (fwd_user_1->addr.v4 != fwd_user_2->addr.v4) {
		return 1;
	}

	if (fwd_user_1->family == IP_RANGE_FAMILY_IPV6) {
		if (memcmp(&fwd_user_1->addr.v61[4], &fwd_user_2->addr.v61[4], 12)) {
			return 1;
		}
	}

	return 0;
}

int fwd_user_add_ip_ranges(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges) {
	uint8_t is_exist;
	int i, j;

	if (range_num > MAX_USER_IP_RANGE_NUM) {
		ALOG(SERVER, ERROR,
				"the specified IP ranges number(%u) exceeds the max value(%u)",
				range_num, MAX_USER_IP_RANGE_NUM);
		return -1;
	}

	if (ip_ranges == NULL) {
		ALOG(SERVER, ERROR, "the range number is %d but ip_ranges is NULL ",
				range_num);
		return -1;
	}

	for (i = 0; i < range_num; i++) {
		is_exist = 0;
		for (j = 0; j < user->range_num; j++) {
			if (fwd_user_cmp(&ip_ranges[i], &user->ip_ranges[j]) == 0) {
				is_exist = 1;
				break;
			}
		}

		if (is_exist) {
			continue;
		}

		if ((user->range_num + 1) > MAX_USER_IP_RANGE_NUM) {
			ALOG(SERVER, ERROR, "IP ranges number exceeds the max value(%u)",
					MAX_USER_IP_RANGE_NUM);
			return -1;
		}

		if (fwd_ip_user_tbl_add(user, 1, &ip_ranges[i]) != 0) {
			return -1;
		}
		user->ip_ranges[user->range_num++] = ip_ranges[i];
	}

	return 0;
}

int fwd_user_del_ip_ranges(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges) {
	uint8_t is_remove[MAX_USER_IP_RANGE_NUM];
	int i, j;

	if (user->range_num == 0) {
		ALOG(SERVER, WARN, "no ip ranges in user %u to delete", user->user_id);
		return 0;
	}

	if (range_num > MAX_USER_IP_RANGE_NUM) {
		ALOG(SERVER, ERROR,
				"the specified IP ranges number(%u) exceeds the max value(%u)",
				range_num, MAX_USER_IP_RANGE_NUM);
		return -1;
	}

	if (ip_ranges == NULL) {
		ALOG(SERVER, ERROR, "the range number is %d but ip_ranges is NULL ",
				range_num);
		return -1;
	}
	memset(is_remove, 0, sizeof(uint8_t) * user->range_num);

	for (i = 0; i < range_num; i++) {
		for (j = 0; j < user->range_num; j++) {
			if (fwd_user_cmp(&ip_ranges[i], &user->ip_ranges[j]) == 0) {
				/* ignore return value check here, delete ASAP */
				fwd_ip_user_tbl_del(user, 1, &ip_ranges[i]);
				is_remove[j] = 1;
				break;
			}
		}
	}

	for (i = 0, j = 0; j < user->range_num; j++) {
		if (is_remove[j]) {
			continue;
		}

		if (i != j) {
			user->ip_ranges[i] = user->ip_ranges[j];
		}
		i++;
	}
	user->range_num = i;

	return 0;
}

int fwd_user_ref_ip_ranges(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges) {
	uint8_t is_keep[user->range_num];
	ip_range_t diff_ip_ranges[MAX_USER_IP_RANGE_NUM];
	uint16_t diff_range_num = 0;
	uint8_t is_exist;
	int i, j;

	if (range_num > MAX_USER_IP_RANGE_NUM) {
		ALOG(SERVER, ERROR,
				"the specified IP ranges number(%u) exceeds the max value(%u)",
				range_num, MAX_USER_IP_RANGE_NUM);
		return -1;
	}

	if (ip_ranges == NULL) {
		ALOG(SERVER, ERROR, "the range number is %d but ip_ranges is NULL ",
				range_num);
		return -1;
	}
	memset(is_keep, 0, sizeof(uint8_t) * user->range_num);

	for (i = 0; i < range_num; i++) {
		is_exist = 0;

		for (j = 0; j < user->range_num; j++) {
			if (fwd_user_cmp(&ip_ranges[i], &user->ip_ranges[j]) == 0) {
				is_exist = 1;
				is_keep[j] = 1;
				break;
			}
		}

		if (!is_exist) {
			diff_ip_ranges[diff_range_num++] = ip_ranges[i];
		}
	}

	for (i = 0, j = 0; j < user->range_num; j++) {
		if (!is_keep[j]) {
			/* ignore return value check here, delete ASAP */
			fwd_ip_user_tbl_del(user, 1, &user->ip_ranges[j]);
			continue;
		}

		if (i != j) {
			user->ip_ranges[i] = user->ip_ranges[j];
		}
		i++;
	}
	user->range_num = i;

	if (fwd_ip_user_tbl_add(user, diff_range_num, diff_ip_ranges) != 0) {
		return -1;
	}
	rte_memcpy(&user->ip_ranges[user->range_num], diff_ip_ranges,
			sizeof(ip_range_t) * diff_range_num);
	user->range_num += diff_range_num;

	return 0;
}

static inline fwd_user_t *_fwd_user_alloc()
{
    void *data;

    if (rte_mempool_get(g_fwd_user_pool, &data) < 0) {
		ALOG(SERVER, ERROR,
				"rte_mempool_get failed, pool name = g_fwd_user_pool");
        return NULL;
    }
    memset(data, 0, g_fwd_user_pool->elt_size);

    return (fwd_user_t *)data;
}

fwd_user_t *fwd_user_new(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges, uint8_t status)
{
    fwd_user_t *user;

    if(range_num > MAX_USER_IP_RANGE_NUM) {
		ALOG(SERVER, ERROR,
				"the specified IP ranges number(%d) exceeds the max value(%d)",
				range_num, MAX_USER_IP_RANGE_NUM);
    	return NULL;
    }
    user = _fwd_user_alloc();

    if (user == NULL) {
        return NULL;
    }
    INIT_LIST_HEAD(&(user->list));
    user->user_id = user_id;

	if (range_num > 0) {
		if (ip_ranges == NULL) {
			ALOG(SERVER, ERROR, "the range number is %d but ip_ranges is NULL ",
					range_num);
			/* the fwd_ip_user_tbl setting has been rollback, so should keep the user range_num is 0 */
			fwd_user_free(user);
			return NULL;
		}

		rte_memcpy(user->ip_ranges, ip_ranges, sizeof(ip_range_t) * range_num);
		user->range_num = range_num;
	}

    return user;
}

void fwd_user_free(fwd_user_t *user) {
    if (user == NULL) {
        return;
    }

    rte_mempool_put(g_fwd_user_pool, (void *)user);
}

int fwd_user_init() {
	g_fwd_user_pool = rte_mempool_create("g_fwd_user_pool", g_fwd_user_max_num,
			sizeof(fwd_user_t), 32, 0, NULL, NULL,
			NULL, NULL, rte_lcore_to_socket_id(rte_lcore_id()),
			MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
	if (g_fwd_user_pool == NULL) {
		RTE_LOG(ERR, LDNS, "[%s]: Failed to alloc g_fwd_user_pool\n",
				__FUNCTION__);
		return -1;
	}
	RTE_LOG(INFO, LDNS, "[%s]: Finish to alloc g_fwd_user_pool\n",
			__FUNCTION__);

	return 0;
}

void dump_fwd_user(FILE *fp, fwd_user_t *user) {
	uint8_t *p;
	fwd_usr_snapshot_t snapshot;

	snapshot.user_id = user->user_id;
	snapshot.status = user->status;
	snapshot.range_num = user->range_num;
	p = (uint8_t*) &snapshot;
	print_byte(fp, sizeof(fwd_usr_snapshot_t), p);

	p = (uint8_t*) user->ip_ranges;
	print_byte(fp, user->range_num * sizeof(ip_range_t), p);
}

