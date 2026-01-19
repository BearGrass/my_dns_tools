#include "common.h"
#include "log.h"
#include "ldns.h"
#include "list.h"
#include "fwd_user.h"
#include "fwd_user_db.h"
#include "fwd_ip_user_tbl.h"
#include "ip_filter.h"
#include "snapshot.h"


static inline fwd_user_t* _fwd_user_db_lookup(fwd_user_db_t *user_db,
		uint32_t user_id, struct fwd_user_db_hash_node **h_node) {
	uint32_t hash;
	fwd_user_t *f_user;
	struct list_head *h_list;

	hash = rte_jhash_1word(user_id, 0) % FWD_USER_DB_HASH_SIZE;
	*h_node = &user_db->user_nodes[hash];
	h_list = &((*h_node)->list);

	list_for_each_entry(f_user, h_list, list)
	{
		if (f_user->user_id == user_id) {
			return f_user;
		}
	}

	return NULL;
}

fwd_user_t** fwd_user_db_list(fwd_user_db_t *fwd_user_db) {
	int i, z_count = 0;
	fwd_user_t **z_list;
	fwd_user_t *f_user;
	const struct list_head *h_list;
	const struct fwd_user_db_hash_node *h_node;

	if (unlikely(fwd_user_db == NULL || fwd_user_db->user_count == 0)) {
		return NULL;
	}

	z_list = malloc(sizeof(fwd_user_t*) * fwd_user_db->user_count);
	if (z_list == NULL) {
		return NULL;
	}

	for (i = 0; i < FWD_USER_DB_HASH_SIZE; i++) {
		h_node = &fwd_user_db->user_nodes[i];
		h_list = &(h_node->list);

		list_for_each_entry(f_user, h_list, list)
		{
			z_list[z_count++] = f_user;
		}

		if (z_count > fwd_user_db->user_count) {
			ALOG(SERVER, ERROR,
					"[%s]: The actual fwd user count is bigger than fwd_user_db->user_count %d\n",
					__FUNCTION__, fwd_user_db->user_count);
			break;
		}
	}

	return z_list;
}

static inline void _fwd_user_db_add(fwd_user_t *f_user,
		struct fwd_user_db_hash_node *h_node) {
	struct list_head *h_list;

	h_list = &(h_node->list);
	list_add(&(f_user->list), h_list);
	h_node->size++;
	g_fwd_user_db->user_count++;
}

static inline void _fwd_user_db_del(fwd_user_t *f_user,
		struct fwd_user_db_hash_node *h_node) {
	list_del(&f_user->list);
	fwd_user_free(f_user);

	if (unlikely(h_node->size == 0)) {
		ALOG(SERVER, WARN, "LCORE %d : FWD IP User hash node size is 0",
				rte_lcore_id());
	} else {
		h_node->size--;
	}

	if (unlikely(g_fwd_user_db->user_count == 0)) {
		ALOG(SERVER, WARN, "LCORE %d : FWD IP User TBL IP count is 0",
				rte_lcore_id());
	} else {
		g_fwd_user_db->user_count--;
	}
}


int fwd_user_db_add_user(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges, uint8_t status) {
	fwd_user_t *f_user;
	struct fwd_user_db_hash_node *h_node;

	f_user = _fwd_user_db_lookup(g_fwd_user_db, user_id, &h_node);
	if (f_user != NULL) {
		ALOG(SERVER, WARN, "[%s] user_id %u is existing\n", __FUNCTION__,
				user_id);
		return 0;
	}

	f_user = fwd_user_new(user_id, range_num, ip_ranges, status);
	if (f_user == NULL) {
		return -1;
	}
	_fwd_user_db_add(f_user, h_node);

	if (fwd_ip_user_tbl_add(f_user, range_num, ip_ranges) != 0) {
		fwd_user_free(f_user);
		return -1;
	}

	return 0;
}

int fwd_user_db_del_user(uint32_t user_id) {
	fwd_user_t *f_user;
	struct fwd_user_db_hash_node *h_node;

	f_user = _fwd_user_db_lookup(g_fwd_user_db, user_id, &h_node);
	if (f_user == NULL) {
		ALOG(SERVER, WARN, "[%s] user_id %u is not existing\n", __FUNCTION__,
				user_id);
		return 0;
	}

	if (fwd_ip_user_tbl_del(f_user, f_user->range_num, f_user->ip_ranges)
			!= 0) {
		return -1;
	}
	_fwd_user_db_del(f_user, h_node);

	return 0;
}

int fwd_user_db_ref_user(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges, uint8_t status) {
	fwd_user_t *f_user;
	struct fwd_user_db_hash_node *h_node;

	f_user = _fwd_user_db_lookup(g_fwd_user_db, user_id, &h_node);
	if (f_user == NULL) {
		if (fwd_user_db_add_user(user_id, range_num, ip_ranges, status) != 0) {
			return -1;
		}
		return 0;
	}

	if (fwd_user_chg_status(f_user, status) != 0) {
		return -1;
	}

	if (fwd_user_ref_ip_ranges(f_user, range_num, ip_ranges) != 0) {
		return -1;
	}

	return 0;
}

int fwd_user_db_chg_status(uint32_t user_id, uint8_t status) {
	fwd_user_t *f_user;
	struct fwd_user_db_hash_node *h_node;

	f_user = _fwd_user_db_lookup(g_fwd_user_db, user_id, &h_node);
	if (f_user == NULL) {
		ALOG(SERVER, ERROR, "[%s] user_id %u is not existing\n", __FUNCTION__,
				user_id);
		return -1;
	}

	if (fwd_user_chg_status(f_user, status) != 0) {
		return -1;
	}

	return 0;
}

int fwd_user_db_add_ip_ranges(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges) {
	fwd_user_t *f_user;
	struct fwd_user_db_hash_node *h_node;

	f_user = _fwd_user_db_lookup(g_fwd_user_db, user_id, &h_node);
	if (f_user == NULL) {
		ALOG(SERVER, ERROR, "[%s] user_id %u is not existing\n", __FUNCTION__,
				user_id);
		return -1;
	}

	if (fwd_user_add_ip_ranges(f_user, range_num, ip_ranges) != 0) {
		return -1;
	}

	return 0;
}

int fwd_user_db_del_ip_ranges(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges) {
	fwd_user_t *f_user;
	struct fwd_user_db_hash_node *h_node;

	f_user = _fwd_user_db_lookup(g_fwd_user_db, user_id, &h_node);
	if (f_user == NULL) {
		ALOG(SERVER, ERROR, "[%s] user_id %u is not existing\n", __FUNCTION__,
				user_id);
		return -1;
	}

	if (fwd_user_del_ip_ranges(f_user, range_num, ip_ranges) != 0) {
		return -1;
	}

	return 0;
}

int fwd_user_db_ref_ip_ranges(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges) {
	fwd_user_t *f_user;
	struct fwd_user_db_hash_node *h_node;

	f_user = _fwd_user_db_lookup(g_fwd_user_db, user_id, &h_node);
	if (f_user == NULL) {
		ALOG(SERVER, ERROR, "[%s] user_id %u is not existing\n", __FUNCTION__,
				user_id);
		return -1;
	}

	if (fwd_user_ref_ip_ranges(f_user, range_num, ip_ranges) != 0) {
		return -1;
	}

	return 0;
}

/* Init Function */
static inline fwd_user_db_t *
fwd_user_db_new(const char *name)
{
	fwd_user_db_t *db;
    int i;

	db = rte_malloc_socket(name, sizeof(fwd_user_db_t), 0,
			rte_lcore_to_socket_id(rte_lcore_id()));
    if (db == NULL) {
    	RTE_LOG(ERR, LDNS, "[%s]: Failed to alloc g_fwd_user_db\n",
    				__FUNCTION__);
        return NULL;
    }

    for (i = 0; i < FWD_USER_DB_HASH_SIZE; i++) {
        INIT_LIST_HEAD(&(db->user_nodes[i].list));
        db->user_nodes[i].size = 0;
    }
    db->user_count = 0;

    return db;
}


int fwd_user_db_init() {
    fwd_user_db_t *db = NULL;
    db = fwd_user_db_new("g_fwd_user_db");
    if (db == NULL) {
        return -1;
    }
    g_fwd_user_db = db;
    RTE_LOG(INFO, LDNS, "[%s]: Finish to new g_fwd_user_db\n", __FUNCTION__);

	if (fwd_ip_user_tbl_init() != 0) {
		return -1;
	}

    if (fwd_user_init() != 0) {
        return -1;
    }

    return 0;
}

static void _fwd_user_db_del_user_node(fwd_user_t *usr,
		struct fwd_user_db_hash_node *h_node) {
	fwd_ip_user_tbl_del(usr, usr->range_num, usr->ip_ranges);
	list_del(&usr->list);
	fwd_user_free(usr);

	if (unlikely(h_node->size == 0)) {
		ALOG(SERVER, WARN, "LCORE %d : FWD User hash node size is 0",
				rte_lcore_id());
	} else {
		h_node->size--;
	}

	if (unlikely(g_fwd_user_db->user_count == 0)) {
		ALOG(SERVER, WARN, "LCORE %d : FWD User db user count is 0",
				rte_lcore_id());
	} else {
		g_fwd_user_db->user_count--;
	}
}

void fwd_user_db_clear() {
    int i;
	fwd_user_t *fwd_usr, *fwd_usr_next;

	if (g_fwd_user_db == NULL) {
		ALOG(SERVER, WARN, "LCORE %d : FWD User DB does not existed",
				rte_lcore_id());
		return;
	}

	if (g_fwd_user_db->user_count > 0) {
		for (i = 0; i < FWD_USER_DB_HASH_SIZE; i++) {
			list_for_each_entry_safe(fwd_usr, fwd_usr_next,
					&g_fwd_user_db->user_nodes[i].list, list)
			{
				_fwd_user_db_del_user_node(fwd_usr,
						&g_fwd_user_db->user_nodes[i]);
			}
			g_fwd_user_db->user_nodes[i].size = 0;
		}

		g_fwd_user_db->user_count = 0;
	}
}

int fwd_user_db_export_snapshot(FILE *fp) {
    uint32_t node_num = g_fwd_user_db->user_count;
    uint32_t offset;
    int i;
    fwd_user_t **list;
    uint8_t *p;
	snapshot_hdr_t hdr;

	hdr.snapshot_type = FWD_USER_SNAPSHOT;
	hdr.payload_size = sizeof(node_num) + sizeof(offset);
    list = fwd_user_db_list(g_fwd_user_db);
	for (i = 0; i < node_num; i++) {
		hdr.payload_size += sizeof(fwd_usr_snapshot_t);
		hdr.payload_size += sizeof(ip_range_t) * list[i]->range_num;
	}

    p = (uint8_t*)&hdr;
    print_byte(fp, sizeof(snapshot_hdr_t), p);

    p = (uint8_t*)&node_num;
    print_byte(fp, sizeof(node_num), p);

    offset = user_queue_offset_get();
    p = (uint8_t*)&offset;
    print_byte(fp, sizeof(offset), p);

    for (i = 0; i < node_num; i ++) {
    	dump_fwd_user(fp, list[i]);
    }
    return 0;
}

static int load_fwd_user_node(FILE *fp, uint32_t *read_size) {
	int num;
	int ret;
	fwd_usr_snapshot_t snapshot;

	num = fread(&snapshot, sizeof(fwd_usr_snapshot_t), 1, fp);
	if (num != 1) {
		ALOG(SERVER, ERROR, "Reload user snapshot error %u(%u)", num,
				sizeof(fwd_usr_snapshot_t));
		return -1;
	}
	*read_size += sizeof(fwd_usr_snapshot_t);

	if (snapshot.range_num > MAX_USER_IP_RANGE_NUM) {
		ALOG(SERVER, ERROR,
				"the specified IP ranges number(%d) exceeds the max value(%d)",
				snapshot.range_num, MAX_USER_IP_RANGE_NUM);
		return -1;
	}
	ip_range_t ip_ranges[snapshot.range_num];

	num = fread((void*) ip_ranges, sizeof(ip_range_t), snapshot.range_num, fp);
	if (num != snapshot.range_num) {
		ALOG(SERVER, ERROR, "Reload ip range buffer error %u(%u)", num,
				sizeof(ip_ranges));
		return -1;
	}
	*read_size += sizeof(ip_range_t) * snapshot.range_num;
	ret = fwd_user_db_add_user(snapshot.user_id, snapshot.range_num, ip_ranges,
			snapshot.status);

	return ret;

}

int fwd_user_db_import_snapshot(FILE *fp, uint32_t payload_size) {
    uint32_t node_num;
    uint32_t offset;
    int ret, num;
    uint32_t i;
    uint32_t read_size = 0;

    num = fread(&node_num, sizeof(node_num), 1, fp);
    if (num != 1) {
        return 0;
    }
    read_size += sizeof(node_num);
    if (node_num <= 0) {
        return 0;
    }

    num = fread(&offset, sizeof(offset), 1, fp);
    if (num != 1) {
        ALOG(SERVER, ERROR, "Reload queue offset error");
        return -1;
    }
    read_size += sizeof(offset);
    fwd_user_db_clear();

	for (i = 0; i < node_num; i++) {
		ret = load_fwd_user_node(fp, &read_size);
		if (ret < 0) {
			ALOG(SERVER, ERROR, "Load fwd user error");
			return -1;
		}
	}

	if (read_size != payload_size) {
		ALOG(SERVER, ERROR,
				"Actual read size (%u) is different with payload size(%u)!",
				read_size, payload_size);
		return -1;
	}
    user_queue_offset_set(offset);

    return 0;
}
