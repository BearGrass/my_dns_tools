#ifndef _FWD_USER_DB_H_
#define _FWD_USER_DB_H_

#include "fwd_user.h"

#define FWD_USER_DB_HASH_SIZE (1<<19)

struct fwd_user_db_hash_node {
    struct list_head list;
    uint32_t size;
};

typedef struct fwd_user_db {
    struct fwd_user_db_hash_node user_nodes[FWD_USER_DB_HASH_SIZE];
    uint32_t user_count;
} fwd_user_db_t;
fwd_user_db_t *g_fwd_user_db;
int g_user_queue_offset;

int fwd_user_db_add_user(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges, uint8_t status);
int fwd_user_db_del_user(uint32_t user_id);
int fwd_user_db_ref_user(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges, uint8_t status);

int fwd_user_db_chg_status(uint32_t user_id, uint8_t status);

int fwd_user_db_add_ip_ranges(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges);
int fwd_user_db_del_ip_ranges(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges);
int fwd_user_db_ref_ip_ranges(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges);
fwd_user_t** fwd_user_db_list(fwd_user_db_t *fwd_user_db);

static inline void user_queue_offset_set(uint32_t offset) {
        g_user_queue_offset = offset;
}

static inline uint32_t user_queue_offset_get() {
        return g_user_queue_offset;
}

int fwd_user_db_init();
void fwd_user_db_clear();

int fwd_user_db_export_snapshot(FILE *fp);
int fwd_user_db_import_snapshot(FILE *fp, uint32_t payload_size);

#endif /* _FWD_USER_DB_H_ */
