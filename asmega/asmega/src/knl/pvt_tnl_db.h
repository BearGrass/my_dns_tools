#ifndef _PVT_TNL_DB_H_
#define _PVT_TNL_DB_H_

#include "lib_asmega.h"

struct pvt_tnl_db {
    /* using tnlID hash value for hash index */
    uint16_t tnl_tbl[MAX_TNL_NUM];
    uint32_t fwd_tbl[MAX_VIEW_ID + 1];
    uint32_t tnl_count;
};

extern struct pvt_tnl_db g_tnl_db;

int as_pvt_tnl_init(void);
int as_pvt_tnl_add(struct pvt_tnl_db *tnl_db, uint32_t tnl_id, uint16_t view_id);
int as_pvt_tnl_del(struct pvt_tnl_db *tnl_db, uint32_t tnl_id);
int as_pvt_tnl_set_all(struct pvt_tnl_db *tnl_db, struct am_tnl_info *list, uint32_t list_len);
/* add_batch and del_batch usually used for OPS, so sorted tnl_list is not necessary*/
int as_pvt_tnl_add_batch(struct pvt_tnl_db *tnl_db, struct am_tnl_info *list, uint32_t list_len);
int as_pvt_tnl_del_batch(struct pvt_tnl_db *tnl_db, struct am_tnl_info *list, uint32_t list_len);
int as_pvt_tnl_clean(struct pvt_tnl_db *tnl_db);
int as_pvt_tnl_set_all_from_usr(struct pvt_tnl_db *tnl_db, void __user * user, uint32_t len);
int as_pvt_tnl_get_all_to_usr(struct pvt_tnl_db *tnl_db, void __user * user, int *len);

static inline uint16_t
as_pvt_tnl_get_view_id(struct pvt_tnl_db *tnl_db, uint32_t tnl_id) {
    if (tnl_db == NULL || tnl_id > MAX_TNL_ID) {
        return 0;
    }
    return tnl_db->tnl_tbl[tnl_id];
}

static inline uint32_t
as_pvt_tnl_get_tnl_id(struct pvt_tnl_db *tnl_db, uint16_t view_id) {
    if (tnl_db == NULL || view_id > MAX_VIEW_ID) {
        return 0;
    }
    return tnl_db->fwd_tbl[view_id];
}

#endif
