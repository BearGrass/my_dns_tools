#include <linux/ctype.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/spinlock_types.h>

#include "util.h"
#include "pvt_tnl_db.h"
#include "errcode.h"


static struct am_tnl_info g_tnl_info_list[2][MAX_VIEW_ID + 1];
static int g_tnl_list_index; // 0 or 1
static int g_tnl_list_len;
struct pvt_tnl_db g_tnl_db;
spinlock_t g_tnl_db_lock;

int as_pvt_tnl_init(void) {
    /* create tunnel table */
    memset(&g_tnl_db, 0, sizeof(struct pvt_tnl_db));
    spin_lock_init(&g_tnl_db_lock);

    return AS_SUCCESS;
}

static void __tnl_info_list_add(uint32_t tnl_id, uint16_t view_id) {
    int new_index, new_len, i, done;

    //pr_info("__tnl_info_list_add: tnl_id %d, view_id %d\n", tnl_id, view_id);
    new_len = 0;
    done = 0;
    new_index = g_tnl_list_index ^ 1;

    for (i = 0; i < g_tnl_list_len; i++, new_len++) {
        if (done == 0 && g_tnl_info_list[g_tnl_list_index][i].tnl_id > tnl_id) {
            g_tnl_info_list[new_index][new_len].tnl_id = tnl_id;
            g_tnl_info_list[new_index][new_len].view_id = view_id;
            new_len++;
            done = 1;
        }
        g_tnl_info_list[new_index][new_len].tnl_id =
                g_tnl_info_list[g_tnl_list_index][i].tnl_id;
        g_tnl_info_list[new_index][new_len].view_id =
                g_tnl_info_list[g_tnl_list_index][i].view_id;
    }

    if (done == 0) {
        g_tnl_info_list[new_index][new_len].tnl_id = tnl_id;
        g_tnl_info_list[new_index][new_len].view_id = view_id;
        new_len++;
        done = 1;
    }
    g_tnl_list_index = new_index;
    g_tnl_list_len = new_len;
}

static void __tnl_info_list_set(uint32_t tnl_id, uint16_t view_id) {
    int i;

    for (i = 0; i < g_tnl_list_len; i++) {
        if (g_tnl_info_list[g_tnl_list_index][i].tnl_id == tnl_id) {
            g_tnl_info_list[g_tnl_list_index][i].view_id = view_id;
            break;
        }
    }
}

static void __tnl_info_list_del(uint32_t tnl_id) {
    int new_index, new_len, i;

    new_len = 0;
    new_index = g_tnl_list_index ^ 1;

    for (i = 0; i < g_tnl_list_len; i++) {
        if (g_tnl_info_list[g_tnl_list_index][i].tnl_id == tnl_id) {
            continue;
        }
        g_tnl_info_list[new_index][new_len].tnl_id =
                g_tnl_info_list[g_tnl_list_index][i].tnl_id;
        g_tnl_info_list[new_index][new_len].view_id =
                g_tnl_info_list[g_tnl_list_index][i].view_id;
        new_len++;
    }
    g_tnl_list_len = new_len;
    g_tnl_list_index = new_index;
}

int as_pvt_tnl_del(struct pvt_tnl_db *tnl_db, uint32_t tnl_id) {
    uint16_t view_id;

    if (tnl_db == NULL || tnl_id > MAX_TNL_ID) {
        // LOG
        return ASMEGA_KNL_TNL_DEL_ERROR;
    }

    view_id = tnl_db->tnl_tbl[tnl_id];
    if (view_id != 0) {
        if (tnl_db->tnl_count > 0) {
            tnl_db->tnl_count--;
        }
        spin_lock_bh(&g_tnl_db_lock);
        tnl_db->fwd_tbl[view_id] = 0;
        tnl_db->tnl_tbl[tnl_id] = 0;
        __tnl_info_list_del(tnl_id);
        spin_unlock_bh(&g_tnl_db_lock);
    }
    return AS_SUCCESS;
}

int as_pvt_tnl_add(struct pvt_tnl_db *tnl_db, uint32_t tnl_id, uint16_t view_id) {
    uint16_t old_view_id;

    //pr_info("as_pvt_tnl_add: tnl_db %p, tnl_id %d, view_id %d\n", tnl_db, tnl_id, view_id);
    if (tnl_db == NULL || tnl_id > MAX_TNL_ID || view_id > MAX_VIEW_ID || view_id < MIN_VIEW_ID) {
        // LOG
        return ASMEGA_KNL_TNL_ADD_ERROR;
    }

    if (tnl_db->fwd_tbl[view_id] != 0 && tnl_db->fwd_tbl[view_id] != tnl_id) {
        // The view id has been bind to other tunnel
        return ASMEGA_KNL_TNL_ADD_ERROR;
    }

    spin_lock_bh(&g_tnl_db_lock);
    old_view_id = tnl_db->tnl_tbl[tnl_id];
    if (old_view_id == view_id) {
        spin_unlock_bh(&g_tnl_db_lock);
        return AS_SUCCESS;
    }
    tnl_db->tnl_tbl[tnl_id] = view_id;
    tnl_db->fwd_tbl[view_id] = tnl_id;

    if (old_view_id != 0) {
        tnl_db->fwd_tbl[old_view_id] = 0;
        __tnl_info_list_set(tnl_id, view_id);
    } else {
        __tnl_info_list_add(tnl_id, view_id);
        tnl_db->tnl_count++;
    }
    spin_unlock_bh(&g_tnl_db_lock);
    return AS_SUCCESS;
}

int as_pvt_tnl_add_batch(struct pvt_tnl_db *tnl_db, struct am_tnl_info *list, uint32_t list_len) {
    int i, ret;
    for (i = 0; i < list_len; i ++) {
        ret = as_pvt_tnl_add(tnl_db, list[i].tnl_id, list[i].view_id);
        if (ret != AS_SUCCESS) {
            return AS_ERROR;
        }
    }
    return AS_SUCCESS;
}

int as_pvt_tnl_del_batch(struct pvt_tnl_db *tnl_db, struct am_tnl_info *list, uint32_t list_len) {
    int i, ret;
    for (i = 0; i < list_len; i ++) {
        ret = as_pvt_tnl_del(tnl_db, list[i].tnl_id);
        if (ret != AS_SUCCESS) {
            return AS_ERROR;
        }
    }
    return AS_SUCCESS;
}

int as_pvt_tnl_clean(struct pvt_tnl_db *tnl_db) {
    spin_lock_bh(&g_tnl_db_lock);
    g_tnl_list_index = 0;
    g_tnl_list_len = 0;
    memset(tnl_db, 0, sizeof(struct pvt_tnl_db));
    memset(g_tnl_info_list, 0, sizeof(g_tnl_info_list));
    spin_unlock_bh(&g_tnl_db_lock);

    return AS_SUCCESS;
}

int __as_pvt_tnl_set_all(struct pvt_tnl_db *tnl_db, uint32_t new_index, uint32_t list_len) {
    int i, pos;
    uint32_t now_max_tnl_id, tnl_id, tmp_tnl_id;
    uint16_t view_id, tmp_view_id;

    pos = 0;
    now_max_tnl_id = 0;

    for (i = 0; i < list_len; i++) {
        tnl_id = g_tnl_info_list[new_index][i].tnl_id;
        view_id = g_tnl_info_list[new_index][i].view_id;

        if (tnl_id > MAX_TNL_ID || view_id > MAX_VIEW_ID || view_id < MIN_VIEW_ID) {
            // LOG
            return ASMEGA_KNL_TNL_SET_ALL_ERROR;
        }

        if (unlikely(tnl_id <= now_max_tnl_id && i > 0)) {
            //LOG
            return ASMEGA_KNL_TNL_SET_ALL_NOT_SORT_ERROR;
        } else {
            now_max_tnl_id = tnl_id;
        }

        while (pos < g_tnl_list_len
                && g_tnl_info_list[g_tnl_list_index][pos].tnl_id < tnl_id) {
            tmp_tnl_id = g_tnl_info_list[g_tnl_list_index][pos].tnl_id;
            tmp_view_id = tnl_db->tnl_tbl[tnl_id];
            tnl_db->fwd_tbl[tmp_view_id] = 0;
            tnl_db->tnl_tbl[tmp_tnl_id] = 0;
            pos++;
        }

        if ((pos < g_tnl_list_len)
                && (g_tnl_info_list[g_tnl_list_index][pos].tnl_id == tnl_id)) {
            tmp_view_id = tnl_db->tnl_tbl[tnl_id];
            tnl_db->fwd_tbl[tmp_view_id] = 0;
            pos++;
        }

        tnl_db->fwd_tbl[view_id] = tnl_id;
        tnl_db->tnl_tbl[tnl_id] = view_id;
    }

    while (pos < g_tnl_list_len) {
        tmp_tnl_id = g_tnl_info_list[g_tnl_list_index][pos].tnl_id;
        tmp_view_id = tnl_db->tnl_tbl[tnl_id];
        tnl_db->fwd_tbl[tmp_view_id] = 0;
        tnl_db->tnl_tbl[tmp_tnl_id] = 0;
        pos++;
    }

    g_tnl_list_index = new_index;
    g_tnl_list_len = list_len;
    tnl_db->tnl_count = list_len;

    return AS_SUCCESS;
}

/*
 * tnl_list should be sorted by tnl_id from small to large
 * */
int as_pvt_tnl_set_all(struct pvt_tnl_db *tnl_db, struct am_tnl_info *list,
        uint32_t list_len) {
    int ret;
    uint32_t new_index;

    if (tnl_db == NULL || list == NULL || list_len > MAX_VIEW_ID_NUM ) {
        return ASMEGA_KNL_TNL_SET_ERROR;
    }


    spin_lock_bh(&g_tnl_db_lock);
    new_index = g_tnl_list_index ^ 1;
    memcpy(g_tnl_info_list[new_index], list,
            sizeof(struct am_tnl_info) * list_len);
    ret = __as_pvt_tnl_set_all(tnl_db, new_index, list_len);
    spin_unlock_bh(&g_tnl_db_lock);
    return ret;

}

/*
 * tnl_list should be sorted by tnl_id from small to large
 * */
int as_pvt_tnl_set_all_from_usr(struct pvt_tnl_db *tnl_db, void __user * user, uint32_t len) {
    int ret;
    uint32_t new_index;
    uint32_t tnl_num;

    if (tnl_db == NULL || user == NULL) {
        return ASMEGA_KNL_TNL_SET_ERROR;
    }

    if ((len % sizeof(am_tnl_info_t)) != 0) {
        return ASMEGA_KNL_SET_SOCKOPT_TNL_NUM_ERROR;
    }
    tnl_num = len / sizeof(am_tnl_info_t);

    if (tnl_num > MAX_VIEW_ID_NUM) {
        return ASMEGA_KNL_SET_SOCKOPT_TNL_NUM_ERROR;
    }

    spin_lock_bh(&g_tnl_db_lock);
    new_index = g_tnl_list_index ^ 1;
    if(copy_from_user(g_tnl_info_list[new_index], user, len)) {
        spin_unlock_bh(&g_tnl_db_lock);
        return ASMEGA_KNL_SET_SOCKOPT_COPY_ERROR;
    }
    ret = __as_pvt_tnl_set_all(tnl_db, new_index, tnl_num);
    spin_unlock_bh(&g_tnl_db_lock);
    return ret;
}

int as_pvt_tnl_get_all_to_usr(struct pvt_tnl_db *tnl_db, void __user * user, int *len) {
    uint32_t real_len;

    if (tnl_db == NULL || user == NULL) {
        return ASMEGA_KNL_TNL_SET_ERROR;
    }
    real_len = (sizeof(am_tnl_info_t) * g_tnl_list_len);

    if (*len < real_len) {
        return ASMEGA_KNL_GET_SOCKOPT_BUF_LEN_ERROR;
    }

    if(copy_to_user(user, g_tnl_info_list[g_tnl_list_index], real_len)) {
        return ASMEGA_KNL_GET_SOCKOPT_COPY_ERROR;
    }
    *len = real_len;

    return AS_SUCCESS;
}
