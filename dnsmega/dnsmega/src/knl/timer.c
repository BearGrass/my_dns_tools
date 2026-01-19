/*
 * Copyright (C)
 * Filename: timer.c
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#include <linux/percpu.h>
#include <linux/workqueue.h>

#include "timer.h"
#include "cache.h"
#include "control.h"
#include "stats.h"
#include "lock.h"

struct dm_cache_timer g_cache_timer_list;
struct delayed_work dm_delayed_work;
struct delayed_work forward_ratelimit_worker;

void expire_timer_control(struct node_t *n, int flag) {
    write_trylock_bh(&g_cache_timer_list.l_expire_node_list);
    if (flag == TIMER_REINSERT || flag == TIMER_INIT) {
        if (!list_empty(&n->expire_timer_list)) {
            list_del_init(&n->expire_timer_list);
        }
    }
    if (flag == TIMER_REINSERT || flag == TIMER_INSERT) {
        list_add_tail(&n->expire_timer_list,
                &g_cache_timer_list.expire_node_list);
    }
    write_unlock_bh(&g_cache_timer_list.l_expire_node_list);
}

void forward_timer_control(struct node_t *n, int flag) {
    write_trylock_bh(&g_cache_timer_list.l_forward_node_list);
    if (flag == TIMER_REINSERT || flag == TIMER_INIT) {
        if (!list_empty(&n->forward_timer_list)) {
            DM_DEC_ESTATS(dm_esmib, DM_CACHE_WITHOUT_ANSWER_NUM);
            list_del_init(&n->forward_timer_list);
        }
    }
    if (flag == TIMER_REINSERT || flag == TIMER_INSERT) {
        DM_INC_ESTATS(dm_esmib, DM_CACHE_WITHOUT_ANSWER_NUM);
        list_add_tail(&n->forward_timer_list,
                &g_cache_timer_list.forward_node_list);
    }
    write_unlock_bh(&g_cache_timer_list.l_forward_node_list);
}

void cache_expired(struct work_struct *work)
{
    struct node_t *n, *n_tmp;
    int bulk_num = 0, i;

    /* forward_node_list includes all the nodes don't have cache
     * expire_node_list includes all the nodes except those in forward_node_list. */

    const int local_clean_bulk_num = sysctl_dm_cache_clean_bulk_num;
    struct node_t **clean_caches = kmalloc(local_clean_bulk_num * sizeof(struct node_t *), GFP_ATOMIC);
    if (clean_caches == NULL) {
        schedule_delayed_work(&dm_delayed_work, sysctl_dm_cache_clean_interval_ms / 1000.0 * HZ);
        return;
    }
    /* clean forward_node_list */
    write_trylock_bh(&g_cache_timer_list.l_forward_node_list);
    list_for_each_entry_safe(n, n_tmp, &g_cache_timer_list.forward_node_list,
                             forward_timer_list) {
        read_trylock_bh(&n->l);
        if (time_is_after_jiffies(n->cached_jiffies + sysctl_dm_forward_timeout_sec * HZ)) {
            read_unlock_bh(&n->l);
            break;
        }
        read_unlock_bh(&n->l);

        DM_INC_ESTATS(dm_esmib, DM_FWD_REAL_TIMEOUT);
        clean_caches[bulk_num ++] = n;

        /* don't clean too many nodes in one time */
        if (bulk_num >= sysctl_dm_cache_clean_bulk_num) {
            break;
        }
    }
    write_unlock_bh(&g_cache_timer_list.l_forward_node_list);
    for (i = 0; i < bulk_num; i++) {
        put_node(clean_caches[i]);
        clean_caches[i] = NULL;
    }

    /* clean expire_node_list */
    bulk_num = 0;
    write_trylock_bh(&g_cache_timer_list.l_expire_node_list);
    list_for_each_entry_safe(n, n_tmp, &g_cache_timer_list.expire_node_list,
                             expire_timer_list) {
        read_trylock_bh(&n->l);
        if (time_is_after_jiffies(n->cached_jiffies + sysctl_dm_expired_time * HZ)) {
            read_unlock_bh(&n->l);
            break;
        }
        read_unlock_bh(&n->l);

        DM_INC_ESTATS(dm_esmib, DM_CACHE_EXPIRED);
        DM_DEC_ESTATS(dm_esmib, DM_CACHE_WITH_ANSWER_NUM);
        clean_caches[bulk_num++] = n;

        if (bulk_num >= sysctl_dm_cache_clean_bulk_num) {
            break;
        }
    }
    write_unlock_bh(&g_cache_timer_list.l_expire_node_list);
    for (i = 0; i < bulk_num; i++) {
        put_node(clean_caches[i]);
        clean_caches[i] = NULL;
    }
    kfree(clean_caches);
    clean_caches = NULL;

    schedule_delayed_work(&dm_delayed_work, sysctl_dm_cache_clean_interval_ms / 1000.0 * HZ);
}

void forward_queries_clear(struct work_struct *work) {
    dm_estats_clear(dm_esmib, DM_FWD_QUERIES);
    schedule_delayed_work(&forward_ratelimit_worker, sysctl_dm_forward_ratelimit_sec * HZ);
}

int dm_timer_init(void)
{
    /* init timer for forward request & cache expired */
    INIT_LIST_HEAD(&g_cache_timer_list.forward_node_list);
    INIT_LIST_HEAD(&g_cache_timer_list.expire_node_list);

    INIT_DELAYED_WORK(&dm_delayed_work, cache_expired);
    schedule_delayed_work(&dm_delayed_work, 1000);

    INIT_DELAYED_WORK(&forward_ratelimit_worker, forward_queries_clear);
    schedule_delayed_work(&forward_ratelimit_worker, 1000);

    /* init lock */
    rwlock_init(&g_cache_timer_list.l_expire_node_list);
    rwlock_init(&g_cache_timer_list.l_forward_node_list);

    pr_info("DNS Mega timer initialization successful\n");
    return 0;
}

void dm_timer_exit(void)
{
    cancel_delayed_work_sync(&dm_delayed_work);
    cancel_delayed_work_sync(&forward_ratelimit_worker);
    pr_info("DNS Mega timer exit successful\n");
}
