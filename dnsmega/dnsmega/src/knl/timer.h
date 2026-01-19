/*
 * Copyright (C)
 * Filename: timer.h
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#ifndef __TIMER_H__
#define __TIMER_H__

#include "cache.h"

#define TIMER_INIT 1
#define TIMER_INSERT 2
#define TIMER_REINSERT 3

struct dm_cache_timer {
    struct list_head expire_node_list;
    struct list_head forward_node_list;
    rwlock_t l_expire_node_list;
    rwlock_t l_forward_node_list;
};

int dm_timer_init(void);
void dm_timer_exit(void);

void forward_timer_control(struct node_t *n, int flag);
void expire_timer_control(struct node_t *n, int flag);

#endif                          /* __TIMER_H__ */
