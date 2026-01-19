/*
 * Copyright (C)
 * Filename: lock.c
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#include "stats.h"
#include "lock.h"

void read_trylock_bh(rwlock_t *lock)
{
    /*
    while (1) {
        local_bh_disable();

        if (read_trylock(lock)) {
            break;
        } else {
            local_bh_enable();
            DM_INC_ESTATS(dm_esmib, DM_LOCK_RETRY);
            ndelay(DELAY_TIME);
        }
    }
    */
    read_lock_bh(lock);
}

void write_trylock_bh(rwlock_t *lock)
{
    /*
    while (1) {
        local_bh_disable();

        if (write_trylock(lock)) {
            break;
        } else {
            local_bh_enable();
            DM_INC_ESTATS(dm_esmib, DM_LOCK_RETRY);
            ndelay(DELAY_TIME);
        }
    }
    */
    write_lock_bh(lock);
}
