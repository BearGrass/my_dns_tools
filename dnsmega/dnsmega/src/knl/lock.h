/*
 * Copyright (C)
 * Filename: timer.h
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#ifndef __LOCK_H__
#define __LOCK_H__

/* the time of enable soft bh
 * when we can not get the lock
 */
#define DELAY_TIME 1000

void read_trylock_bh(rwlock_t *lock);
void write_trylock_bh(rwlock_t *lock);

#endif                          /* __LOCK_H__ */
