
/*
 * Author:
 *    Andy chen <sanjie.cyg@taobao.com>
 */

#ifndef _RATELIMIT_H_
#define _RATELIMIT_H_

#include <stdint.h>

#include "rte_core.h"

struct ratelim_cfg {
    rte_spinlock_t lock;
    uint64_t check_cycle;
    uint32_t average;
    uint32_t burst;
    int64_t tokens;
};

int ratelimit_setup(struct ratelim_cfg *ratelim, int average, int burst);
int ratelimit_pass(struct ratelim_cfg *ratelim);

#endif

