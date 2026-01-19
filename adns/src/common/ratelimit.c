
#include <string.h>
#include <errno.h>

#include "rte_core.h"

#include "ratelimit.h"

static uint64_t HZ;

int ratelimit_setup(struct ratelim_cfg *ratelim, int average, int burst)
{
    if (average > burst) {
        rte_errno = EINVAL;
        return -1;
    }

    memset(ratelim, 0, sizeof(struct ratelim_cfg));
    ratelim->check_cycle = rte_get_hpet_cycles();
    ratelim->average = average;
    ratelim->burst = burst;
    ratelim->tokens = 0;
    rte_spinlock_init(&ratelim->lock);

    return 0;
}

/* return 1 on pass, otherwise on dropped */
int ratelimit_pass(struct ratelim_cfg *ratelim)
{
    uint64_t diff, now, check_cycle;
    int64_t toks;

    now = rte_get_hpet_cycles();
    rte_spinlock_lock(&ratelim->lock);
    check_cycle = ratelim->check_cycle;
    diff = now - check_cycle;

    if (diff) {
        diff = rte_get_hpet_cycles() - check_cycle;
        if (!diff) {
            goto xmit;
        }   

        toks = (diff * ratelim->average) / HZ; 
        ratelim->tokens += toks;
        if (ratelim->tokens > ratelim->burst)
            ratelim->tokens = ratelim->burst;
    }   

xmit:
    if (ratelim->tokens > 0) {
        ratelim->tokens--;
        ratelim->check_cycle = rte_get_hpet_cycles();
        rte_spinlock_unlock(&ratelim->lock);
        return 1;
    }   

    rte_spinlock_unlock(&ratelim->lock);
    return 0;
}

int ratelimit_init(void)
{
    HZ = rte_get_hpet_hz();

    return 0;
}


void ratelimit_cleanup(void)
{
    // do nothing
}

