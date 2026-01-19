#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_malloc.h>
#include "rcu.h"
#include "errcode.h"
#include "log.h"
#include "adns.h"
#include "adns_stats.h"

static struct list_head ready_event_list; /* TODO: a sorted tree would be better */
static unsigned first_lcore_id = -1;
static unsigned nb_online_cores = -1;
static uint64_t rcu_seq[RTE_MAX_LCORE];
rte_atomic16_t finish_counter;

inline int do_rcu_first_lcore()
{
    uint64_t cur_seq = rcu_seq[first_lcore_id];
    struct rcu_event * ready_event = NULL;

    if (rte_atomic16_read(&finish_counter) >= nb_online_cores) {
        rte_atomic16_set(&finish_counter, 1);
        rcu_seq[first_lcore_id]++;
        STATS_INC(rcu_cnt);

        while ( !list_empty(&ready_event_list) ) {
            ready_event = list_first_entry(&ready_event_list, struct rcu_event, list);
            if (cur_seq - ready_event->seq <= 1 ) { /* unsigned subtraction, avoid overflow */
                break;
            }
            else {
                list_del(&(ready_event->list));
                ready_event->func(ready_event->cb_input);
                rte_free(ready_event);
            }
        }
    }

    return 0;
}

inline int do_rcu_other_lcore(unsigned coreid)
{
    uint64_t cur_seq = rcu_seq[coreid];
     /* though the reading below may have contention with writing on first lcore,
      * first_seq just may be a older value, and it does not matter */
    uint64_t first_seq = rcu_seq[first_lcore_id];

    if (first_seq -  cur_seq > 0){
        rcu_seq[coreid]++;
        rte_atomic16_inc(&finish_counter);
    }
    else if (first_seq -  cur_seq < 0) {
        log_server_error(rte_lcore_id(), "[%s]: RCU critical error: "
            "core %d (seq=%d) overruns first core (seq=%d).\n",
             __FUNCTION__, coreid, cur_seq, first_seq);
    }

    return 0;
}

/*
 * call_rcu() only tries to enqueue the rcu event
 * CAUTIONS: if failed, caller is responsible to do the cleanning.
 */
int call_rcu(void (*cb_func_ptr)(void *), void * cb_func_input)
{
    struct rcu_event * new_event;

    if (cb_func_ptr ==  NULL) {
        return -1;
    }

    new_event = (struct rcu_event *)rte_zmalloc(NULL, sizeof(struct rcu_event), RTE_CACHE_LINE_SIZE);
    if (new_event == NULL) {
        return -2;
    }

    new_event->func = cb_func_ptr;
    new_event->cb_input = (void *)cb_func_input;
    new_event->seq = rcu_seq[rte_lcore_id()];

    list_add_tail(&(new_event->list), &ready_event_list);

    return 0;
}

int rcu_init(void)
{
    int i = 0;

    INIT_LIST_HEAD(&ready_event_list);

    RTE_LCORE_FOREACH(i){
        if(rte_lcore_is_enabled(i)) {
            if(first_lcore_id == -1){
                first_lcore_id = i;
                rcu_seq[i] = 1;
            }else{
                rcu_seq[i] = 0;
            }
        }
    }

    nb_online_cores = app.lcore_io_num + 1 + 1; // one for misc, one for admin

    rte_atomic16_set(&finish_counter, 1);

    return 0;
}
