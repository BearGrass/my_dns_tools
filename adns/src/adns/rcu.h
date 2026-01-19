#ifndef __RCU_H__
#define __RCU_H__
#include "list.h"

struct rcu_event {
    uint64_t         seq;
    void             (*func)(void * input);
    void             *cb_input;
    struct list_head list;
};

#ifdef __cplusplus
extern "C" {
#endif

extern int rcu_init(void);
extern int call_rcu(void (*cb_func_ptr)(void *), void * cb_func_input);
extern int do_rcu_first_lcore();
extern int do_rcu_other_lcore(unsigned coreid);

#ifdef __cplusplus
}
#endif

#endif//__RCU_H__

