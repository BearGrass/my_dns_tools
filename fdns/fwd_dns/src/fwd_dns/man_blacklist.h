#ifndef __MAIN_BLACKLIST_H_
#define __MAIN_BLACKLIST_H_
#include "rte_core.h"
#include "storage.h"
#include<stdint.h>
extern int g_blacklist_label_max;
extern int init_man_blacklist();
extern int is_man_blacklist(node *n);

extern int man_blacklist_judge(const uint8_t *key,uint16_t size);
extern void charge_man_blacklist_state();//only called at misc core
#endif
