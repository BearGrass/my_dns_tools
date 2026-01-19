#ifndef __MAIN_WHITELIST_H_
#define __MAIN_WHITELIST_H_
#include "rte_core.h"
#include "storage.h"
#include<stdint.h>
extern int g_whitelist_label_max;
extern int init_man_whitelist();
extern int is_man_whitelist(node *n);

extern int man_whitelist_judge(const uint8_t *key,uint16_t size);
extern void charge_man_whitelist_state();//only called at misc core
#endif
