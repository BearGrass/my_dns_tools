#ifndef __WHITELIST_H_
#define __WHITELIST_H_
#include "rte_core.h"
#include "storage.h"
#include<stdint.h>
extern int init_whitelist();
extern int is_whitelist(node *n);

extern int whitelist_judge(const uint8_t *key,uint16_t size);
extern void charge_whitelist_state();//only called at misc core
#endif
