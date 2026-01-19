#ifndef __OVERSEALIST_H_
#define __OVERSEALIST_H_
#include "rte_core.h"
#include "dns_pkt.h"
#include "storage.h"
#include<stdint.h>

#define LABEL_MAX 128
extern int init_oversealist();
extern void charge_oversealist_state();
extern int oversealist_judge(uint8_t *key,uint16_t size);
#endif
