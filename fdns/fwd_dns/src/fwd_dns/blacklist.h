#ifndef __BLACKLIST_H_
#define __BLACKLIST_H_
#include "dns_pkt.h"
#include "storage.h"
#include<stdint.h>

#define LABEL_MAX 128
extern int init_blacklist();
extern void charge_blacklist_state();
extern int black_domain_pkt(struct dns_packet *pkt);
#endif
