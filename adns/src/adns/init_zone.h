#ifndef _ADNS_INIT_ZONE_H_
#define _ADNS_INIT_ZONE_H_


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <rte_spinlock.h>
#include <rte_atomic.h>


int adns_zonedb_load_init(void);
void adns_zonedb_load_cleanup(void);


#endif

