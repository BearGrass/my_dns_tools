#ifndef _ADNS_UTILI_H_
#define _ADNS_UTILI_H_


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_lcore.h>
#include <rte_memory.h>


/*update interval: 2s*/
#define CPU_UTILI_INTER 2


struct cycle_use {
	uint64_t recv;
	uint64_t send;
	uint64_t app;
} __rte_cache_aligned;


extern struct cycle_use g_cycle_usage[RTE_MAX_LCORE];
extern struct adns_utili g_adns_utili;


void cpu_utili_process(void);


#endif

