#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_lcore.h>
#include <rte_cycles.h>

#include "utili_base.h"
#include "adns_utili.h"


struct cycle_use g_cycle_usage[RTE_MAX_LCORE] = {{0, 0, 0}};
struct adns_utili g_adns_utili;
static uint64_t g_pre_usage[RTE_MAX_LCORE] = {0};


void cpu_utili_process()
{
	int i, lcore_num;
    uint64_t hz;
	float utili;

	lcore_num = rte_lcore_count();
	if (lcore_num > RTE_MAX_LCORE) {
		return;
	}
	g_adns_utili.cpu_num = lcore_num;

	lcore_num = 0;
	hz = rte_get_timer_hz();
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (rte_lcore_is_enabled(i) == 0) {
			continue;
        }

		g_adns_utili.cpu[i].lcore = i;
		utili = ((float)(g_cycle_usage[i].send + g_cycle_usage[i].recv + g_cycle_usage[i].app - g_pre_usage[i]) 
								/ (CPU_UTILI_INTER*hz))*100;
		g_pre_usage[i] = g_cycle_usage[i].send + g_cycle_usage[i].recv + g_cycle_usage[i].app;

		g_adns_utili.cpu[i].usage = utili;
	}
}

