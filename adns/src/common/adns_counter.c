#include <rte_config.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_string_fns.h>
#include <rte_branch_prediction.h>
#include <string.h>
#include "adns_counter.h"
#include <rte_cycles.h>
#include "common_value.h"
#include "adns.h"
#include "adns_types.h"

extern struct app_params app;
extern uint64_t g_node_qps_valid_duration;

const struct rte_memzone *g_adns_counter_table[RTE_MAX_NUMA_NODES][RTE_MAX_LCORE];
uint32_t  g_adns_counter_num = DEFAULT_NUM;
uint16_t g_io_lcore_id_start;
uint16_t g_io_lcore_num;

int adns_counter_init_value(unsigned int counter_id)
{
    int i;
    struct counter *cnt = NULL;
    const struct rte_memzone **socket_counter_mz = NULL;
    const struct rte_memzone *lcore_counter_mz = NULL;


    if(INVALID_COUNTER_ID(counter_id)){
        return -1;
    }

    // for now we only use node 0, if muma is on, need work here
    socket_counter_mz = (const struct rte_memzone **)(g_adns_counter_table[0]);
    if (socket_counter_mz == NULL) {
        return -1;
    }

    for (i = 0; i < g_io_lcore_num; i ++) {
         lcore_counter_mz = socket_counter_mz[i];
         cnt = (struct counter *)(lcore_counter_mz->addr);
         memset(cnt + counter_id, 0, sizeof(struct counter));
    }

    return 0;
}


int adns_counter_add(unsigned int counter_id, uint64_t num)
{
    int io_lcoreid;
    const struct rte_memzone *lcore_counter_mz = NULL;
    struct counter *cnt = NULL;

    if (INVALID_COUNTER_ID(counter_id)) {
        return -1;
    }

    io_lcoreid = rte_lcore_id() - g_io_lcore_id_start;
    // for now we only use node 0, if muma is on, need work here
    lcore_counter_mz = g_adns_counter_table[0][io_lcoreid];

    cnt = ((struct counter *)(lcore_counter_mz->addr)) + counter_id;
    cnt->value += num;

    return 0;
}


int adns_counter_increase(int counter_id)
{
    return adns_counter_add(counter_id, 1);
}


int adns_counter_sub(unsigned int counter_id, uint64_t num)
{
    int io_lcoreid;
    const struct rte_memzone *lcore_counter_mz = NULL;
    struct counter *cnt = NULL;

    if (INVALID_COUNTER_ID(counter_id)) {
        return -1;
    }

    io_lcoreid = rte_lcore_id() - g_io_lcore_id_start;
    // for now we only use node 0, if muma is on, need work here
    lcore_counter_mz = g_adns_counter_table[0][io_lcoreid];

    cnt = ((struct counter *)(lcore_counter_mz->addr)) + counter_id;
    cnt->value -= num;

    return 0;
}


int adns_counter_decrease(int counter_id)
{
    return adns_counter_sub(counter_id, 1);
}


int adns_counter_sum_get(unsigned int counter_id, uint64_t *value)
{
    int io_lcoreid;
    uint64_t sum = 0;
    const struct rte_memzone *lcore_counter_mz = NULL;
    struct counter *cnt = NULL;

    if (value == NULL) {
        return -1;
    }
    *value = 0;

    if (INVALID_COUNTER_ID(counter_id)) {
        return -1;
    }

    for (io_lcoreid = 0; io_lcoreid < g_io_lcore_num; io_lcoreid++) {
        // for now we only use node 0, if muma is on, need work here
        lcore_counter_mz = g_adns_counter_table[0][io_lcoreid];
        cnt = ((struct counter *)(lcore_counter_mz->addr)) + counter_id;
        sum += cnt->value;
    }

    *value = sum;
    return 0;
}


int adns_counter_sum_get_queries_bytes(unsigned int counter_id, uint64_t *queries, uint64_t *bytes)
{
    int io_lcoreid;
    uint64_t total_queries = 0, total_bytes = 0;
    const struct rte_memzone *lcore_counter_mz = NULL;
    struct counter *cnt = NULL;

    if (queries == NULL || bytes == NULL) {
        return -1;
    }
    *queries = 0;
    *bytes = 0;

    if (INVALID_COUNTER_ID(counter_id)) {
        return -1;
    }

    for (io_lcoreid = 0; io_lcoreid < g_io_lcore_num; io_lcoreid++) {
        // for now we only use node 0, if muma is on, need work here
        lcore_counter_mz = g_adns_counter_table[0][io_lcoreid];
        cnt = ((struct counter *)(lcore_counter_mz->addr)) + counter_id;

        total_queries += cnt->queries;
        total_bytes += cnt->bytes;
    }

    *queries = total_queries;
    *bytes = total_bytes;

    return 0;
}

int adns_counter_init(uint32_t init_num)
{
    int i, io_lcoreid;
    const struct rte_memzone *mz;
    char s[64];

    if (init_num >= COUNTERS_MAX_NUM) {
        RTE_LOG(ERR, EAL, "The init perlcore counter num is too large");
        return -1;
    }

    if (init_num != 0) {
        g_adns_counter_num = init_num;
    }

    g_io_lcore_id_start = app.lcore_io_start_id;
	#define MAX_TCP_WORKER_NUM  2
    g_io_lcore_num = app.lcore_io_num + MAX_TCP_WORKER_NUM;

    // for now we only use node 0, if muma is on, need work here
    for(i = 0; i < 1; i++){
        for (io_lcoreid = 0; io_lcoreid < g_io_lcore_num; io_lcoreid ++) {
            snprintf(s, sizeof(s), "adns_counter_memzone_%d_%d", i, io_lcoreid);
            mz = rte_memzone_reserve(s, sizeof(struct counter) * g_adns_counter_num, i, 0);
            if (mz == NULL) {
                rte_exit(EXIT_FAILURE, "Cannot init %s on socket %d for lcore %d\n", s, i, (io_lcoreid + g_io_lcore_id_start));
            } else {
                RTE_LOG(INFO, EAL, "Allocated %s on socket %d for lcore %d\n", s, i, (io_lcoreid + g_io_lcore_id_start));
            }
            g_adns_counter_table[i][io_lcoreid] = (struct rte_memzone *)mz;
            memset(mz->addr, 0, sizeof(struct counter) * g_adns_counter_num);
        }
    }

    return 0;
}


void adns_counter_cleanup()
{
    return;
}


