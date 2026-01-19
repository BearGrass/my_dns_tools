#include "mem_info.h"

#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_atomic.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_mempool.h>

struct mem_info_t g_mem_info;


static unsigned
rte_mempool_count_cache(const struct rte_mempool *mp)
{

#if RTE_MEMPOOL_CACHE_MAX_SIZE > 0
    unsigned lcore_id;
    unsigned count = 0;
    unsigned cache_count;

    for (lcore_id = 0; lcore_id < mp->cache_size; lcore_id++) {
        cache_count = mp->local_cache[lcore_id].len;
        count += cache_count;
    }
    return count;
#else
    RTE_SET_USED(mp);
    return 0;
#endif
}

static inline uint64_t cal_common_count(const struct rte_mempool *mp) {

    unsigned common_count = rte_ring_count(mp->pool_data);
    unsigned cache_count = rte_mempool_count_cache(mp);
    if ((cache_count + common_count) > mp->size) {
        common_count = mp->size - cache_count;
    }
    return common_count;
}

static inline double cal_elt_size(const struct rte_mempool *mp) {

    return (mp->header_size + mp->elt_size + mp->trailer_size + \
        /* Every object has a rte_ring entry, the entry size is aligned  */
        sizeof(void*) * 1.0 * rte_align32pow2(mp->size + 1) / mp->size);
}


int get_memory_info() {

    memset((void*)&g_mem_info, 0, sizeof(struct mem_info_t));
    struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
    rte_rwlock_read_lock(&mcfg->mlock);

    int i = 0, j = 0;
    /* for each memseg */
    for (i = 0; i < RTE_MAX_MEMSEG; i++) {
        if (mcfg->memseg[i].addr == NULL)
            break;
        g_mem_info.total_per_socket[mcfg->memseg[i].socket_id] += mcfg->memseg[i].len;
        g_mem_info.total += mcfg->memseg[i].len;
    }

    /* for each memzone */
    for (i = 0; i < RTE_MAX_MEMZONE; i++) {
        if (mcfg->memzone[i].addr == NULL)
            break;

        g_mem_info.used += mcfg->memzone[i].len;
        g_mem_info.used_per_socket[mcfg->memzone[i].socket_id] += mcfg->memzone[i].len;
        struct rte_mempool *mp = NULL;
        
        /* mempool */
        if (memcmp(mcfg->memzone[i].name, RTE_MEMPOOL_MZ_PREFIX, 3) == 0) {
            mp = rte_mempool_lookup((mcfg->memzone[i].name) + 3);
            if (mp == NULL) {
                continue;
            }

            size_t memzone_len = 0;
            struct rte_mempool_memhdr *hdr;
            struct rte_memzone *mz = NULL;
            STAILQ_FOREACH(hdr, &mp->mem_list, next) {
                mz = (struct rte_memzone *)hdr->opaque;
                if (mz) {
                    memzone_len += mz->len;
                }
            }
            

            g_mem_info.zone_info_list[j].is_pool = 1;
            /* name
                * when zone is a pool, zone_name is consisted of 'MP_" + pool_name */
            memcpy(g_mem_info.zone_info_list[j].name, mcfg->memzone[i].name + 3,
                strlen(mcfg->memzone[i].name) - 3);
            /* socket id */
            g_mem_info.zone_info_list[j].socket_id = mcfg->memzone[i].socket_id;
            /* length */
            g_mem_info.zone_info_list[j].len = mcfg->memzone[i].len + \
                sizeof(void*) * rte_align32pow2(mp->size + 1) + sizeof(struct rte_ring) + 64 + memzone_len;
            /* element net size */
            g_mem_info.zone_info_list[j].pool_detail.elt_net_size = mp->elt_size;
            /* element total size */
            g_mem_info.zone_info_list[j].pool_detail.elt_size = cal_elt_size(mp);
            /* element count */
            g_mem_info.zone_info_list[j].pool_detail.elt_count = mp->size;
            /* element available count */
            g_mem_info.zone_info_list[j].pool_detail.avail_count = cal_common_count(mp);
            /* common base size */
            g_mem_info.zone_info_list[j].pool_detail.base_size = \
                sizeof(struct rte_mempool) + sizeof(struct rte_ring) + mp->private_data_size + 64 * 2;
        }
        else {
            /* ring is already calculated in mempool */
            if (memcmp(mcfg->memzone[i].name, "RG_MP_", 6) == 0 ) {
                continue;
            }

            /* physical memzone */
            g_mem_info.zone_info_list[j].is_pool = 0;
            /* name */
            memcpy(g_mem_info.zone_info_list[j].name, mcfg->memzone[i].name, strlen(mcfg->memzone[i].name));
            /* socket id */
            g_mem_info.zone_info_list[j].socket_id = mcfg->memzone[i].socket_id;
            /* zone len */
            g_mem_info.zone_info_list[j].len = mcfg->memzone[i].len;
        }
        j ++;
        g_mem_info.count++;
    }
    rte_rwlock_read_unlock(&mcfg->mlock);
    return 0;
}
