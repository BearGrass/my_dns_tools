#ifndef _MEM_INFO_H_
#define _MEM_INFO_H_

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>

#ifndef RTE_MAX_NUMA_NODES
    #define RTE_MAX_NUMA_NODES  8
#endif

#ifndef RTE_MEMZONE_NAMESIZE
    #define RTE_MEMZONE_NAMESIZE 32
#endif

#ifndef RTE_MAX_MEMZONE
    #define RTE_MAX_MEMZONE 2560
#endif

struct mem_info_t {
    uint64_t    count;

    uint64_t    used;
    uint64_t    total;

    uint64_t    used_per_socket[RTE_MAX_NUMA_NODES];
    uint64_t    total_per_socket[RTE_MAX_NUMA_NODES];

    struct      zone_info_t {
        char        name[RTE_MEMZONE_NAMESIZE];
        uint64_t    len;
        int32_t     socket_id;
        uint8_t     is_pool;
        struct      pool_detail_t {
            uint64_t    base_size;
            uint64_t    elt_count;
            double      elt_size;
            uint64_t    elt_net_size;
            uint64_t    avail_count;
        } pool_detail;
    } zone_info_list[RTE_MAX_MEMZONE];
};

extern struct mem_info_t g_mem_info;

int get_memory_info();

#endif
