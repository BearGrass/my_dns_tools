#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "rte_mbuf.h"
#include <rte_lcore.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "mbuf.h"
#include "adns.h"


struct rte_mempool *g_pktmbuf_pool = NULL;
struct rte_mempool *g_syslogmbuf_pool = NULL;


int init_mbuf()
{
    int socket_id;
    char name[64];

    socket_id = 0;
    
    if (g_pktmbuf_pool == NULL) {
        snprintf(name, sizeof(name), "ip_fragment_mbuf_pool_%d", socket_id);
        g_pktmbuf_pool = rte_mempool_create(name, DEFAULT_MEMPOOL_BUFFERS, DEFAULT_MBUF_SIZE, 
                                    DEFAULT_MEMPOOL_CACHE_SIZE,
                                    sizeof(struct rte_pktmbuf_pool_private),
                                    rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL, 0, 0);
        if(g_pktmbuf_pool == NULL){
            return -1;
        }

        printf("Allocated mbuf pool on socket:%d\n", socket_id);
    }

    if (g_syslogmbuf_pool == NULL) {
        snprintf(name, sizeof(name), "syslog_mbuf_pool_%d", socket_id);
        g_syslogmbuf_pool = rte_mempool_create(name, DEFAULT_SYSLOG_MEMPOOL_BUFFERS, DEFAULT_MBUF_SIZE,
                                    DEFAULT_MEMPOOL_CACHE_SIZE,
                                    sizeof(struct rte_pktmbuf_pool_private),
                                    rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL, 0, 0);
        if (g_syslogmbuf_pool == NULL){
            return -2;
        }

        printf("Allocated syslog mbuf pool on socket: %d\n", socket_id);
    }

    return 0;
}

int app_init_mbuf_pools(void)
{
    unsigned socket, lcore;

    /* Create the mbuf pool */
    kni_pktmbuf_pool = rte_mempool_create("kni_mbuf_pool", KNI_NB_MBUF, KNI_MBUF_SZ,
            KNI_MEMPOOL_CACHE_SZ,
            sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
            rte_socket_id(), 0);
    if (kni_pktmbuf_pool == NULL) {
        RTE_LOG(ERR, ADNS, "Could not initialise mbuf pool");
        return -1;
    }

    /* Init the buffer pools */
    for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
        char name[32];
        if (is_socket_used(socket) == 0) {
            continue;
        }

        snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
        RTE_LOG(ERR, ADNS, "Creating the mbuf pool for socket %u ...\n", socket);

        /* To support EDNS0 4096 bytes & GRE tunnel, packet will have 
           ether header + ipv4 header + gre header + ipv4 header + udp header
           + 4096 = 4166, at least 2 cache lines more than 4096 of
           DEFAULT_MBUF_SIZE. So add 8 cache lines for more room */
        app.pools[socket] = rte_mempool_create(
                name,
                DEFAULT_MEMPOOL_BUFFERS,
                DEFAULT_MBUF_SIZE + 8 * RTE_CACHE_LINE_SIZE,
                DEFAULT_MEMPOOL_CACHE_SIZE,
                sizeof(struct rte_pktmbuf_pool_private),
                rte_pktmbuf_pool_init, NULL,
                rte_pktmbuf_init, NULL,
                0,
                0);
        if (app.pools[socket] == NULL) {
            RTE_LOG(ERR, ADNS, "Cannot create mbuf pool on socket %u\n", socket);
            return -1;
        }
    }

    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        if (app.lcore_params[lcore].type == e_LCORE_DISABLED) {
            continue;
        }

        socket = rte_lcore_to_socket_id(lcore);
        app.lcore_params[lcore].pool = app.pools[socket];
    }

    return 0;
}

