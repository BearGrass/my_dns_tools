#ifndef _UTILI_BASE_H_
#define _UTILI_BASE_H_


#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <rte_config.h>

#include "adns_conf.h"
#include "adns_share.h"


struct cpu_utili {
	int lcore;
	float usage;
};


struct adns_utili {
	struct cpu_utili cpu[RTE_MAX_LCORE];
	int cpu_num;
};


/*adns info*/
typedef struct adns_info{
    uint32_t zone_max_num;
    uint32_t private_route_zone_max_num;
    uint32_t dnssec_zone_max_num;
    uint32_t dnssec_cache_max_num;
    uint32_t domain_max_num;
    uint32_t rr_max_num;
    uint32_t rdata_ctl_max_num;
    uint32_t private_rdata_ctl_max_num;
    uint32_t rrset_memory_max_num;
    uint32_t zone_name_max_num[NAME_LEN_TYPE_NUM];
    uint32_t domain_name_max_num[NAME_LEN_TYPE_NUM];

    uint32_t zone_num;
    uint32_t private_route_zone_num;
    uint32_t dnssec_zone_num;
    uint32_t dnssec_cache_num;
    uint32_t domain_num;
    uint32_t rr_num;
    struct rr_detail_num_t rr_detail_num;//wrapped up in a struct and it will be bound to adns_share.h -- should it be?
    uint32_t rdata_ctl_num;
    uint32_t private_rdata_ctl_num;
    uint32_t rrset_memory_num;
    uint32_t zone_name_used_num[NAME_LEN_TYPE_NUM];
    uint32_t domain_name_used_num[NAME_LEN_TYPE_NUM];
}adns_info_t;


/*dpdk port stats*/
typedef struct adns_dpdk_port_stats{
    uint64_t ipackets;  /**< Total number of successfully received packets. */
    uint64_t opackets;  /**< Total number of successfully transmitted packets.*/
    uint64_t ibytes;    /**< Total number of successfully received bytes. */
    uint64_t obytes;    /**< Total number of successfully transmitted bytes. */
    uint64_t ierrors;   /**< Total number of erroneous received packets. */
    uint64_t oerrors;   /**< Total number of failed transmitted packets. */
    uint64_t imcasts;   /**< Total number of multicast received packets. */
    uint64_t rx_nombuf; /**< Total number of RX mbuf allocation failures. */
    uint64_t q_ipackets[RTE_ETHDEV_QUEUE_STAT_CNTRS];/**< Total number of queue RX packets. */
	uint64_t q_errors[RTE_ETHDEV_QUEUE_STAT_CNTRS];  /**< Total number of queue packets received that are dropped. */
	uint64_t q_opackets[RTE_ETHDEV_QUEUE_STAT_CNTRS];/**< Total number of queue TX packets. */
	
}adns_dpdk_port_stats_t;

/* dpdk rte_malloc_socket_stats */
typedef struct adns_malloc_socket_stats{
	size_t heap_totalsz_bytes; /**< Total bytes on heap */
	size_t heap_freesz_bytes;  /**< Total free bytes on heap */
	size_t greatest_free_size; /**< Size in bytes of largest free block */
	unsigned free_count;       /**< Number of free elements on heap */
	unsigned alloc_count;      /**< Number of allocated elements on heap */
	size_t heap_allocsz_bytes; /**< Total allocated bytes on heap */
}adns_malloc_socket_stats_t;


#endif

