
#ifndef _ADNS_FDIR_H_
#define _ADNS_FDIR_H_

#include <stdint.h>
#include <string.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_atomic.h>
#include <rte_rwlock.h>
#include <rte_lpm.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_ether.h>
#include <rte_errno.h>
#include <rte_spinlock.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_timer.h>
#include <rte_ethdev.h>
#include <rte_kni.h>

// Only support IPv4, does not support vlan and flexbytes feature setting.
struct adns_fdir_masks {
	uint8_t port_id;
	uint8_t mode;	// perfect or signature

	/** When set to 1, packet l4type is \b NOT relevant in filters, and
	   source and destination port masks must be set to zero. */
	uint8_t only_ip_flow;
	/** Mask of Destination IPv4 Address. All bits set to 1 define the
	    relevant bits to use in the destination address of an IPv4 packet
	    when matching it against FDIR filters. */
	uint32_t dst_ipv4_mask;
	/** Mask of Source IPv4 Address. All bits set to 1 define
	    the relevant bits to use in the source address of an IPv4 packet
	    when matching it against FDIR filters. */
	uint32_t src_ipv4_mask;
	/** Mask of Source Port. All bits set to 1 define the relevant
	    bits to use in the source port of an IP packets when matching it
	    against FDIR filters. */
	uint16_t src_port_mask;
	/** Mask of Destination Port. All bits set to 1 define the relevant
	    bits to use in the destination port of an IP packet when matching it
	    against FDIR filters. */
	uint16_t dst_port_mask;
};

#define ADNS_FDIR_ADD    0x01
#define ADNS_FDIR_DEL    0x02
#define ADNS_FDIR_UPDATE 0x03

struct adns_fdir_filter {
	int opcode;

	uint8_t port_id;
	uint8_t queue_id;
	uint8_t soft_id;
	
	uint8_t protocol;
	
	uint32_t src_addr;
	uint32_t dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
};


extern int adns_fdir_init(void);
extern void adns_fdir_cleanup(void);
extern int add_fdir_port(uint16_t dport,int queue_id,int i_port);
#endif

