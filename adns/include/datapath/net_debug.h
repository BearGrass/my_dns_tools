
#ifndef _NET_DEBUG_H_
#define _NET_DEBUG_H_

#include <stdint.h>


#define NIPQUAD(addr) \
    ((uint8_t *)&addr)[0], \
    ((uint8_t *)&addr)[1], \
    ((uint8_t *)&addr)[2], \
    ((uint8_t *)&addr)[3]

#define HIPQUAD(addr) \
    ((uint8_t *)&addr)[3], \
    ((uint8_t *)&addr)[2], \
    ((uint8_t *)&addr)[1], \
    ((uint8_t *)&addr)[0]

struct arpv4_hdr {
    uint16_t hard_type;
	uint16_t protocol;
	uint8_t  hard_addr_size;
	uint8_t  prot_addr_size;
	uint16_t opcode;
	uint8_t  sender_mac[6];
	uint8_t  sender_ip[4];
	uint8_t  target_mac[6];
	uint8_t  target_ip[4];
} __attribute__((packed));




void net_arp_dump(struct arpv4_hdr *arp);
void net_pkt_dump(const void *data);



#endif

