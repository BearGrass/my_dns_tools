#ifndef _PRIVATE_ROUTE_H_
#define _PRIVATE_ROUTE_H_

#include <stdint.h>


#include "adns_types.h"

/* The quit condition of dichotomy */
#define _IPSET_QCOD         4

/* Max IPv4 address, 255.255.255.255 */
#define _IPSET_MAX_4        0xFFFFFFFFU

/* Ipset lookup miss return value */
#define IPSET_LOOKUP_MISS   255  // 2^8 -1

/**
 ** IPv4 information
 **/
struct adns_ipset_ipv4_info {
    uint32_t    ips_head;
    uint32_t    ips_tail;
    adns_private_route_id_t id;
}__attribute__((packed));

typedef struct adns_ipset_ipv4_info adns_ipset_ipv4_info_t;

/**
 **  IP set for private route
 **/
struct adns_ipset {
    uint16_t                   ips_cap;           /* ip segment capacity */
    uint16_t                   ips_num;           /* ip segment number */
    adns_private_route_id_t    max_route_id;      /* max private_route_id in the ipset */           
    adns_ipset_ipv4_info_t     *info4;            /* ip segments */
}__attribute__((packed));

typedef struct adns_ipset adns_ipset_t;

#if 0
static inline uint32_t
adns_ipv4_head(uint32_t ipv4_addr, uint8_t mask)
{
    uint32_t mask32_t[33] = {0x00000000, 0x80000000, 0xc0000000, 0xe0000000,
                             0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000,
                             0xff000000, 0xff800000, 0xffc00000, 0xffe00000,
                             0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000,
                             0xffff0000, 0xffff8000, 0xffffc000, 0xffffe000,
                             0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00,
                             0xffffff00, 0xffffff80, 0xffffffc0, 0xffffffe0,
                             0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe,
                             0xffffffff};
    
    if(mask > 32) {
        mask = 32;
    }
    
    return ntohl(ipv4_addr) & mask32_t[mask];
}


static inline uint32_t
adns_ipv4_tail(uint32_t ipv4_head, uint8_t mask)
{
    //((0x1 << (32 - mask)) - 1)
    uint32_t mask32_t[33] = {0xffffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff,
                             0x0fffffff, 0x07ffffff, 0x03ffffff, 0x01ffffff,
                             0x00ffffff, 0x007fffff, 0x003fffff, 0x001fffff,
                             0x000fffff, 0x0007ffff, 0x0003ffff, 0x0001ffff,
                             0x0000ffff, 0x00007fff, 0x00003fff, 0x00001fff,
                             0x00000fff, 0x000007ff, 0x000003ff, 0x000001ff,
                             0x000000ff, 0x0000007f, 0x0000003f, 0x0000001f,
                             0x0000000f, 0x00000007, 0x00000003, 0x00000001,
                             0x00000000};
    if(mask > 32) {
        mask = 32;
    }
    
    return ipv4_head | mask32_t[mask];
}
#endif

/*******************************************************************************
 * Init memory for private route
 ******************************************************************************/
int adns_private_route_init();


/*******************************************************************************
 * Create an ipset
 ******************************************************************************/
adns_ipset_t* adns_ipset_alloc(adns_socket_id_t socket_id);


/*******************************************************************************
 * Add an ipset segment list to the ipset
 * The IP segment list must be add with incremental ID
 * @param ipset
 *    ipset pointer
 * @param ipset_ipsl
 *    ip segment list pointer, the IP segment list must be incrementally sorted
 *    by head address, the IP address is in host order,the ipset_ipsl will be 
 *    modified in this function
 * return
 *    0 if success
 *    <0 if failure
 *****************************************************************************/
int adns_ipset_init(adns_ipset_t *ipset, const char *iplib);


/******************************************************************************
 * Destroy the ipset
 * @param ipset
 *    ipset pointer
 *****************************************************************************/
void adns_ipset_free(adns_ipset_t *ipset);


/******************************************************************************
 * Lookup an IPv4 address in the ipset
 * @param ipset
 *    ipset pointer
 * @param addr
 *    the IPv4 address to lookup
 * return
 *    IPSET_LOOKUP_MISS if addr not found
 *    view id
 *****************************************************************************/
adns_private_route_id_t adns_ipset_lookup(adns_ipset_t *ipset, uint32_t addr_n);

#endif
