#ifndef _AS_VXLAN_H_
#define _AS_VXLAN_H_

#include <linux/types.h>
#include <linux/netfilter.h>    /* union nf_inet_addr */
#include <asm/byteorder.h>


struct vxlan_info {
        u32 vid;
        __be32 saddr;   /* vxlan src address */
        __be32 daddr;   /* vxlan dst address */
        __be16 dport;
};

struct vxlanhdr {
        __u8    flags;
#if defined(__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                type:1,
                ext:1,
                debug:1,
                res1:1;
        __u8    tos:3,
                slb_type:3,
                res2:2;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    res1:1,
                debug:1,
                ext:1,
                type:1,
                version:4;
        __u8    res2:2,
                slb_type:3,
                tos:3;
#endif
        __u8    res3;
        __be32  vid;
};

#define VCTK_VXLAN_TOS_BYPASS_SG        0x01

#define VX_SLB_HC       3       /* keepalived healthcheck */
#define VX_SLB_L7       4       /* tengine */

#define VXLAN_N_VID (1u << 24)
#define VXLAN_VID_MAX  (VXLAN_N_VID - 1)
#define VXLAN_HLEN (sizeof(struct udphdr) + sizeof(struct vxlanhdr))
#define VXLAN_FLAGS 0x08
#define VXLAN_LISTEN_PORT       htons(4789)
#define vxlan_id(vhdr) (ntohl(vhdr->vid) >> 8)

#endif

