#ifndef _ADNS_EDNS_H_
#define _ADNS_EDNS_H_

#include <net/route.h>

#include "dns.h"
#include "util.h"

/* Structure representing one OPT RR option */
struct adns_opt_option {
    uint16_t code;
    uint16_t length;
    uint32_t data;
};
typedef struct adns_opt_option adns_opt_option_t;

/* edns-client-sunbet util */
#define ECS_FAMILY_IPV4      1
#define ECS_FAMILY_IPV6      2
#define ECS_MIN_SIZE         8
#define MAX_UDP_PAYLOAD      512
#define DNS_EDNS0_MAX_LENGTH 4096
#define ADNS_RRTYPE_OPT      41
#define PVT_EDNS_OPT_SIZE    8
#define AS_NO_VXLAN          0
#define AS_VXLAN             1

/* structure for google-edns-subnet option */
struct adns_opt_ecs {
    uint16_t code;
    uint16_t length;
    uint16_t family;		/* address family, 1:IPv4, 2:IPv6 */
    uint8_t  src_mask;		/* source netmask */
    uint8_t  scope_mask;	/* scope netmask */

    uint8_t  addr_len;		/* address lenth */

    // support both ipv4 and ipv6 ecs data
    union {
        uint32_t        v4;         /* IPv4 address */
        uint8_t         v61[16];    /* IPv6 address of uint8_t */
        uint16_t        v62[8];     /* IPv6 address of uint16_t */
        uint32_t        v63[4];     /* IPv6 address of uint32_t */
        uint64_t        v64[2];     /* IPv6 address of uint64_t */
    } addr;
};
typedef struct adns_opt_ecs adns_opt_ecs_t;

/* structure for edns cookie */
struct adns_opt_cookie {
    uint16_t code;            /* opcode, 10 for cookie */
    uint16_t length;          /* cookie length, could include both client cookie and server cookie, 8 or [16,40] */
    uint8_t client_cookie[8]; /* client cookie, 8 bytes */
    uint8_t server_cookie[0]; /* server cookie, varial size, 0 or [8, 32] */
};
typedef struct adns_opt_cookie adns_opt_cookie_t;

/* Structure for holding EDNS parameter */
struct adns_opt_rr {
    uint16_t payload;	/* UDP payload */
    uint8_t ext_rcode;	/* Extended RCODE */

    /* Supported version of EDNS, set to EDNS_NOT_SUPPORTED if not supported */
    uint8_t version;

    uint16_t flags;	/* EDNS flags */
    struct adns_opt_option options;	/* EDNS options */
    uint16_t size;			/* Total size of the OPT RR in wire format */
};
typedef struct adns_opt_rr adns_opt_rr_t;

enum adns_edns_const {
    EDNS_OPT             = 41,
    EDNS_MAX_UDP_PAYLOAD = 4096, /* Maximum UDP payload with EDNS enabled. */
    EDNS_VERSION         = 0,    /* Supported EDNS version. */
    EDNS_NOT_SUPPORTED   = 255,  /* EDNS not supported. */
    EDNS_OPTION_NSID     = 3,    /* NSID option code. */
    EDNS_OPTION_ECS      = 8,    /* client-subnet option code. */
    EDNS_OPTION_COOKIE   = 10,   /* cookie option code */
    EDNS_MIN_SIZE        = 11,   /* Minimum size of EDNS OPT RR in wire format. */
    EDNS_OPTION_PVT      = 65535, /* private zone dedicated */
    EDNS_OPTION_PVT_LEN  = 4
};

static inline void __attribute__ ((always_inline))
adns_edns_init(adns_opt_rr_t *opt_rr, uint16_t code, uint16_t length,
        uint32_t data) {
    opt_rr->ext_rcode = 0;
    opt_rr->flags = 0;
    opt_rr->version = 0;
    opt_rr->payload = EDNS_MAX_UDP_PAYLOAD;
    opt_rr->options.code = code;
    opt_rr->options.length = length;
    opt_rr->options.data = data;
    opt_rr->size = EDNS_MIN_SIZE + PVT_EDNS_OPT_SIZE;
}

static inline void __attribute__ ((always_inline))
adns_edns_to_wire(const adns_opt_rr_t *opt_rr, uint8_t *pos)
{
    uint16_t *rdlen;
    uint16_t len;

    *(pos++) = 0;
    *(uint16_t *)pos = htons(ADNS_RRTYPE_OPT);
    pos += 2;
    *(uint16_t *)pos = htons(opt_rr->payload);
    pos += 2;
    *(pos++) = opt_rr->ext_rcode;
    *(pos++) = opt_rr->version;
    *(uint16_t *)pos = htons(opt_rr->flags);
    pos += 2;

    rdlen = (uint16_t *)pos;
    len = 0;
    pos += 2;

    *(uint16_t *)pos = htons(opt_rr->options.code);
    pos += 2;
    *(uint16_t *)pos = htons(opt_rr->options.length);
    pos += 2;
    *(uint32_t *)pos = htonl(opt_rr->options.data);
    pos += 4;
    len += 4 + opt_rr->options.length;
    *rdlen = htons(len);
}

/* add pvt view id to edns option */
static inline void __attribute__ ((always_inline))
adns_view_id_to_edns_option(adns_opt_rr_t *opt_rr, uint16_t *opt_len, uint8_t *pos)
{
    *opt_len = htons(ntohs(*opt_len) + PVT_EDNS_OPT_SIZE);
    *(uint16_t *)pos = htons(opt_rr->options.code);
    pos += 2;
    *(uint16_t *)pos = htons(opt_rr->options.length);
    pos += 2;
    *(uint32_t *)pos = htonl(opt_rr->options.data);
    pos += 4;
}

int parse_dns_additional(uint8_t **wire, uint16_t **opt_len_pos, uint16_t edns_len);


#endif

