
#ifndef _ADNS_EDNS_H_
#define _ADNS_EDNS_H_

#include <stdint.h>

#include "utils.h"
#include "rrset.h"


/* Structure representing one OPT RR option */
struct adns_opt_option {
	uint16_t code;
	uint16_t length;
	uint8_t *data;
};
typedef struct adns_opt_option adns_opt_option_t;


/* EDNS without opt size */
#define EDNS_EMPTY_SIZE 11

/* EDNS DO bit mask */
#define EDNS_DO      0x8000U
#define EDNS_H_DO    0x0080U

/* edns-client-sunbet util */
#define ECS_FAMILY_IPV4 1
#define ECS_FAMILY_IPV6 2

#define ECS_MIN_SIZE    8

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
	struct adns_opt_option *options;	/* EDNS options */
	struct adns_opt_ecs opt_ecs;
	uint16_t option_count;	/* Count of EDNS options in this OPT RR */
	uint16_t options_max;	/* Maximum count of options */
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
	EDNS_MIN_SIZE        = 11    /* Minimum size of EDNS OPT RR in wire format. */
};

/* Creates new empty OPT RR structure for holding EDNS parameters. */
adns_opt_rr_t *adns_edns_new(void);

/* Initializes OPT RR structure from given OPT RRSet. */
int adns_edns_new_from_rr(adns_opt_rr_t *opt_rr, struct adns_rrset *rrset);

/* Returns the UDP payload stored in the OPT RR. */
uint16_t adns_edns_get_payload(const adns_opt_rr_t *opt_rr);

/* Sets the UDP payload field in the OPT RR. */
void adns_edns_set_payload(adns_opt_rr_t *opt_rr, uint16_t payload);

/* Returns the Extended RCODE stored in the OPT RR. */
uint8_t adns_edns_get_ext_rcode(const adns_opt_rr_t *opt_rr);

/* Sets the Extended RCODE field in the OPT RR. */
void adns_edns_set_ext_rcode(adns_opt_rr_t *opt_rr, uint8_t ext_rcode);

/* Returns the EDNS version stored in the OPT RR. */
uint8_t adns_edns_get_version(const adns_opt_rr_t *opt_rr);

/* Sets the EDNS version field in the OPT RR. */
void adns_edns_set_version(adns_opt_rr_t *opt_rr, uint8_t version);

/* brief Returns the flags stored in the OPT RR. */
uint16_t adns_edns_get_flags(const adns_opt_rr_t *opt_rr);

/* Returns the state of the DO bit in the OPT RR flags. */
int adns_edns_get_do(const adns_opt_rr_t *opt_rr);

/* Sets the DO bit in the OPT RR. */
void adns_edns_set_do(adns_opt_rr_t *opt_rr);

int adns_edns_add_option(adns_opt_rr_t *opt_rr, uint16_t code,
		uint16_t length, const uint8_t *data);

int adns_edns_has_option(const adns_opt_rr_t *opt_rr, uint16_t code);

int adns_edns_to_wire(const adns_opt_rr_t *opt_rr, uint8_t *wire,
		size_t max_size);

int adns_edns_size(adns_opt_rr_t *opt_rr);

void adns_edns_free_options(adns_opt_rr_t *opt_rr);

void adns_edns_free(adns_opt_rr_t *opt_rr);

#endif

