#ifndef _FWD_USER_H_
#define _FWD_USER_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


#define MAX_USER_IP_RANGE_NUM 16

#define USER_STATUS_SERVING 0
#define USER_STATUS_SUSPEND 1

#define IP_RANGE_FAMILY_IPV4 1
#define IP_RANGE_FAMILY_IPV6 2

#define IP_RANGE_MIN_MASK_DEPTH 20

typedef struct ip_range {
  uint8_t family;    /* address family, 1:IPv4, 2:IPv6 */
  uint8_t mask;    /* address netmask */
  uint16_t padding1;
  uint32_t padding2;
  // support both ipv4 and ipv6
  union {
    uint32_t        v4;         /* IPv4 address */
      uint8_t         v61[16];    /* IPv6 address of uint8_t */
      uint16_t        v62[8];     /* IPv6 address of uint16_t */
      uint32_t        v63[4];     /* IPv6 address of uint32_t */
      uint64_t        v64[2];     /* IPv6 address of uint64_t */
  } addr;
} ip_range_t;

typedef struct fwd_usr_snapshot {
	uint32_t user_id;
	uint16_t range_num;
	uint8_t status;
} __attribute__((packed)) fwd_usr_snapshot_t;

typedef struct fwd_user {
    struct list_head list;
    uint32_t user_id;
    uint16_t range_num;
    uint8_t status;
    ip_range_t ip_ranges[MAX_USER_IP_RANGE_NUM];
} fwd_user_t;

extern uint32_t g_fwd_user_max_num;

static inline int fwd_user_chg_status(fwd_user_t *user, uint8_t status) {
	if (status != USER_STATUS_SERVING && status != USER_STATUS_SUSPEND) {
		return -1;
	}

	user->status = status;
	return 0;
}

int fwd_user_add_ip_ranges(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges);
int fwd_user_del_ip_ranges(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges);
int fwd_user_ref_ip_ranges(fwd_user_t *user, uint16_t range_num,
		ip_range_t *ip_ranges);

fwd_user_t* fwd_user_new(uint32_t user_id, uint16_t range_num,
		ip_range_t *ip_ranges, uint8_t status);
void fwd_user_free(fwd_user_t *user);
int fwd_user_init();

void dump_fwd_user(FILE *fp, fwd_user_t *user);


#endif /* _FWD_USER_H_ */
