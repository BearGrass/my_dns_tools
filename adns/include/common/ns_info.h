#ifndef _NS_INFO_H_
#define _NS_INFO_H_

#include <stdint.h>

/* NS group info */
struct adns_ns_group_info {
	uint32_t group_id;                                          /* NS group ID */
	uint32_t ref_count;                                         /* NS group reference count */

	uint32_t ns_count;                                          /* NS count */
	uint8_t ns[ADNS_MAX_NS_NUM_PER_GROUP][ADNS_DOMAIN_MAX_LEN]; /* NS name */
}__attribute__((packed));

#endif
