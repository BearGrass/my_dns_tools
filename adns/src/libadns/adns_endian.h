
#ifndef _ADNS_ENDIAN_H_
#define _ADNS_ENDIAN_H_

#include <rte_byteorder.h>

#define adns_htobe16(x) rte_cpu_to_be_16(x)
#define adns_htobe32(x) rte_cpu_to_be_32(x)
#define adns_htobe64(x) rte_cpu_to_be_64(x)

#define adns_be16toh(x) rte_be_to_cpu_16(x)
#define adns_be32toh(x) rte_be_to_cpu_32(x)
#define adns_be64toh(x) rte_be_to_cpu_64(x)

/*
 * An architecture-optimized byte swap for a 64-bit value stored as 8-bit array.
 */
/* 64-bit mode */
static inline uint64_t adns_arch_bswap64(uint8_t *_x) {
    return _x[7] | ((uint64_t) _x[6] << 8) | ((uint64_t) _x[5] << 16)
            | ((uint64_t) _x[4] << 24) | ((uint64_t) _x[3] << 32)
            | ((uint64_t) _x[2] << 40) | ((uint64_t) _x[1] << 48)
            | ((uint64_t) _x[0] << 56);
}

#endif

