#ifndef _UTILS_H_
#define _UTILS_H_

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_byteorder.h>


#define adns_htobe16(x) rte_cpu_to_be_16(x)
#define adns_htobe32(x) rte_cpu_to_be_32(x)
#define adns_htobe64(x) rte_cpu_to_be_64(x)

#define adns_be16toh(x) rte_be_to_cpu_16(x)
#define adns_be32toh(x) rte_be_to_cpu_32(x)
#define adns_be64toh(x) rte_be_to_cpu_64(x)

static inline uint16_t adns_wire_read_u16(const uint8_t *pos)
{
    return adns_be16toh(*(const uint16_t *)pos);
}

static inline uint32_t adns_wire_read_u32(const uint8_t *pos)
{
    return adns_be32toh(*(const uint32_t *)pos);
}

static inline uint64_t adns_wire_read_u48(const uint8_t *pos)
{
    uint64_t input = 0;
    memcpy((void *)&input + 1, (void *)pos, 6);
    return adns_be64toh(input) >> 8;
}

static inline uint64_t adns_wire_read_u64(const uint8_t *pos)
{
    return adns_be64toh(*(const uint64_t *)pos);
}

static inline void adns_wire_write_u16(uint8_t *pos, uint16_t data)
{
    *(uint16_t *)pos = adns_htobe16(data);
}

static inline void adns_wire_write_u32(uint8_t *pos, uint32_t data)
{
    *(uint32_t *)pos = adns_htobe32(data);
}

static inline void adns_wire_write_u48(uint8_t *pos, uint64_t data)
{
    uint64_t swapped = adns_htobe64(data << 8);
    memcpy((void *)pos, (uint8_t *)&swapped + 1, 6);
}

static inline void adns_wire_write_u64(uint8_t *pos, uint64_t data)
{
    *(uint64_t *)pos = adns_htobe64(data);
}

#endif
