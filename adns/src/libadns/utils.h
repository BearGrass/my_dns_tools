
#ifndef _ADNS_UTILS_H_
#define _ADNS_UTILS_H_

#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "adns_endian.h"

#if 0
struct adns_lookup_table {
	int id;
	const char *name;
};

typedef struct adns_lookup_table adns_lookup_table_t;

adns_lookup_table_t *adns_lookup_by_name(adns_lookup_table_t *table,
                                             const char *name);

adns_lookup_table_t *adns_lookup_by_id(adns_lookup_table_t *table,
                                           int id);
#endif

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
	memcpy((uint8_t *)&input + 1, (void *)pos, 6);
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

