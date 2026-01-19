
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "dns_pkt.h"

#include "descriptor.h"
#include "rrset.h"
#include "dname.h"


#if 0
static int adns_packet_parse_rdata(struct adns_rrset *rr, const uint8_t *wire,
		size_t *pos, size_t total_size, size_t rdlength)
{
	if (!rr || !wire || !pos || rdlength == 0) {
		return -EINVAL;
	}

	/*! \todo As I'm revising it, seems highly inefficient to me.
	 *        We just need to skim through the packet,
	 *        check if it is in valid format and store pointers to various
	 *        parts in rdata instead of copying memory blocks and
	 *        parsing domain names (with additional allocation) and then
	 *        use use the wireformat for lookup again. Compression could
	 *        be handled in-situ without additional memory allocs...
	 */

	int ret = knot_rrset_rdata_from_wire_one(rr, wire, pos, total_size,
	                                         rdlength);
	if (ret != 0) {
		printf("packet: parse_rdata: Failed to parse RDATA.\n");
		return ret;
	}

	return 0;
}
#endif

struct adns_rrset *
query_parse_rr(const uint8_t *wire, size_t *pos, size_t size)
{
	printf("Parsing RR from position: %zu, total size: %zu\n", *pos, size);

	adns_dname_t *owner = adns_dname_parse(wire, pos, size);
	printf("Created owner: %p, actual position: %zu\n", owner, *pos);
	if (owner == NULL) {
		return NULL;
	}
	adns_dname_to_lower(owner);

	char *name = adns_dname_to_str(owner);
	printf("Parsed name: %s\n", name);
	free(name);

	if (size - *pos < ADNS_RR_HEADER_SIZE) {
		printf("Malformed RR: Not enough data to parse RR header.\n");
		adns_dname_free(&owner);
		return NULL;
	}

	printf("Reading type from position %zu\n", *pos);

	uint16_t type = adns_wire_read_u16(wire + *pos);
	uint16_t rclass = adns_wire_read_u16(wire + *pos + 2);
	uint32_t ttl = adns_wire_read_u32(wire + *pos + 4);

	struct adns_rrset *rrset = adns_rrset_new(owner, type, rclass, ttl);
	if (rrset == NULL) {
		adns_dname_free(&owner);
		return NULL;
	}

	uint16_t rdlength = adns_wire_read_u16(wire + *pos + 8);

	printf("Read RR header: type %u, class %u, ttl %u, rdlength %u\n", 
			rrset->type, rrset->rclass, rrset->ttl, rdlength);

	*pos += ADNS_RR_HEADER_SIZE;

	if (size - *pos < rdlength) {
		printf("Malformed RR: Not enough data to parse RR"
		           " RDATA (size: %zu, position: %zu).\n", size, *pos);
		adns_rrset_deep_free(rrset);
		return NULL;
	}

	if (rdlength == 0) {
		return rrset;
	}

	return rrset;
}

/* This function is never used now, maybe we can delete it */
int query_parse_additional(struct adns_packet *query, const uint8_t *wire,
		size_t *pos, size_t size)
{
	int ret;
	struct adns_rrset *rrset;

	rrset = query_parse_rr(wire, pos, size);
	if (rrset == NULL)
		return -ESRCH;

	/*
	query->additional = rrset;
	query->ar_rrsets++;
	*/

	// Now convert additioanl rrset into opt rr
	if (adns_rrset_get_type(rrset) != ADNS_RRTYPE_OPT)
		return -1;

	// fill edns(opt) field
	ret = adns_edns_new_from_rr(&query->opt_rr, rrset);	
	if (ret < 0)
		return -1;

	return 0;
}

