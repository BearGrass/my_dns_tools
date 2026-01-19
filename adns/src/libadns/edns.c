
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include "descriptor.h"
#include "rrset.h"
#include "edns.h"


enum adns_edns_consts {
	/*! \brief Mask for the DO bit. */
	ADNS_EDNS_DO_MASK = (uint16_t)0x8000,
	/*! \brief Step for allocation of space for option entries. */
	ADNS_EDNS_OPTION_STEP = 1
};

adns_opt_rr_t *adns_edns_new(void)
{
	adns_opt_rr_t *opt_rr = (adns_opt_rr_t *)malloc(sizeof(adns_opt_rr_t));
	memset(opt_rr, 0, sizeof(adns_opt_rr_t));

	opt_rr->size = EDNS_MIN_SIZE;
	opt_rr->option_count = 0;
	opt_rr->options_max = 0;

	opt_rr->ext_rcode = 0;
	opt_rr->flags = 0;
	opt_rr->version = 0;

	return opt_rr;
}

int adns_edns_new_from_rr(adns_opt_rr_t *opt_rr, struct adns_rrset *rrset)
{
	if (opt_rr == NULL || rrset == NULL
	    || adns_rrset_get_type(rrset) != ADNS_RRTYPE_OPT) {
		return -EINVAL;
	}

	printf("Parsing payload.\n");
	// class <--> payload
	opt_rr->payload = adns_rrset_get_class(rrset);

	// the TTL has switched bytes
	uint32_t ttl;
	printf("TTL: %u\n", adns_rrset_get_ttl(rrset));
	adns_wire_write_u32((uint8_t *)&ttl, adns_rrset_get_ttl(rrset));
	// first byte of TTL is extended RCODE
	printf("TTL: %u\n", ttl);
	memcpy(&opt_rr->ext_rcode, &ttl, 1);
	printf("Parsed extended RCODE: %u.\n", opt_rr->ext_rcode);
	// second is the version
	memcpy(&opt_rr->version, (const uint8_t *)(&ttl) + 1, 1);
	printf("Parsed version: %u.\n", opt_rr->version);
	// third and fourth are flags
	opt_rr->flags = adns_wire_read_u16((const uint8_t *)(&ttl) + 2);
	printf("Parsed flags: %u.\n", opt_rr->flags);
	// size of the header, options are counted elsewhere
	opt_rr->size = 11;

	printf("EDNS created.\n");

	return 0;
}

uint16_t adns_edns_get_payload(const adns_opt_rr_t *opt_rr)
{
	return opt_rr->payload;
}

void adns_edns_set_payload(adns_opt_rr_t *opt_rr, uint16_t payload)
{
	opt_rr->payload = payload;
}

uint8_t adns_edns_get_ext_rcode(const adns_opt_rr_t *opt_rr)
{
	return opt_rr->ext_rcode;
}

void adns_edns_set_ext_rcode(adns_opt_rr_t *opt_rr, uint8_t ext_rcode)
{
	opt_rr->ext_rcode = ext_rcode;
}

uint8_t adns_edns_get_version(const adns_opt_rr_t *opt_rr)
{
	return opt_rr->version;
}

void adns_edns_set_version(adns_opt_rr_t *opt_rr, uint8_t version)
{
	opt_rr->version = version;
}

uint16_t adns_edns_get_flags(const adns_opt_rr_t *opt_rr)
{
	return opt_rr->flags;
}

int adns_edns_do(const adns_opt_rr_t *opt_rr)
{
	if (opt_rr == NULL) {
		return -EINVAL;
	}

	return (opt_rr->flags & ADNS_EDNS_DO_MASK);
}

void adns_edns_set_do(adns_opt_rr_t *opt_rr)
{
	if (opt_rr == NULL) {
		return;
	}

	opt_rr->flags |= ADNS_EDNS_DO_MASK;
}

int adns_edns_add_option(adns_opt_rr_t *opt_rr, uint16_t code,
		uint16_t length, const uint8_t *data)
{
	if (opt_rr == NULL) {
		return -EINVAL;
	}

	if (opt_rr->option_count == opt_rr->options_max) {
		adns_opt_option_t *options_new = (adns_opt_option_t *)calloc(
				(opt_rr->options_max + ADNS_EDNS_OPTION_STEP),
				sizeof(adns_opt_option_t));
		memcpy(options_new, opt_rr->options,
				opt_rr->option_count * sizeof(adns_opt_option_t));

		adns_opt_option_t *old_options = opt_rr->options;
		opt_rr->options = options_new;
		opt_rr->options_max += ADNS_EDNS_OPTION_STEP;
		free(old_options);
	}

	printf("Adding option.\n");
	printf("Code: %u, Length: %u, Data: %p\n", code, length, data);

	opt_rr->options[opt_rr->option_count].data = (uint8_t *)malloc(length);
	memcpy(opt_rr->options[opt_rr->option_count].data, data, length);

	opt_rr->options[opt_rr->option_count].code = code;
	opt_rr->options[opt_rr->option_count].length = length;

	++opt_rr->option_count;
	opt_rr->size += 4 + length;

	return 0;
}

int adns_edns_has_option(const adns_opt_rr_t *opt_rr, uint16_t code)
{
	if (opt_rr == NULL) {
		return 0;
	}

	int i = 0;
	while (i < opt_rr->option_count && opt_rr->options[i].code != code) {
		++i;
	}

	//assert(i >= opt_rr->option_count || opt_rr->options[i].code == code);
	if((i < opt_rr->option_count) || (opt_rr->options[i].code != code)){
            return 0;
        }

	return (i < opt_rr->option_count);
}

int adns_edns_to_wire(const adns_opt_rr_t *opt_rr, uint8_t *wire,
		size_t max_size)
{
	int i;

	if (opt_rr == NULL) {
		return -EINVAL;
	}

	//assert(EDNS_MIN_SIZE <= (int)max_size);
	if(EDNS_MIN_SIZE > (int)max_size){
            return -1;
        }

	if ((int)max_size < opt_rr->size) {
		printf("Not enough place for OPT RR wire format.\n");
		return -ENOSPC;
	}

	uint8_t *pos = wire;

	printf("Putting OPT RR to the wire format. Size: %d, position: %zu\n",
			opt_rr->size, (size_t)(pos - wire));

	*(pos++) = 0;
	adns_wire_write_u16(pos, ADNS_RRTYPE_OPT);
	pos += 2;
	adns_wire_write_u16(pos, opt_rr->payload);
	pos += 2;
	*(pos++) = opt_rr->ext_rcode;
	*(pos++) = opt_rr->version;
	adns_wire_write_u16(pos, opt_rr->flags);
	pos += 2;

	printf("Leaving space for RDLENGTH at pos %zu\n", (size_t)(pos - wire));

	uint8_t *rdlen = pos;
	uint16_t len = 0;
	pos += 2;

	// OPTIONs
	for (i = 0; i < opt_rr->option_count; ++i) {
		printf("Inserting option #%d at pos %zu\n", i, (size_t)(pos - wire));
		adns_wire_write_u16(pos, opt_rr->options[i].code);
		pos += 2;
		adns_wire_write_u16(pos, opt_rr->options[i].length);
		pos += 2;
		memcpy(pos, opt_rr->options[i].data, opt_rr->options[i].length);
		pos += opt_rr->options[i].length;
		len += 4 + opt_rr->options[i].length;
	}

	printf("Final pos %zu\n", (size_t)(pos - wire));

	adns_wire_write_u16(rdlen, len);

	return opt_rr->size;
}

int adns_edns_size(adns_opt_rr_t *opt_rr)
{
	if (opt_rr == NULL) {
		return -EINVAL;
	}

	return opt_rr->size;
}

void adns_edns_free_options(adns_opt_rr_t *opt_rr)
{
	int i;

	if (opt_rr->option_count > 0) {
		/* Free the option data, if any. */
		for (i = 0; i < opt_rr->option_count; i++) {
			adns_opt_option_t *option = &(opt_rr->options[i]);
			free(option->data);
		}
		free(opt_rr->options);
	}
}

void adns_edns_free(adns_opt_rr_t *opt_rr)
{
	if (opt_rr == NULL) {
		return;
	}

	adns_edns_free_options(opt_rr);

	free(opt_rr);
	opt_rr = NULL;
}

