
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "rte_core.h"

#include "dname.h"
#include "consts.h"
#include "errcode.h"
#include "tolower.h"
#include "utils.h"
#include "wire.h"


int adns_dname_size(const adns_dname_t *name)
{
    if (unlikely(name == NULL))
        return -EINVAL;

    /* Count name size without terminal label. */
    int len = 0;
    while (*name != '\0') {
        /* Compression pointer is 2 octets. */
        if(adns_wire_is_pointer(name)) {
            return len + 2;
        }

        uint8_t lblen = *name + 1;
        len += lblen;
        name += lblen;
    }

    return len + 1;
}

int adns_dname_labels(const uint8_t *name)
{
    if (name == NULL)
        return ADNS_EINVAL;

    uint8_t count = 0;
    while (*name != '\0') {
        ++count;
        name = adns_wire_next_label(name);
        if (!name)
            return ADNS_EMALF;
    }
    return count;
}

static int adns_label_is_equal(const uint8_t *lb1, const uint8_t *lb2)
{
    return (*lb1 == *lb2) && memcmp(lb1 + 1, lb2 + 1, *lb1) == 0;
}

char *adns_dname_to_str(const adns_dname_t *name)
{
	uint32_t i;

	if (name == NULL)
		return NULL;

	/*! \todo Supply packet. */
	/*! \todo Write to static buffer? */
	// Allocate space for dname string + 1 char termination.
	int dname_size = adns_dname_size(name);
	size_t alloc_size = dname_size + 1;
	char *res = malloc(alloc_size);
	if (res == NULL) {
		return NULL;
	}

	uint8_t label_len = 0;
	size_t  str_len = 0;

	for (i = 0; i < dname_size; i++) {
		uint8_t c = name[i];

		// Read next label size.
		if (label_len == 0) {
			label_len = c;

			// Write label separation.
			if (str_len > 0 || dname_size == 1) {
				res[str_len++] = '.';
			}

			continue;
		}

		if (isalnum(c) != 0 || c == '-' || c == '_' || c == '*' ||
		    c == '/') {
			res[str_len++] = c;
		} else if (ispunct(c) != 0) {
			// Increase output size for \x format.
			alloc_size += 1;
			char *extended = realloc(res, alloc_size);
			if (extended == NULL) {
				free(res);
				return NULL;
			}
			res = extended;

			// Write encoded character.
			res[str_len++] = '\\';
			res[str_len++] = c;
		} else {
			// Increase output size for \DDD format.
			alloc_size += 3;
			char *extended = realloc(res, alloc_size);
			if (extended == NULL) {
				free(res);
				return NULL;
			}
			res = extended;

			// Write encoded character.
			int ret = snprintf(res + str_len, alloc_size - str_len,
			                   "\\%03u", c);
			if (ret <= 0 || ret >= alloc_size - str_len) {
				free(res);
				return NULL;
			}

			str_len += ret;
		}

		label_len--;
	}

	// String_termination.
	res[str_len] = 0;

	return res;
}

adns_dname_t *adns_dname_from_str(const char *name, unsigned len)
{
	if (name == NULL || len == 0 || len > ADNS_DNAME_MAXLEN) {
		return NULL;
	}

	/* Estimate wire size for special cases. */
	unsigned wire_size = len + 1;
	if (name[0] == '.' && len == 1) {
		wire_size = 1; /* Root label. */
		len = 0;      /* Do not parse input. */
	} else if (name[len - 1] != '.') {
		++wire_size; /* No FQDN, reserve last root label. */
	}

	/* Create wire. */
	uint8_t *wire = malloc(wire_size * sizeof(uint8_t));
	if (wire == NULL)
		return NULL;
	*wire = '\0';

	/* Parse labels. */
	const uint8_t *ch = (const uint8_t *)name;
	const uint8_t *np = ch + len;
	uint8_t *label = wire;
	uint8_t *w = wire + 1; /* Reserve 1 for label len */
	while (ch != np) {
		if (*ch == '.') {
			/* Zero-length label inside a dname - invalid. */
			if (*label == 0) {
				free(wire);
				return NULL;
			}
			label = w;
			*label = '\0';
		} else {
			*w = *ch;
			*label += 1;
		}
		++w;
		++ch;
	}

	/* Check for non-FQDN name. */
	if (*label > 0) {
		*w = '\0';
	}

	return wire;
}

int adns_dname_to_lower(adns_dname_t *name)
{
	uint8_t i;
	if (name == NULL)
		return ADNS_EINVAL;

	/*! \todo Faster with \xdfdf mask. */
	while (*name != '\0') {
		for (i = 0; i < *name; ++i)
			name[1 + i] = adns_tolower(name[1 + i]);
		name = (uint8_t *)adns_wire_next_label(name);
		if (name == NULL) {
			return ADNS_EINVAL;
		}
	}

	return ADNS_EOK;
}

bool adns_dname_is_sub(const adns_dname_t *sub, const adns_dname_t *domain)
{
	if (sub == domain)
		return false;

	/* Count labels. */
	if (sub == NULL || domain == NULL)
		return false;
	int sub_l = adns_dname_labels(sub);
	int domain_l = adns_dname_labels(domain);

	/* Subdomain must have more labels as parent. */
	if (sub_l <= domain_l)
		return false;

	/* Align end-to-end to common suffix. */
	int common = adns_dname_align(&sub, sub_l, &domain, domain_l);

	/* Compare common suffix. */
	while(common > 0) {
		/* Compare label. */
		if (!adns_label_is_equal(sub, domain))
			return false;
		/* Next label. */
		sub = adns_wire_next_label(sub);
		domain = adns_wire_next_label(domain);
		--common;
	}
	return true;
}

bool adns_dname_is_wildcard(const adns_dname_t *name)
{
	if (name == NULL)
		return false;
	return name[0] == 1 && name[1] == '*';
}


void adns_dname_free(adns_dname_t **name)
{
	if (name == NULL || *name == NULL)
		return;

	free(*name);
	*name = NULL;
}


static int adns_dname_check(const adns_dname_t *dname)
{
	if (dname == NULL)
		return -1;

	int i;
	int name_len = 1; /* Keep \x00 terminal label in advance. */
	adns_dname_t *name = (adns_dname_t *)dname;

	if (*name == '\0')
		return -1;

	while (*name != '\0') {
		/* Check label length (maximum 63 bytes allowed). */
		if (*name > 63)
			return -1;

		/* Check if there's enough space. */
		int lblen = *name + 1;
		for (i = 1; i < lblen; i++) {
			if (isalpha(name[i]) || isdigit(name[i]) || name[i] == '-' ||
					name[i] == '_')
				continue;
			return -1;
		}

		if (name_len + lblen > 253)
			return -1;
		/* Update wire size only for noncompressed part. */
		name_len += lblen;
		/* Hop to next label. */
		name += lblen;
	}

	return 0;
}


int adns_dname_cmp_wire(const adns_dname_t *d1, const adns_dname_t *d2)
{
    int len = 0;
    int ret = 0;
    
    /* This would be hard to catch since -1 is a good result, assert instead. */
    if (d1 == NULL || d2 == NULL){
        return ADNS_EINVAL;
    }

    //d1 is query name,so check here.d2 is the name save in the memory, it's checked in the adns_adm.
    if (adns_dname_check(d1) < 0){
        return -1;
    }

    int len1 = strlen((const char *)d1);
    int len2 = strlen((const char *)d2);
    len = len1 - len2;
    if(len >= 0){
        ret = memcmp(d1+len, d2, len2);
        if ((ret != 0) || (len == 0)) {
            return ret;
        }
        return 1;
    }else{
        len = -len;
        ret = memcmp(d1, d2+len, len1);
        if (ret != 0) {
            return ret;
        }
        return -1;
    }
    
}

int adns_dname_cmp(const adns_dname_t *d1, const adns_dname_t *d2)
{
    return adns_dname_cmp_wire(d1, d2);
}


bool adns_dname_is_equal(const adns_dname_t *d1, const adns_dname_t *d2)
{
	/*! \todo Could be implemented more efficiently, check profile first. */
	return (adns_dname_cmp(d1, d2) == 0);
}

int adns_dname_align(const uint8_t **d1, uint8_t d1_labels,
		const uint8_t **d2, uint8_t d2_labels)
{
	unsigned j;

	if (d1 == NULL || d2 == NULL)
		return ADNS_EINVAL;

	for (j = d1_labels; j < d2_labels; ++j)
		*d2 = adns_wire_next_label(*d2);

	for (j = d2_labels; j < d1_labels; ++j)
		*d1 = adns_wire_next_label(*d1);

	return (d1_labels < d2_labels) ? d1_labels : d2_labels;
}



int adns_dname_lf(uint8_t *dst, const adns_dname_t *src)
{
	if (dst == NULL || src == NULL)
		return ADNS_EINVAL;

	uint8_t *len = dst++;
	*len = '\0';
	*dst = '\0';
	const uint8_t* l = src;

	if (adns_dname_check(src) < 0)
		return -1;

	/*! \todo This could be made as offsets to pkt? */
	const uint8_t* lstack[ADNS_DNAME_MAXLEN];
	const uint8_t **sp = lstack;
	while(*l != 0) { /* build label stack */
		*sp++ = l;
		l = l + l[0] + sizeof(uint8_t);
		//l = adns_wire_next_label(l, pkt);
	}
	while(sp != lstack) {          /* consume stack */
		l = *--sp; /* fetch rightmost label */
		memcpy(dst, l+1, *l);  /* write label */
		dst += *l;
		*dst++ = '\0';         /* label separator */
		*len += *l + 1;
	}

	/* root label special case */
	if (*len == 0)
		*len = 1; /* \x00 */

	return ADNS_EOK;
}


int adns_dname_prefix(adns_dname_t *name, char * dst)
{
	uint32_t j = 0;
    char * start = name;
    char * end = 0;
    
	while (*name != '\0') {
        j++;

        if ( 2==j ) {
            end = start;
        } else if (j>2) {
		    end = adns_wire_next_label(end);
        }

		name = (uint8_t *)adns_wire_next_label(name);
		if (name == NULL) {
            break;
		}
	}

    if (end && (end!=start)) {
        memcpy(dst, start, end-start);
        dst[end-start] = 0;
	    return ADNS_EOK;
    } 
    else {
	    return -1;
    }
}
