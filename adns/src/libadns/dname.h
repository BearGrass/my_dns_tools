#ifndef _ADNS_DNAME_H_
#define _ADNS_DNAME_H_


#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

typedef uint8_t adns_dname_t;

#ifdef __cplusplus 
extern "C" { 
#endif

int adns_dname_size(const adns_dname_t *name);
int adns_dname_labels(const uint8_t *name);
char *adns_dname_to_str(const adns_dname_t *name);
adns_dname_t *adns_dname_from_str(const char *name, unsigned len);
int adns_dname_to_lower(adns_dname_t *name);
bool adns_dname_is_sub(const adns_dname_t *sub, const adns_dname_t *domain);
bool adns_dname_is_wildcard(const adns_dname_t *name);
void adns_dname_free(adns_dname_t **name);
bool adns_dname_is_equal(const adns_dname_t *d1, const adns_dname_t *d2);
int adns_dname_align(const uint8_t **d1, uint8_t d1_labels,
		const uint8_t **d2, uint8_t d2_labels);
int adns_dname_lf(uint8_t *dst, const adns_dname_t *src);

#ifdef __cplusplus 
}
#endif

#endif

