#ifndef _ADNS_RRSET_H_
#define _ADNS_RRSET_H_


#include <stdint.h>
#include <stdbool.h>

#include "dname.h"
#include "adns_conf.h"
#include "adns_types.h"
#include "list.h"
#include "descriptor.h"


struct adns_rdata {
    struct list_head list;
	adns_weight_t cw;	                /* current weight */
	uint16_t len;
	uint8_t *data;
}__attribute__((packed));


struct adns_rdata_ctl {
    struct list_head list;
    adns_weight_t tw;	/* total weight */
    uint16_t rdata_count;
    uint8_t schedule_mode; /* schedule mode of rrset's view */
}__attribute__((packed));


struct adns_rrset {
	adns_type_t type;
	adns_rclass_t rclass;
    adns_ttl_t ttl;
    struct adns_rdata_ctl default_rdata;
	struct adns_rdata_ctl *ctl_rdata;    /* view: 0 ~ g_view_max_num */
	struct adns_rdata_ctl *private_ctl_rdata; /* private route: 0 ~ g_private_route_per_zone_max_num*/
	uint8_t default_ns;                  /* if set, indicating the rrset is default NS rrset */
	uint32_t ref_count;                  /* reference count of the NS rdata */
}__attribute__((packed));

// adns rrsig rdata structure
typedef struct adns_rrsig_rdata {
    uint16_t      covered;       // rrset type that rrsig covered
    uint8_t       algorithm;     // sign algorithm
    uint8_t       labels;        // rrset owner label count
    uint32_t      original_ttl;  // rrset original ttl
    uint32_t      time_expire;   // signature expire timestamp
    uint32_t      time_signed;   // signature inception timestamp
    uint16_t      key_id;        // ZKS's key tag
    uint8_t       signer[0];     // signature content
} __attribute__((packed)) adns_rrsig_rdata;

#define RRSIG_DATA_MAX_LEN (sizeof(adns_rrsig_rdata) + ADNS_DNAME_MAXLEN + DNS_SIG_ECDSA256SIZE)
// RRsig rr: name pointer + (type class ttl rdlen) + rrsig_rdata + signer(zone name uncompressed) + signature
#define RRSIG_RR_LEN(signer) ( 2 + ADNS_RR_HEADER_SIZE + sizeof(adns_rrsig_rdata) + (signer)->name_len + DNS_SIG_ECDSA256SIZE )


/* default NS list hash */
struct adns_ns_list_hash {
	struct list_head list;
	uint32_t size;
}__attribute__((packed));

/* default NS list element */
struct adns_ns_list_elem {
	struct list_head list;
	struct adns_rdata *ns_rdata;           /* NS rdata pointer */
	uint32_t ttl;                          /* TTL of NS */
	uint8_t unchanged;                     /* If set, indicating that this NS is unchanged while reloading NS list file */
	uint8_t fresh;                         /* If set, indicating that this NS is freshly added, only set in reload process */
	uint32_t ns_group_id;                  /* The id of NS group to which the NS belongs */
}__attribute__((packed));

/* NS group list file path */
extern char *g_ns_list_file;
extern struct adns_ns_list_hash *g_ns_tbl;
extern struct adns_rrset** g_ns_rrsets;

typedef enum {
	ADNS_RRSET_COMPARE_PTR,
	ADNS_RRSET_COMPARE_HEADER,
	ADNS_RRSET_COMPARE_WHOLE
} adns_rrset_compare_type_t;


#ifdef __cplusplus
extern "C" {
#endif

struct adns_rrset *adns_rrset_new(adns_type_t type, adns_rclass_t rclass, adns_ttl_t ttl);
void adns_rrset_deep_free(struct adns_rrset *rrset);
uint8_t *adns_rrset_create_rdata(struct adns_rdata_ctl *rdata_ctl, const uint16_t size, adns_weight_t weight, adns_type_t type);
int adns_rrset_add_rdata(struct adns_rdata_ctl *rdata_ctl, const uint8_t *rdata, uint16_t size, adns_weight_t weight, const char *original_rdata, adns_type_t type);
int adns_rrset_edit_rdata(struct adns_rdata_ctl *rdata_ctl, const uint8_t *rdata, int rdata_len, adns_weight_t weight, const char *original_rdata);
struct adns_rdata_ctl* adns_rrset_get_rdata_ctl(struct adns_rrset *rrset, adns_viewid_t view_id);
struct adns_rdata_ctl* adns_rrset_get_private_rdata_ctl(struct adns_rrset *rrset, adns_private_route_id_t private_route_id);
struct adns_rdata_ctl* adns_rrset_new_rdata_ctl(struct adns_rrset *rrset, adns_viewid_t view_id);
struct adns_rdata_ctl* adns_rrset_new_private_rdata_ctl(struct adns_rrset *rrset, adns_private_route_id_t private_route_id);
void adns_rrset_del_rdata(struct adns_rdata_ctl *rdata_ctl, const char *rdata, int rdata_len, const char *original_rdata, adns_type_t type);
void adns_rrset_cleanup_rdatas_for_ctl(struct adns_rdata_ctl *rdata_ctl, adns_type_t type);
int adns_rrset_check_rdata_exist(struct adns_rrset *rrset);
int adns_rrset_check_rdata_exist_in_view(struct adns_rrset *rrset, adns_viewid_t view_id);
int adns_rrset_check_rdata_exist_in_private_route(struct adns_rrset *rrset, adns_private_route_id_t private_route_id);
int rrset_init(void);
void rrset_cleanup(void);

struct adns_rdata *rdata_alloc(adns_type_t type);
void rdata_free(struct adns_rdata *rdata, adns_type_t type);

int ns_list_init(void);
struct adns_ns_list_hash* ns_list_load(int reload);
struct adns_ns_list_elem* ns_list_lookup(struct adns_ns_list_hash *ns_tbl, uint8_t *ns_name, uint8_t ns_name_len, uint32_t ttl);
int ns_list_tbl_merge(struct adns_ns_list_hash *old_ns_tbl, struct adns_ns_list_hash *new_ns_tbl);
void ns_list_recover(struct adns_ns_list_hash *old_ns_tbl);
void ns_list_deep_free(struct adns_ns_list_hash *ns_tbl);
void ns_rrsets_free(struct adns_rrset** ns_rrsets);

#ifdef __cplusplus
}
#endif

#endif
