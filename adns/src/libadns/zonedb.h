#ifndef _ADNS_ZONEDB_H_
#define _ADNS_ZONEDB_H_


#include <stdio.h>
#include <stdlib.h>
#include <rte_malloc.h>


#include "dname.h"
#include "list.h"
#include "zone.h"


struct zone_hash {
    struct list_head list;
    uint32_t size;
};


struct adns_zonedb {
    struct zone_hash zone_tbl[ADNS_ZONEDB_HASH_SIZE];
    char name[ADNS_ZONEDB_NAMELEN];
    int zone_count;
};


typedef struct adns_zonedb adns_zonedb_t;
extern struct adns_zonedb *g_datacore_db;
extern int * g_p_zone_lbs_max;


#ifdef __cplusplus
extern "C" {
#endif

struct adns_zone *adns_zonedb_lookup_exact(const struct adns_zonedb *db, const adns_dname_t *zone_name);
struct adns_zone *adns_zonedb_lookup(const struct adns_zonedb *db, const adns_dname_t *zone_name);
int adns_zonedb_add_zone(struct adns_zonedb *db, struct adns_zone *zone);
int adns_zonedb_del_zone(struct adns_zonedb *db, const adns_dname_t *zone_name);
struct adns_zone **adns_zonedb_list(const struct adns_zonedb *zonedb);
int adns_zonedb_soa_to_str(const struct adns_zone *zone, char *buf, size_t maxlen);
int adns_zonedb_dump(struct adns_zonedb *zonedb, FILE *fp, const char *zone_name, const char *domain_name, uint8_t custom_view, adns_viewid_t view_id, uint16_t dump_all, char *err);
int adns_zonedb_init();
void adns_zonedb_cleanup();
int dump_caa_rdata(char *buf, int len, struct adns_rdata *rdata);
int adns_zonedb_get_zone(struct adns_zonedb *db, const char * name, struct adns_zone ** p_zone, char *err);

#ifdef __cplusplus
}
#endif

#endif


