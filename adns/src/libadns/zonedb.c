#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <rte_lcore.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>


#include "log.h"
#include "errcode.h"
#include "adns_share.h"
#include "adns_conf.h"
#include "descriptor.h"
#include "wire.h"
#include "zonedb.h"
#include "zone.h"
#include "node.h"
#include "rrset.h"
#include "domain_hash.h"
#include "murmurhash3.h"
#include "libadns.h"


#define ADNS_LINE_MAX_LEN            1024
#define ADNS_CMD_RESP_ERR_LEN        256


struct adns_zonedb *g_datacore_db =  NULL;
int * g_p_zone_lbs_max = 0;
extern adns_weight_t g_large_weight;

extern char *view_id_to_name(int id);

static void cmd_set_err(char *str, const char *fmt, ...)
{
    va_list ap;

    if (str == NULL) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(str, ADNS_CMD_RESP_ERR_LEN, fmt, ap);
    va_end(ap);
}


static inline void update_global_zone_lbs_max(int label)
{
    if (label > *g_p_zone_lbs_max) {
        *g_p_zone_lbs_max = label;
    }
}


static struct adns_zone *__adns_zonedb_lookup(const struct adns_zonedb *db, 
    const adns_dname_t *zone_name, int zone_name_len)
{
    uint32_t hash;
    struct adns_zone *zone;
    const struct list_head *h_list;
    const struct zone_hash *zone_tbl, *h_node;
        
    if (db == NULL || zone_name == NULL) {
        return NULL;
    }

    zone_tbl = db->zone_tbl;
    if (zone_tbl == NULL) {
        return NULL;
    }

    hash = mm3_hash((const char *)zone_name, zone_name_len);
    h_node = &zone_tbl[hash & ADNS_ZONEDB_HASH_MASK];
    h_list = &(h_node->list);

    list_for_each_entry(zone, h_list, list) {
        if (zone->name_len == zone_name_len
            && !memcmp(zone_name, zone->name, zone_name_len)) {
            return zone;
        }
    }

    return NULL;
}


struct adns_zone *adns_zonedb_lookup_exact(const struct adns_zonedb *db, const adns_dname_t *zone_name)
{
    int zone_name_len;
    struct adns_zone *zone;

    if (db == NULL) {
        return NULL;
    }

    zone_name_len = adns_dname_size(zone_name);
    if (zone_name_len < 1) {
        return NULL;
    }

    zone = __adns_zonedb_lookup(db, zone_name, zone_name_len);
    if (zone == NULL) {
        return NULL;
    }

    return zone;
}


struct adns_zone *adns_zonedb_lookup(const struct adns_zonedb *db, 
                                     const adns_dname_t *zone_name)
{
    int zone_lbs, name_size;  
    struct adns_zone *zone;

    if (db == NULL || zone_name == NULL) {
        return NULL;
    }

    zone_lbs = adns_dname_labels(zone_name);
    while (zone_lbs > *g_p_zone_lbs_max) {
        zone_name = adns_wire_next_label(zone_name);
        zone_lbs--;
    }

    //name_size = qname_len;
    name_size = adns_dname_size(zone_name);
    while (name_size > 0) {
        zone = __adns_zonedb_lookup(db, zone_name, name_size);
        if (zone != NULL) {
            return zone;
        }

        name_size -= zone_name[0] + 1;
        zone_name = adns_wire_next_label(zone_name);
    }

    return NULL;
}


static int __adns_zonedb_add(struct adns_zonedb *db, struct adns_zone *zone,
    const adns_dname_t *dname, int dname_len)
{
    uint32_t hash;
    struct adns_zone *zone_item;
    struct list_head *h_list;
    struct zone_hash *zone_tbl, *h_node;    
    
    if (db == NULL || zone == NULL || dname == NULL) {
        return -1;
    }

    zone_tbl = db->zone_tbl;
    if (zone_tbl == NULL) {
        return -2;
    }

    hash = mm3_hash((const char *)dname, dname_len);
    h_node = &zone_tbl[hash & ADNS_ZONEDB_HASH_MASK];
    h_list = &(h_node->list);

    list_for_each_entry(zone_item, h_list, list) {
        if (zone_item->name_len == dname_len
            && !memcmp(zone_item->name, dname, dname_len)){
            log_server_warn(rte_lcore_id(), "[%s]: zone %s is existed\n", __FUNCTION__, dname);
            return 0;
        }
    }
    
    list_add(&(zone->list), h_list);
    h_node->size++;
    db->zone_count++;
    
    update_global_zone_lbs_max(zone->domain_max_label);
    
    return 0;
}


int adns_zonedb_add_zone(struct adns_zonedb *db, struct adns_zone *zone)
{
    if (db == NULL || zone == NULL || zone->name == NULL) {
        return -1;
    }

    return __adns_zonedb_add(db, zone, zone->name, zone->name_len);
}


int adns_zonedb_del_zone(struct adns_zonedb *db, const adns_dname_t *zone_name)
{
    int name_len;
    uint32_t hash;
    struct adns_zone *zone, *zone_nxt;
    struct list_head *h_list;
    struct zone_hash *zone_tbl, *h_node;
    
    if (db == NULL || zone_name == NULL) {
        return -1;
    }
  
    zone_tbl = db->zone_tbl;
    if (zone_tbl == NULL) {
        return -2;
    }

    name_len = adns_dname_size(zone_name);
    hash = mm3_hash((const char *)zone_name, name_len);
    h_node = &zone_tbl[hash & ADNS_ZONEDB_HASH_MASK];
    h_list = &(h_node->list);

    list_for_each_entry_safe(zone, zone_nxt, h_list, list) {
        if (zone->name_len == name_len
            && !memcmp(zone->name, zone_name, name_len)) {
              
            list_del(&zone->list);
            h_node->size--;
            db->zone_count--;
            return 0;
        }
    }

    return 0;
}


struct adns_zone **adns_zonedb_list(const struct adns_zonedb *zonedb)
{
    int i, z_count = 0;   
    struct adns_zone **z_list;
    struct adns_zone *zone;
    const struct list_head *h_list;   
    const struct zone_hash *zone_tbl, *h_node;
    
    zone_tbl = zonedb->zone_tbl;
    if (zone_tbl == NULL) {
        return NULL;
    }

    z_list = malloc(sizeof(struct adns_zone *) * zonedb->zone_count);
    if (z_list == NULL) {
        return NULL;
    }
  
    for (i = 0; i < ADNS_ZONEDB_HASH_SIZE; i++) {
        h_node = &zone_tbl[i];
        h_list = &(h_node->list);
        
        list_for_each_entry(zone, h_list, list) {
            z_list[z_count++] = zone;
        }
    }

    return z_list;
}


int adns_zonedb_soa_to_str(const struct adns_zone *zone, char *buf, size_t maxlen)
{
    int i, len, total = 0, dname_len;
    char *dname_str, *domain;
    const uint8_t *dname;

    if (zone == NULL || buf == NULL) {
        return -1;
    }

    /*
     * header format: zone name | [region | tunnel | forward | ]TTL | CLASS | TYPE
     */
    dname_str = adns_dname_to_str(zone->name); 
    len = snprintf(buf + total, maxlen - total, "%s %u IN SOA ",
            dname_str, zone->soa.ttl);
    free(dname_str);
    if (len < 0) {
        return -1;
    }
    total += len;

    /*
     * rdata format: primary ns, mail, searial, refresh, retry, expire, minimum
     */
    /* primary */
    dname = zone->soa.data;
    domain = adns_dname_to_str(dname);
    dname_len = adns_dname_size(dname);
    len = snprintf(buf + total, maxlen - total, "%s ", domain);
    free(domain);
    if (len < 0) {
        return -1;  
    }
    total += len;
    
    /* mail */
    dname = dname + dname_len;
    domain = adns_dname_to_str(dname);
    dname_len = adns_dname_size(dname);
    len = snprintf(buf + total, maxlen - total, "%s", domain);
    free(domain);
    if (len < 0) {
        return -1;  
    }
    total += len;
    
    /* serial */
    const uint8_t *pos = (const uint8_t *)dname + dname_len;
    const uint32_t *num32 = (const uint32_t *)pos;
    for (i = 0; i < 5; i++) {
        len = snprintf(buf + total, maxlen - total, " %u", ntohl(*num32));
        if (len < 0) {
            return -1;  
        }
        total += len;
        num32++;
    }
    buf[total++] = '\n';

    return total;
}


static int adns_dump_zone_meta(int fd, const struct adns_zone *zone)
{
    char buf[1024];
    int len;

    if (fd < 0 || zone == NULL) {
        return ADNS_ADMIN_DUMP_ZONE_META_ERROR;
    }
    
    len = adns_zonedb_soa_to_str(zone, buf, 1024);
    if (len < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: Dump zone %s meta failed\n", __FUNCTION__, zone->name);
        return ADNS_ADMIN_DUMP_ZONE_META_ERROR;
    }
  
    write(fd, buf, len);
    return 0;
}


static int adns_dump_rdata_ctl_a(int fd, const struct adns_node *node, const struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, const struct adns_rdata_ctl *rdata_ctl)
{
    int len = 0, total = 0;
    char *dname_str,*view_name, *type_name, rdata_str[64];
    char buf[ADNS_LINE_MAX_LEN];
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    if (custom_view) {
        snprintf(custom_view_name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, view_id);
        view_name = custom_view_name;
    }
    else {
        if (view_id == 0) {
            view_name = "default";            
        }
        else {
            view_name = (char *)view_id_to_name(view_id);
            if (view_name == NULL) {
                free(dname_str);
                return -1;
            }
        }
    }

    type_name = "A";

    len = snprintf(buf, ADNS_LINE_MAX_LEN, "%s %s %u IN %s", dname_str, view_name, rrset->ttl, type_name);

    const struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        if (inet_ntop(AF_INET, rdata->data, rdata_str, 64) == NULL) {
            continue;
        }
        /*
         * RR format: domain | view name | TTL | TYPE | rdata | <weight>
         */
        total = len;
        if(g_large_weight == 0) {
            free(dname_str);
            log_server_error(rte_lcore_id(), "[%s]: g_large_weight is 0 at division\n", __FUNCTION__);
            return -1;
        }
        total += snprintf(buf + len, ADNS_LINE_MAX_LEN - len, " %s %u\n", rdata_str, rdata->cw / g_large_weight);

        write(fd, buf, total);
    }

    free(dname_str);
    return 0;
}


static int adns_dump_rdata_ctl_domain(int fd, const struct adns_node *node, const struct adns_rrset *rrset, const char *type_name, uint8_t custom_view, adns_viewid_t view_id, const struct adns_rdata_ctl *rdata_ctl)
{
    int len = 0, total = 0;
    char *dname_str, *view_name;
    char buf[ADNS_LINE_MAX_LEN];
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    if (custom_view) {
        snprintf(custom_view_name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, view_id);
        view_name = custom_view_name;
    }
    else {
        if (view_id == 0) {
            view_name = "default";            
        }
        else {
            view_name = (char *)view_id_to_name(view_id);
            if (view_name == NULL) {
                free(dname_str);
                return -1;
            }
        }
    }

    len = snprintf(buf, ADNS_LINE_MAX_LEN, "%s %s %u IN %s", dname_str, view_name, rrset->ttl, type_name);

    const struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
		char *rdata_str = adns_dname_to_str((adns_dname_t *)(rdata->data));
        /*
         * RR format: domain | view name | TTL | TYPE | rdata
         */
        total = len;
        if (!strcmp(type_name, "CNAME")) {
            /* CNAME must set weight */
            if(g_large_weight == 0) {
                log_server_error(rte_lcore_id(), "[%s]: g_large_weight is 0 at division\n", __FUNCTION__);
                free(dname_str);
                free(rdata_str);
                return -1;
            }
            total += snprintf(buf + len, ADNS_LINE_MAX_LEN - len, " %s %u\n", rdata_str, rdata->cw / g_large_weight);
        } else {
            total += snprintf(buf + len, ADNS_LINE_MAX_LEN - len, " %s\n", rdata_str);
        }

        write(fd, buf, total);
		free(rdata_str);
    }

    free(dname_str);
    return 0;
}


static int adns_dump_rdata_ctl_mx(int fd, const struct adns_node *node, const struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, const struct adns_rdata_ctl *rdata_ctl)
{
    int len = 0, total = 0;
    char *dname_str,*view_name, *type_name;
    char buf[ADNS_LINE_MAX_LEN];
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    if (custom_view) {
        snprintf(custom_view_name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, view_id);
        view_name = custom_view_name;
    }
    else {
        if (view_id == 0) {
            view_name = "default";            
        }
        else {
            view_name = (char *)view_id_to_name(view_id);
            if (view_name == NULL) {
                free(dname_str);
                return -1;
            }
        }
    }
    
    type_name = "MX";

    len = snprintf(buf, ADNS_LINE_MAX_LEN, "%s %s %u IN %s", dname_str, view_name, rrset->ttl, type_name);

    const struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        uint16_t prefer = ntohs(*(uint16_t *)rdata->data);
        char *rdata_str = adns_dname_to_str((adns_dname_t *)(rdata->data 
                    + sizeof(uint16_t)));

        /*
         * RR format: domain | view name | TTL | TYPE | PREFER | rdata
         */
        total = len;
        total += snprintf(buf + len, ADNS_LINE_MAX_LEN - len, " %u %s\n", prefer, rdata_str);

        write(fd, buf, total);
		free(rdata_str);
    }

    free(dname_str);
    return 0;
}


static int adns_dump_rdata_ctl_txt(int fd, const struct adns_node *node, const struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, const struct adns_rdata_ctl *rdata_ctl)
{
    int len = 0, total = 0;
    char *dname_str,*view_name, *type_name;
    const int buf_size = ADNS_LINE_MAX_LEN + TXT_MAX_SIZE;
    char buf[buf_size];
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    if (custom_view) {
        snprintf(custom_view_name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, view_id);
        view_name = custom_view_name;
    }
    else {
        if (view_id == 0) {
            view_name = "default";            
        }
        else {
            view_name = (char *)view_id_to_name(view_id);
            if (view_name == NULL) {
                free(dname_str);
                return -1;
            }
        }
    }

    type_name = "TXT";

    len = snprintf(buf, buf_size, "%s %s %u IN %s ", dname_str, view_name, rrset->ttl, type_name);

    const struct list_head *h_list = &(rdata_ctl->list);
    uint8_t num;
    int now = 0;
    list_for_each_entry(rdata, h_list, list) {
        /*
         * RR format: domain | view name | TTL | TYPE | rdata | <weight>
         * txt rdata format: num1|string[num1]|...|numN|string[numN]
         */
        total = len;
        now = 0;
        while (now < rdata->len) {
            buf[total++] = '"';
            num = rdata->data[now];
            memcpy(buf + total, rdata->data + now + 1, num);
            total += num;
            now += num + 1;
            buf[total++] = '"';
            buf[total++] = ' ';
        }
        buf[total++] = '\n';
        write(fd, buf, total);
    }

    free(dname_str);
    return 0;
}


static int adns_dump_rdata_ctl_aaaa(int fd, const struct adns_node *node, const struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, const struct adns_rdata_ctl *rdata_ctl)
{
    int len = 0, total = 0;
    char *dname_str,*view_name, *type_name, rdata_str[64];
    char buf[ADNS_LINE_MAX_LEN];
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    if (custom_view) {
        snprintf(custom_view_name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, view_id);
        view_name = custom_view_name;
    }
    else {
        if (view_id == 0) {
            view_name = "default";
        }
        else {
            view_name = (char *)view_id_to_name(view_id);
            if (view_name == NULL) {
                free(dname_str);
                return -1;
            }
        }
    }

    type_name = "AAAA";

    len = snprintf(buf, ADNS_LINE_MAX_LEN, "%s %s %u IN %s", dname_str, view_name, rrset->ttl, type_name);
    free(dname_str);

    const struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        if (inet_ntop(AF_INET6, rdata->data, rdata_str, 64) == NULL) {
            continue;
        }
        /*
         * RR format: domain | view name | TTL | TYPE | rdata | <weight>
         */
        total = len;
        if(g_large_weight == 0) {
            log_server_error(rte_lcore_id(), "[%s]: g_large_weight is 0 at division\n", __FUNCTION__);
            return -1;
        }
        total += snprintf(buf + len, ADNS_LINE_MAX_LEN - len, " %s %u\n", rdata_str, rdata->cw / g_large_weight);

        write(fd, buf, total);
    }

    return 0;
}


int dump_caa_rdata(char *buf, int len, struct adns_rdata *rdata) {
    int total = 0;
    /*
     * CAA format: Flags | Tag | Value
     */
    uint8_t *pos = rdata->data;
    uint8_t caa_flags = *pos;
    int tmp_len = snprintf(buf, len, "%u ", caa_flags);
    if (tmp_len < 0) {
        return -1;
    }
    total += tmp_len;
    ++pos;
    /* Check the needed buffer length for tag and value, (1 space +
     * 1 \n) = (1 flags byte + 1 tag length byte)
     */
    if (total + rdata->len > len) {
        return -2;
    }
    uint8_t tag_len = *pos;
    ++pos;
    memcpy(buf + total, pos, tag_len);
    pos += tag_len;
    total += tag_len;
    buf[total++] = ' ';
    uint16_t value_len = rdata->len - tag_len - 2;
    memcpy(buf + total, pos, value_len);
    total += value_len;
    buf[total++] = '\n';

    return total;
}


static int adns_dump_rdata_ctl_caa(int fd, const struct adns_node *node, const struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, const struct adns_rdata_ctl *rdata_ctl)
{
    int len = 0;
    char *dname_str, *view_name, *type_name;
    const int buf_size = ADNS_LINE_MAX_LEN + CAA_VALUE_LEN_MAX;
    char buf[buf_size];
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);
    
    if (custom_view) {
        snprintf(custom_view_name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, view_id);
        view_name = custom_view_name;
    }
    else {
        if (view_id == 0) {
            view_name = "default";
        }
        else {
            view_name = (char *) view_id_to_name(view_id);
            if (view_name == NULL) {
                free(dname_str);
                return -1;
            }
        }
    }
    type_name = "CAA";

    /*
     * RR format: domain | view name | TTL | TYPE | rdata type | rdata
     */
    len = snprintf(buf, buf_size, "%s %s %u IN %s ", dname_str,
            view_name, rrset->ttl, type_name);
    free(dname_str);

    const struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list)
    {
        int rdata_len = dump_caa_rdata(buf + len, buf_size - len,
                rdata);
        if (rdata_len < 0) {
            return -2;
        }
        write(fd, buf, len + rdata_len);
    }

    return 0;
}


static int adns_dump_rdata_ctl_srv(int fd, const struct adns_node *node, const struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, const struct adns_rdata_ctl *rdata_ctl)
{
    int len = 0, total = 0;
    char *dname_str,*view_name, *type_name;
    char buf[ADNS_LINE_MAX_LEN];
    struct adns_rdata *rdata;
    char custom_view_name[VIEW_NAME_LEN] = {0};

    if (rdata_ctl->rdata_count == 0) {
        return 0;
    }

    dname_str = adns_dname_to_str(node->name);

    if (custom_view) {
        snprintf(custom_view_name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, view_id);
        view_name = custom_view_name;
    }
    else {
        if (view_id == 0) {
            view_name = "default";            
        }
        else {
            view_name = (char *)view_id_to_name(view_id);
            if (view_name == NULL) {
                free(dname_str);
                return -1;
            }
        }
    }

    type_name = "SRV";

    len = snprintf(buf, ADNS_LINE_MAX_LEN, "%s %s %u IN %s", dname_str, view_name, rrset->ttl, type_name);

    const struct list_head *h_list = &(rdata_ctl->list);
    list_for_each_entry(rdata, h_list, list) {
        uint16_t pri = ntohs(*(uint16_t *)rdata->data);
        uint16_t weight = ntohs(*((uint16_t *)rdata->data + 1));
        uint16_t port = ntohs(*((uint16_t *)rdata->data + 2));
        char *rdata_str = adns_dname_to_str((adns_dname_t *)(rdata->data 
    				+ sizeof(uint16_t) * 3));

        /*
         * RR format: domain | view name | TTL | TYPE | rdata | <weight>
         */
        total = len;
        total += snprintf(buf + len, ADNS_LINE_MAX_LEN - len, " %u %u %u %s\n", pri, weight, port, rdata_str);

        write(fd, buf, total);
		free(rdata_str);
    }

    free(dname_str);
    return 0;
}


static int adns_dump_rdata_ctl(int fd, const struct adns_node *node, const struct adns_rrset *rrset, uint8_t custom_view, adns_viewid_t view_id, const struct adns_rdata_ctl *rdata_ctl)
{
    int ret = 0;
    switch (rrset->type) {
        case ADNS_RRTYPE_A:
            ret = adns_dump_rdata_ctl_a(fd, node, rrset, custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_NS:
            ret = adns_dump_rdata_ctl_domain(fd, node, rrset, "NS", custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_CNAME:
            ret = adns_dump_rdata_ctl_domain(fd, node, rrset, "CNAME", custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_PTR:
            ret = adns_dump_rdata_ctl_domain(fd, node, rrset, "PTR", custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_DNAME:
            ret = adns_dump_rdata_ctl_domain(fd, node, rrset, "DNAME", custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_MX:
            ret = adns_dump_rdata_ctl_mx(fd, node, rrset, custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_TXT:
        case ADNS_RRTYPE_SPF:
            ret = adns_dump_rdata_ctl_txt(fd, node, rrset, custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_AAAA:
            ret = adns_dump_rdata_ctl_aaaa(fd, node, rrset, custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_SRV:
            ret = adns_dump_rdata_ctl_srv(fd, node, rrset, custom_view, view_id, rdata_ctl);
            break;
        case ADNS_RRTYPE_CAA:
            ret = adns_dump_rdata_ctl_caa(fd, node, rrset, custom_view, view_id, rdata_ctl);
            break;
        default:
            break;
    }
    return ret;
}

int adns_dump_opt_ctl_domain(int fd, const struct adns_node *node, uint16_t type)
{
    int len = 0;
    char *dname_str;
    char buf[ADNS_LINE_MAX_LEN];

    dname_str = adns_dname_to_str(node->name);

    len = snprintf(buf, ADNS_LINE_MAX_LEN, "%s domain_opt 600 IN %u %u %u\n", dname_str, type, node->A_schedule_mode, node->AAAA_schedule_mode);

    write(fd, buf, len);
    free(dname_str);
    return 0;
}

int adns_dump_opt_ctl_zone(int fd, const struct adns_zone *zone)
{
    int len = 0;
    char *zname_str;
    char buf[ADNS_LINE_MAX_LEN];

    zname_str = adns_dname_to_str(zone->name);

    len = snprintf(buf, ADNS_LINE_MAX_LEN, "%s zone_opt 600 IN ZOPT %u %u %u\n", zname_str, zone->enable_cname_cascade, zone->private_route_enable, zone->wildcard_fallback_enable);

    write(fd, buf, len);
    free(zname_str);
    return 0;
}

static int adns_dump_node(int fd, struct adns_node *node, uint8_t custom_view, adns_viewid_t view_id, uint16_t dump_all, char *err)
{ 
    int i, j, ret = 0;
    struct adns_rdata_ctl *rdata_ctl = NULL;
    struct adns_rrset *rrset = NULL;
    
    if (node == NULL) {
        return ADNS_ADMIN_DUMP_NODE_NULL_ERROR;
    }

    for (i = 0; i < ADNS_RRSET_NUM; i++) {
        rrset = node->rrsets[i];
        if (rrset == NULL) {
            continue; 
        }
        
        if (dump_all) {
            /*add for dump domain opt for pb check, just dump domain with a,4a,cname*/
            if ((dump_all == ADNS_RRTYPE_DS) &&
                    ( (rrset->type == ADNS_RRTYPE_A) 
                    || (rrset->type == ADNS_RRTYPE_AAAA) 
                    || (rrset->type == ADNS_RRTYPE_CNAME) )) {
                if (rrset->default_rdata.rdata_count > 0) {
                    adns_dump_opt_ctl_domain(fd, node, rrset->type);
                }
            }
            /* dump default rdata */
            ret = adns_dump_rdata_ctl(fd, node, rrset, 0, 0, &(rrset->default_rdata));
            if (ret < 0) {
                cmd_set_err(err, "[%s]: Dump node %s failed, type %d, default view\n", __FUNCTION__, node->name, i);
                log_server_warn(rte_lcore_id(), "[%s]: Dump node %s failed, type %d, default view\n", __FUNCTION__, node->name, i);
                return ADNS_ADMIN_DUMP_NODE_RDATA_ERROR;
            }
            /* dump fix view rdata if exist */
            /* NOTE: ctl_rdata index 0 correspond to default rdata_ctrl */
            if (rrset->ctl_rdata != NULL) {
                for (j = 1; j < g_view_max_num; j++) {
                    rdata_ctl = adns_rrset_get_rdata_ctl(rrset, j);
                    if (rdata_ctl == NULL) {
                        continue; 
                    }

                    ret = adns_dump_rdata_ctl(fd, node, rrset, 0, j, rdata_ctl);
                    if (ret < 0) {
                        cmd_set_err(err, "[%s]: Dump node %s failed, type %d, view_id %d\n", __FUNCTION__, node->name, i, j);
                        log_server_warn(rte_lcore_id(), "[%s]: Dump node %s failed, type %d, view_id %d\n", __FUNCTION__, node->name, i, j);
                        return ADNS_ADMIN_DUMP_NODE_RDATA_ERROR;      
                    }
                }
            }
            /* dump custom view rdata if exist */
            if (rrset->private_ctl_rdata != NULL) {
                for (j = 0; j < g_private_route_per_zone_max_num; j ++) {
                    rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, j);
                    if (rdata_ctl == NULL) {
                        continue; 
                    }

                    ret = adns_dump_rdata_ctl(fd, node, rrset, 1, j, rdata_ctl);
                    if (ret < 0) {
                        cmd_set_err(err, "[%s]: Dump node %s failed, type %d, %sview_id %d\n", __FUNCTION__, node->name, i, CUSTOM_VIEW_PREFIX, j);
                        log_server_warn(rte_lcore_id(), "[%s]: Dump node %s failed, type %d, %sview_id %d\n", __FUNCTION__, node->name, i, CUSTOM_VIEW_PREFIX, j);
                        return ADNS_ADMIN_DUMP_NODE_RDATA_ERROR;      
                    }
                }
            }
        } else {
            if (custom_view) {
                rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, view_id);
            }
            else {
                rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
            }
            if (rdata_ctl == NULL) {
                continue; 
            } 
            
            ret = adns_dump_rdata_ctl(fd, node, rrset, custom_view, view_id, rdata_ctl);
            if (ret < 0) {
                cmd_set_err(err, "[%s]: Dump node %s failed, type %d, %sview_id %d\n", __FUNCTION__, node->name, i, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
                log_server_warn(rte_lcore_id(), "[%s]: Dump node %s failed, type %d, %sview_id %d\n", __FUNCTION__, node->name, i, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
                return ADNS_ADMIN_DUMP_NODE_RDATA_ERROR;      
            }
        }
    }
    
    return ret; 
}


static int adns_zone_dump(FILE *fp, const struct adns_zone *zone, const char *domain, uint8_t custom_view, adns_viewid_t view_id, uint16_t dump_all, char * err)
{
    int fd, ret;
    adns_dname_t *dname;
    struct adns_node *node, *node_nxt;
    const struct list_head *h_list;
    const struct node_hash *h_node;

    setvbuf(fp, NULL, _IONBF, 0);
    fd = fileno(fp);

    ret = adns_dump_zone_meta(fd, zone);
    if (ret < 0) {
        return ret; 
    }

    if (!domain || !domain[0]) {
        dump_all = ADNS_RRTYPE_DS; //all for this zone
    }
    if (dump_all) {
        h_node = &(zone->node_tbl);
        h_list = &(h_node->list);
        /*add for dump domain opt for pb check*/
        if (dump_all == ADNS_RRTYPE_DS) {
            adns_dump_opt_ctl_zone(fd, zone);
        }
 
        list_for_each_entry_safe(node, node_nxt, h_list, list) {
            ret = adns_dump_node(fd, node, custom_view, view_id, dump_all, err);
            if (ret < 0) {
                return ret; 
            }               
        }            
    } else {
        dname = adns_dname_from_str(domain, strlen(domain));
        if (dname == NULL) {
            cmd_set_err(err, "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to convert domain %s\n", __FUNCTION__, domain);
            return ADNS_ADMIN_DUMP_DNAME_ERROR;
        }
    
        node = adns_domain_hash_lookup(zone, dname); 
        if (node == NULL) {
            adns_dname_free(&dname);
            cmd_set_err(err, "[%s]: Node %s does not exist\n", __FUNCTION__, domain);
            log_server_warn(rte_lcore_id(), "[%s]: Node %s does not exist\n", __FUNCTION__, domain); 
            return ADNS_ADMIN_DUMP_FIND_NODE_ERROR;      
        }
        
        if (custom_view<=0  && view_id <=0) {
            dump_all = ADNS_RRTYPE_DS; //all for this domain
        }
        ret = adns_dump_node(fd, node, custom_view, view_id, dump_all, err);
        if (ret < 0) {
            adns_dname_free(&dname);
            return ret; 
        }
        adns_dname_free(&dname);
    }
      
    return 0;
}


int adns_zonedb_dump(struct adns_zonedb *zonedb, FILE *fp, const char *zone_name, const char *domain_name, uint8_t custom_view, adns_viewid_t view_id, uint16_t dump_all, char *err)
{
    int i, ret;     
    adns_dname_t *zone_dname = NULL;      
    struct adns_zone *zone;
    struct list_head *h_list; 
    struct zone_hash *zone_tbl, *h_node;
        
    if (dump_all) {
        zone_tbl = zonedb->zone_tbl;
        if (zone_tbl == NULL) {
            return ADNS_ADMIN_DUMP_ZONEDB_TABLE_NULL_ERROR;
        }

        for (i = 0; i < ADNS_ZONEDB_HASH_SIZE; i++) {
            h_node = &zone_tbl[i];
            h_list = &(h_node->list);
            
            list_for_each_entry(zone, h_list, list) {
                ret = adns_zone_dump(fp, zone, NULL, 0, 0, dump_all, err);
                if (ret < 0) {
                    return ret; 
                }
            }
        }   

    } else {
        zone_dname = adns_dname_from_str(zone_name, strlen(zone_name));
        if (zone_dname == NULL) {
            cmd_set_err(err, "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_name);
            log_server_warn(rte_lcore_id(), "[%s]: Failed to convert zone %s\n", __FUNCTION__, zone_name);
            return ADNS_ADMIN_DUMP_CONVERT_ZONE_ERROR;
        }
        
        zone = adns_zonedb_lookup_exact(zonedb, zone_dname);
        if (zone == NULL) {
            adns_dname_free(&zone_dname);
            cmd_set_err(err, "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_name);
            log_server_warn(rte_lcore_id(), "[%s]: Zone %s does not exist\n", __FUNCTION__, zone_name); 
            return ADNS_ADMIN_DUMP_FIND_ZONE_ERROR;
        }
        
        ret = adns_zone_dump(fp, zone, domain_name, custom_view, view_id, dump_all, err);
        if (ret < 0) {
            adns_dname_free(&zone_dname);
            return ret; 
        }
        
        adns_dname_free(&zone_dname);
    }
       
    return 0;
}

int adns_zonedb_get_zone(struct adns_zonedb *db, const char * name, struct adns_zone ** p_zone, char *err)
{
    adns_dname_t *zone_dname;
    struct adns_zone * zone;

    if (db == NULL || name == NULL || p_zone == NULL) {
        cmd_set_err(err, "[%s]: NULL pointer is passed in, FAILURE\n", __FUNCTION__);
        return -1;
    }

    zone_dname = adns_dname_from_str(name, strlen(name));
    if (zone_dname == NULL) {
        cmd_set_err(err, "[%s]: Failed to convert zone %s, FAILURE\n", __FUNCTION__, name);
        return -2;
    }

    zone = adns_zonedb_lookup_exact(db, zone_dname);
    if (NULL == zone) {
        adns_dname_free(&zone_dname);
        cmd_set_err(err, "[%s]: Zone %s does not existed, FAILURE\n", __FUNCTION__, name);
        return -3;
    }

    adns_dname_free(&zone_dname);
    *p_zone = zone;
    return 0;
}

/* Init Function */
static struct adns_zonedb *adns_zonedb_new(const char *name, int socket_id)
{
    int i;
    struct adns_zonedb *db;

    db = rte_zmalloc_socket(name, sizeof(struct adns_zonedb), 0, socket_id);
    if (db == NULL) {
        return NULL;
    }
    snprintf(db->name, ADNS_ZONEDB_NAMELEN, "zonedb_%s", name);
    db->zone_count = 0;

    for (i = 0; i < ADNS_ZONEDB_HASH_SIZE; i++) {
        INIT_LIST_HEAD(&(db->zone_tbl[i].list));
        db->zone_tbl[i].size = 0;
    }

    return db;    
}


static void adns_zonedb_free(struct adns_zonedb *db)
{
    if (db == NULL) {
        return;
    }

    rte_free(db);
}


int adns_zonedb_init()
{
    int admin_core;
    adns_socket_id_t socket_id;
    char name[64];
    struct adns_zonedb *db = NULL;

    admin_core = rte_lcore_id();
    socket_id = rte_lcore_to_socket_id(admin_core);
    snprintf(name, 64, "%s_%d", "g_datacore_db", socket_id);

    db = adns_zonedb_new(name, socket_id);
    if (db == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot init %s on socket %d\n", name, socket_id);
        return -1;
    }
    g_datacore_db = db;
  
    fprintf(stdout, "[%s]: Finish to new zonedb %s\n", __FUNCTION__, name);    
    return 0;
}


void adns_zonedb_cleanup()
{
    if (g_datacore_db != NULL) {
        adns_zonedb_free(g_datacore_db);
        g_datacore_db = NULL;
    }
}

