#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_memory.h>

#include "adns_conf.h"
#include "adns_share.h"
#include "adns_endian.h"
#include "private_route.h"
#include "iplib.h"
#include "log.h"


struct rte_mempool *g_private_route_pools[ADNS_MAX_SOCKETS] = {NULL};

#ifndef UNIT_TEST
int 
adns_private_route_init() 
{
    adns_socket_id_t socket_id;
    char name[64] = {0};

    for (socket_id = 0; socket_id < ADNS_MAX_SOCKETS; socket_id++) {
        /* allocate memory pool for private route ipset */
        /* since rte_mempool's element num can not exceed 268435455(0XFFFFFFF), we are not able to allocate a mempool with
           10w*100*100 ip segments, the current solution is to allocate a mempool with 10w elements, each element contains
           100*100 ip segments, this method waste memory, seek for better solution */
        snprintf(name, sizeof(name), "g_private_route_pools_%d", socket_id);
        g_private_route_pools[socket_id] = rte_mempool_create(name, g_private_route_zone_max_num,
                sizeof(struct adns_ipset_ipv4_info) * g_private_route_per_zone_max_num * g_ip_segment_per_route_max_num, 32, 0, NULL, NULL, NULL,
                NULL, socket_id, 0);
        if (g_private_route_pools[socket_id] == NULL) {
            fprintf(stdout, "[%s]: fail to alloc g_private_route_pools %s\n", __FUNCTION__, name);
            return -1;
        }
        fprintf(stdout, "[%s]: Finish to alloc g_private_route_pools %s\n", __FUNCTION__, name);
    }

    return 0;
}

adns_ipset_t* 
adns_ipset_alloc(adns_socket_id_t socket_id)
{
    adns_ipset_t *ipset = NULL;
    void *data = NULL;

    if (socket_id >= ADNS_MAX_SOCKETS) {
        log_server_error(rte_lcore_id(), "[%s]: argument error, socket id: %d\n", __FUNCTION__, socket_id);
        return NULL;
    }

    ipset = rte_malloc_socket(NULL, sizeof(adns_ipset_t), RTE_CACHE_LINE_SIZE, socket_id);
    if (ipset == NULL) {
        log_server_error(rte_lcore_id(), "[%s]: alloc ipset failure, socket id: %d\n", __FUNCTION__, socket_id);
        return NULL;
    }
    memset(ipset, 0, sizeof(adns_ipset_t));
    
    if (rte_mempool_get(g_private_route_pools[socket_id], &data)) {
        log_server_error(rte_lcore_id(), "[%s]: get element from private route pool failure, socket id: %d\n", __FUNCTION__, socket_id);
        rte_free(ipset);
        return NULL;
    }
    ipset->info4 = (adns_ipset_ipv4_info_t *)data;

    ipset->ips_cap = g_private_route_per_zone_max_num * g_ip_segment_per_route_max_num;
    ipset->max_route_id = g_private_route_per_zone_max_num;

#ifndef UNIT_TEST
    INCREASE_PRIVATE_ROUTE_ZONE_NUM(1);
#endif

    return ipset;
}
#endif

#if 0
static inline uint8_t
_adns_ipset_cal_mask(uint32_t ips_head, uint32_t ips_tail)
{
    uint8_t i;

    uint32_t m = ~(ips_tail ^ ips_head);
    
    for (i = 31; i >= 0; i --) {
        if (((m >> i) & 1) == 0) {
            break;
        }
    }
    return 31 - i;
}
#endif

static inline int
_adns_ipset_add(adns_ipset_t *ipset, int index, char *line)
{
    struct id_ipmap entry;

    if (ipset == NULL ||
        line == NULL) {
        return -1;
    }

    if (index >= ipset->ips_cap) {
        return -1;
    }

    char *str = rm_whitespace(line);
    if (ip_process_entry(&entry, str, ipset->max_route_id)) {
        return -1;
    }

    ipset->info4[index].ips_head = entry.IPMAP4.ip_start;
    ipset->info4[index].ips_tail = entry.IPMAP4.ip_end;
    ipset->info4[index].id = (adns_private_route_id_t)entry.id;

    return 0;
}


int
adns_ipset_init(adns_ipset_t *ipset, const char *iplib)
{
    int line_idx = 0;
    char line[ADNS_LINE_MAX_LEN] = {0};
    FILE *fp = NULL;
    int line_length = 0;
    int ret = -1;
    uint16_t ipseg_num[g_private_route_per_zone_max_num];
    memset(ipseg_num, 0, sizeof(uint16_t) * g_private_route_per_zone_max_num);

    if (ipset == NULL || iplib == NULL) {
        return -1;
    }

    fp = fopen(iplib, "r");
    if (fp == NULL) {
        return -1;
    }

    while (!feof(fp) && fgets(line, sizeof(line) - 1, fp) != NULL ) {
        if (unlikely(line_idx >= ipset->ips_cap)) {
            goto err;
        }
        line_length = strlen(line);
        
        if (line_length > 0) {
            if (line[line_length - 1] == '\n') {
                line[line_length - 1] = '\0';
            }
            if (line_length > 0 && line[line_length - 1] == '\r') {
                line[line_length - 1] = '\0';
            }
        }

        if (_adns_ipset_add(ipset, line_idx, line)) {
            //fprintf(stderr, "[%s]: Line %d format is invalid\n", __FUNCTION__, line_idx);
            goto err;
        }
        ipseg_num[ipset->info4[line_idx].id] += 1;
        if (ipseg_num[ipset->info4[line_idx].id] > g_ip_segment_per_route_max_num) {
            log_server_error(rte_lcore_id(), "[%s]: custom view %d, IP segment number exceed limit\n", __FUNCTION__, ipset->info4[line_idx].id);
            goto err;
        }

        line_idx ++;

    }
    ipset->ips_num = line_idx;
    ret = 0;

err:
    if (fp)
        fclose(fp);
    return ret;
}

void 
adns_ipset_free(adns_ipset_t *ipset)
{
    if (ipset == NULL) {
        return;
    }

    adns_socket_id_t socket_id = rte_socket_id();
    if (ipset->info4) {
        rte_mempool_put(g_private_route_pools[socket_id], (void *)ipset->info4);
    }

    rte_free(ipset);
#ifndef UNIT_TEST
    DECREASE_PRIVATE_ROUTE_ZONE_NUM(1);
#endif
}

adns_private_route_id_t
adns_ipset_lookup(adns_ipset_t *ipset, uint32_t addr_n)
{
    uint32_t addr, head, tail, mid, gap;

    addr = adns_be32toh(addr_n);

    if (unlikely(addr < ipset->info4[0].ips_head)) {
        return IPSET_LOOKUP_MISS;
    }

    head = 0;
    tail = ipset->ips_num - 1;
    if (unlikely(addr > ipset->info4[tail].ips_head)) {
        if (unlikely(addr <= ipset->info4[tail].ips_tail)) {
            return ipset->info4[tail].id;
        }
        else {
            return IPSET_LOOKUP_MISS;
        }
    }

    while (1) {
        gap = tail - head;
        if (unlikely(gap < _IPSET_QCOD))
            break;

        gap >>= 1;
        mid = head + gap;
        if (addr >= ipset->info4[mid].ips_head)
            head = mid;
        else
            tail = mid;
    }

    for (mid = head; mid <= tail; mid++) {
        if (addr >= ipset->info4[mid].ips_head &&
            addr <= ipset->info4[mid].ips_tail) {
            return ipset->info4[mid].id;
        }
    }

    return IPSET_LOOKUP_MISS;
}
