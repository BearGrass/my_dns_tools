#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <rte_core.h>

#include "net_debug.h"
#include "iplib.h"
#include "common.h"
#include "view.h"

static adns_viewid_t *ip_infos[ADNS_NB_SOCKETS] = {NULL};
static struct ipv6_bitmap_index *ipv6_ipmap_key[ADNS_NB_SOCKETS] = {NULL};
static struct id_ipmap_list *ipv6_infos[ADNS_NB_SOCKETS] = {NULL};
static const struct rte_memzone *ip_mzs[ADNS_NB_SOCKETS] = {NULL};
static const struct rte_memzone *ipv6_key_mzs[ADNS_NB_SOCKETS] = {NULL};
static const struct rte_memzone *ipv6_mzs[ADNS_NB_SOCKETS] = {NULL};
char *g_ipfile_path = IPLIB_FILE;
char *g_ipv6file_path = IPV6LIB_FILE;
static uint32_t  g_view_max_num = 4096;


char *rm_whitespace(char *string)
{
    char *start = string + strspn(string, " \t");
    char *end = start + (strlen(start)) - 1;

    while ((*end == ' ' || *end == '\t') && end > start) {
        end--;
    }
    if (end != start) {
        *(end + 1) = '\0';
    }

    return start;
}


inline void ip_bitmap_set(uint32_t ip, adns_viewid_t id)
{
    int i;
    for (i = 0; i < ADNS_NB_SOCKETS; i++) {
        // need consume about extra 90 seconds if invoke Lhtonl(ip)
        *(ip_infos[i] + ip/*Lhtonl(ip)*/) = id;
    }
}


adns_viewid_t ip_bitmap_get(uint64_t ip, adns_socket_id_t socket_id)
{
    return *(ip_infos[socket_id] + ip);
    //return *(ip_infos[socket_id] + adns_htonl(ip));
}

static inline int
ip_bitmap_add(char *line, uint32_t *vecs_ip, uint8_t *vhas_ip)
{
    int ret;
    uint64_t ip;
    struct id_ipmap entry;
    char *str = rm_whitespace(line);

    ret = ip_process_entry(&entry, str, g_view_max_num);
    if (ret < 0) {
        return -1;
    }

    for (ip = entry.IPMAP4.ip_start; ip <= entry.IPMAP4.ip_end; ip++) {
        ip_bitmap_set((uint32_t)ip, entry.id);
    }
    vhas_ip[entry.id] = 1;

    if (vecs_ip[entry.id] == 0) {
        if ((entry.IPMAP4.ip_start & 0xFF000000) != 0x0B000000
                && (entry.IPMAP4.ip_start & 0xFF000000) != 0x1E000000
                && (entry.IPMAP4.ip_start & 0xFF000000) != 0x021000000
                && (entry.IPMAP4.ip_start & 0x000000FF) == 0) {
            vecs_ip[entry.id] = entry.IPMAP4.ip_start;
        } else if ((entry.IPMAP4.ip_end & 0xFF000000) != 0x0B000000
                && (entry.IPMAP4.ip_end & 0xFF000000) != 0x1E000000
                && (entry.IPMAP4.ip_end & 0xFF000000) != 0x21000000
                && (entry.IPMAP4.ip_end & 0xFFFFFF00) > entry.IPMAP4.ip_start) {
            vecs_ip[entry.id] = entry.IPMAP4.ip_end & 0xFFFFFF00;
        }
    }

    return 0;
}

inline static int ipv6_cmp(struct id_ipmap entry, uint64_t iph, uint64_t ipt)
{
    /* large */
    if (iph > entry.IPMAP6.ip_end1 ||
            (iph == entry.IPMAP6.ip_end1 && ipt > entry.IPMAP6.ip_end2))
    {
        return 1;
    }
    /* less */
    if (iph < entry.IPMAP6.ip_start1 ||
            (iph == entry.IPMAP6.ip_start1 && ipt < entry.IPMAP6.ip_start2))
    {
        return -1;
    }
    /* equall */
    return 0;

}

static adns_viewid_t ipv6_bsearch(struct id_ipmap *ip_seg, struct in6_addr ipaddr, uint16_t L, uint16_t R) {
    uint64_t iph, ipt;
    int mid, flag;
    //ipv6to64(ipaddr, &iph, &ipt);
    iph = adns_be64toh(*(uint64_t*)ipaddr.s6_addr);
    ipt = adns_be64toh(*(uint64_t*)(ipaddr.s6_addr+8));
    /* iph:ipt is less than the least of segment or larger than the lagest of segment */
    if (ipv6_cmp(ip_seg[L], iph, ipt) < 0 || ipv6_cmp(ip_seg[R], iph, ipt) > 0) {
        return 0;
    }
    if (L > R) {
        return 0;
    }
    while (1) {
        if (L == R) {
            if (ipv6_cmp(ip_seg[L], iph, ipt) == 0) {
                return ip_seg[L].id;
            } else {
                return 0;
            }
        }
        if (L == R - 1) {
            if (ipv6_cmp(ip_seg[L], iph, ipt) == 0) {
                return ip_seg[L].id;
            } else if (ipv6_cmp(ip_seg[R], iph, ipt) == 0) {
                return ip_seg[R].id;
            } else {
                return 0;
            }
        }
        mid = (L + R) / 2;
        flag = ipv6_cmp(ip_seg[mid], iph, ipt);
        if (flag == 0) {
            return ip_seg[mid].id;
        }
        if (flag < 0) {
            R = mid;
        } else {
            L = mid + 1;
        }
    }
}

adns_viewid_t ipv6_bitmap_get(struct in6_addr ipaddr, adns_socket_id_t socket_id)
{
    struct ipv6_bitmap_index *index;
    index = &ipv6_ipmap_key[socket_id][adns_be32toh(ipaddr.s6_addr32[0])];
    return ipv6_bsearch(ipv6_infos[socket_id]->seg, ipaddr, index->start, index->end);
}

int __ipv6_insert(struct id_ipmap entry, adns_socket_id_t socket_id) {
    struct id_ipmap_list *list = ipv6_infos[socket_id];
    /* list may be 1 ~ MAX_IPV6_SEQ - 1 */
    if (list->cnt >= MAX_IPV6_SEQ - 1) {
        return -1;
    }

    list->cnt ++;
    memcpy(&list->seg[list->cnt], &entry, sizeof(struct id_ipmap));
    return list->cnt;
}

inline static int ipv6_insert(struct id_ipmap entry) {
    int i, ret;
    for (i = 0; i < ADNS_NB_SOCKETS; i++) {
        ret = __ipv6_insert(entry, i);
        if (ret < 0) {
            return ret;
        }
    }
    return ret;
}


static inline int ipv6_bitmap_set(struct id_ipmap entry)
{
    int pos;
    uint64_t j, start, end;

    start = entry.IPMAP6.ip_start1 >> 32;
    end = entry.IPMAP6.ip_end1 >> 32;
    if (start > end) {
        return -1;
    }

    pos = ipv6_insert(entry);
    if (pos < 0) {
        return -1;
    }

    for (j = start; j <= end; j ++) {
        if (ipv6_ipmap_key[0][j].start == 0) {
            ipv6_ipmap_key[0][j].start = pos;
            ipv6_ipmap_key[0][j].end = pos;
        } else {
            ipv6_ipmap_key[0][j].end = pos;
        }
    }
    return 0;
}

static inline int
ipv6_bitmap_add(char *line, uint8_t *vhas_ip)
{
    int ret;
    struct id_ipmap entry;
    char *str = rm_whitespace(line);

    ret = ipv6_process_entry(&entry, str, g_view_max_num);
    if (ret < 0) {
        fprintf(stderr, "[%s]: ipv6 file error(%s)\n", __FUNCTION__, str);
        return -1;
    }
    ret = ipv6_bitmap_set(entry);
    if (ret < 0) {
        fprintf(stderr, "[%s]: ipv6 insert error(%s)\n", __FUNCTION__, str);
        return -1;
    }
    vhas_ip[entry.id] = 1;
    return 0;
}

static int __iplib_load_init(char *ipfile_path, uint16_t ip_proto,
        uint32_t *vecs_ip, uint8_t *vhas_ip) {
    int line_idx = 0;
    char line[ADNS_LINE_MAX_LEN] = {0};
    FILE *fp = NULL;
    int L, ret;

    if (ipfile_path == NULL) {
        RTE_LOG(ERR, LDNS, "[%s]: File is NULL\n", __FUNCTION__);
        return -1;
    }
    fp = fopen(ipfile_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "[%s]: Cannot open file: %s\n", __FUNCTION__, ipfile_path);
        return -1;
    }

    while (!feof(fp) && fgets(line, sizeof(line) - 1, fp) != NULL ) {
        line_idx++;
        L = strlen(line);
        if (L > 0) {
            if (line[L - 1] == '\n') {
                line[L - 1] = '\0';
            }
            if (L > 0 && line[L - 1] == '\r') {
                line[L - 1] = '\0';
            }
        }

        if (ip_proto == ETHER_TYPE_IPv4) {
            ret = ip_bitmap_add(line, vecs_ip, vhas_ip);
        } else if (ip_proto == ETHER_TYPE_IPv6) {
            ret = ipv6_bitmap_add(line, vhas_ip);
        }
        if (ret) {
            fprintf(stderr, "[%s]: Line %d format is invalid\n", __FUNCTION__, line_idx);
            goto err;
        }
    }

    fclose(fp);
    return 0;

err:
    fclose(fp);
    return -1;
}

int iplib_load_init()
{
    int i, ret;
    uint32_t view_ecs[VIEW_MAX_COUNT];
    /*view has ips ?*/
    uint8_t has_ip[VIEW_MAX_COUNT];

    memset(view_ecs, 0, sizeof(view_ecs));
    memset(has_ip, 0, sizeof(has_ip));
    ret = __iplib_load_init(g_ipfile_path, ETHER_TYPE_IPv4, view_ecs, has_ip);
    if (ret < 0) {
        return ret;
    }
    ret = __iplib_load_init(g_ipv6file_path, ETHER_TYPE_IPv6, view_ecs, has_ip);
    if (ret < 0) {
        return ret;
    }

    for (i = 1; i < g_view_nums; i++) {
        if (has_ip[i] == 0) {
            fprintf(stderr, "[%s]: There is no any ipv4 or ipv6 address for view %s\n",
                    __FUNCTION__, view_id_to_name(i));
            continue;
        }

        if (ip_bitmap_get(view_ecs[i], 0) != i) {
            fprintf(stderr,
                    "[%s]: Failed to get default ECS ip for view %s\n",
                    __FUNCTION__, view_id_to_name(i));
            return -1;
        }
        g_recs_views->view_list[i].ecs_ip = Lhtonl(view_ecs[i]);
        g_auth_views->view_list[i].ecs_ip = g_recs_views->view_list[i].ecs_ip;
        g_backup_views->view_list[i].ecs_ip = g_recs_views->view_list[i].ecs_ip;
        printf("The ecs ip for view: %s is %u.%u.%u.%u\n", view_id_to_name(i),
                NIPQUAD(g_recs_views->view_list[i].ecs_ip));
    }

    return ret;
}

void test_ip(char *ip)
{
    uint32_t v = find_view_by_strip(ip);
    printf("%s in view %s\n", ip, get_lcore_view_name(v));
}

void run_view_test()
{
    test_ip("192.168.1.1");
    test_ip("192.168.2.2");
    test_ip("10.15.2.1");
    test_ip("10.155.2.1");
    test_ip("1.1.1.1");
    test_ip("1.1.2.1");
    test_ip("2.2.2.2");
    test_ip("2.3.4.5");
}

int iplib_init(void)
{
    int i, ret;
    char name[RTE_MEMZONE_NAMESIZE];

    for (i = 0; i < ADNS_NB_SOCKETS; i++) {
        snprintf(name, RTE_MEMZONE_NAMESIZE, "iplib_mzs_%d", i);
        ip_mzs[i] = rte_memzone_reserve(name, (uint64_t)IP_MZ_SIZE, i, 0);
        if (ip_mzs[i] == NULL) {
            RTE_LOG(ERR, LDNS, "[%s]: Cannot reserve memory for %s\n",
                    __FUNCTION__, name);
            return -1;
        }

        memset(ip_mzs[i]->addr, 0, IP_MZ_SIZE);
        ip_infos[i] = (adns_viewid_t *)ip_mzs[i]->addr;
    }

    for (i = 0; i < ADNS_NB_SOCKETS; i ++) {
        snprintf(name, RTE_MEMZONE_NAMESIZE, "ipv6_ipmap_key_%d", i);
        ipv6_key_mzs[i] = rte_memzone_reserve(name, IPV6_KEY_MZ_SIZE, i, 0);
        if (ipv6_key_mzs[i] == NULL) {
            fprintf(stderr, "[%s]: Cannot reserve memory for %s\n", __FUNCTION__, name);
            return -1;
        }

        memset(ipv6_key_mzs[i]->addr, 0, IPV6_KEY_MZ_SIZE);
        ipv6_ipmap_key[i] = (struct ipv6_bitmap_index*)ipv6_key_mzs[i]->addr;

        snprintf(name, RTE_MEMZONE_NAMESIZE, "ipv6lib_mzs_%d", i);
        ipv6_mzs[i] = rte_memzone_reserve(name, IPV6_MZ_SIZE, i, 0);
        if (ipv6_mzs[i] == NULL) {
            fprintf(stderr, "[%s]: Cannot reserve memory for %s\n", __FUNCTION__, name);
            return -1;
        }
        memset(ipv6_mzs[i]->addr, 0,IPV6_MZ_SIZE);
        ipv6_infos[i] = (struct id_ipmap_list *)ipv6_mzs[i]->addr;
    }

    ret = iplib_load_init();
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to load iplib\n", __FUNCTION__);
        return -1;
    }
    run_view_test();

    return 0;
}


void iplib_cleanup(void)
{
    int i;

    for (i = 0; i < ADNS_NB_SOCKETS; i++) {
        if (ip_mzs[i] != NULL) {
            memset(ip_mzs[i]->addr, 0, IP_MZ_SIZE);
        }
        if (ipv6_key_mzs[i] != NULL) {
            memset(ipv6_key_mzs[i]->addr, 0, IPV6_KEY_MZ_SIZE);
        }
        if (ipv6_mzs[i] != NULL) {
            memset(ipv6_mzs[i]->addr, 0, IPV6_MZ_SIZE);
        }
    }
}
