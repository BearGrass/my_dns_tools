
/* IP library now only support IPv4 */

#ifndef _ADNS_IPLIB_H_
#define _ADNS_IPLIB_H_

#include <stdint.h>
#include <string.h>
#include <rte_core.h>

typedef uint16_t adns_viewid_t;
typedef uint8_t adns_socket_id_t;

#define adns_be16toh(x) rte_be_to_cpu_16(x)
#define adns_be32toh(x) rte_be_to_cpu_32(x)
#define adns_be64toh(x) rte_be_to_cpu_64(x)

#define ADNS_NB_SOCKETS         1
#define ADNS_LINE_MAX_LEN     1024
#define IP_MZ_SIZE          ((uint64_t)(1UL << 32) * sizeof(adns_viewid_t))
#define IPLIB_FILE "etc/ip_range.map"
#define IPV6LIB_FILE "etc/ipv6_range.map"
#define IPV6_MZ_SIZE        sizeof(struct id_ipmap_list)
#define IPV6_KEY_MZ_SIZE    (uint64_t)(1UL << 32)* sizeof(struct ipv6_bitmap_index)
#define MAX_IPV6_SEQ (1<<18)


struct ipv6_bitmap_index {
	uint32_t start, end;
};

struct id_ipv4map {
    uint32_t ip_start;
    uint32_t ip_end;
};

struct id_ipv6map {
    uint64_t ip_start1, ip_start2;
    uint64_t ip_end1, ip_end2;
};

struct id_ipmap {
    union {
        struct id_ipv4map ipv4;
        struct id_ipv6map ipv6;
    } ipmap;
    adns_viewid_t id;
#define IPMAP6 ipmap.ipv6
#define IPMAP4 ipmap.ipv4
};

struct id_ipmap_list {
    struct id_ipmap seg[MAX_IPV6_SEQ];
    int cnt;
};

/*ip start | ip end | ID*/
static inline int ip_process_entry(struct id_ipmap *entry, char *line, uint32_t max_entry_num)
{
    int i;
    unsigned int val;
    char *str, *saveptr = NULL, *token, *buf[10];

    for (i = 0, str = line; ; i++, str = NULL) {
        token = strtok_r(str, " ", &saveptr);
        if (token == NULL) {
            break;
        }

        if (i >= 5) {
            break;
        }
        buf[i] = token;
    }

    if (i != 3) {
        return -1;
    }

    entry->ipmap.ipv4.ip_start = (uint32_t)atoi(buf[0]);
    entry->ipmap.ipv4.ip_end = (uint32_t)atoi(buf[1]);
    if (entry->ipmap.ipv4.ip_start > entry->ipmap.ipv4.ip_end) {
        return -1;
    }

    if ((val = (unsigned int)atoi(buf[2])) >= max_entry_num) {
        return -1;
    }
    entry->id = (adns_viewid_t)val;

    return 0;
}

/* ip_start[0] ip_start[1] | ip_end[0] ip_end[1] | ID */
static inline int ipv6_process_entry(struct id_ipmap *entry, char *line, uint32_t max_entry_num)
{
    int i;
    unsigned int val;
    char *str, *saveptr = NULL, *token, *buf[10];

    for (i = 0, str = line; ; i++, str = NULL) {
        token = strtok_r(str, " ", &saveptr);
        if (token == NULL) {
            break;
        }

        if (i >= 5) {
            break;
        }
        buf[i] = token;
    }

    if (i != 5) {
        fprintf(stderr, "[%s]: The number of entry is error %d\n", __FUNCTION__, i);
        return -1;
    }
    entry->ipmap.ipv6.ip_start1 = (uint64_t)strtoull(buf[0], NULL, 10);
    entry->ipmap.ipv6.ip_start2 = (uint64_t)strtoull(buf[1], NULL, 10);
    entry->ipmap.ipv6.ip_end1= (uint64_t)strtoull(buf[2], NULL, 10);
    entry->ipmap.ipv6.ip_end2= (uint64_t)strtoull(buf[3], NULL, 10);
    if ( entry->ipmap.ipv6.ip_start1 > entry->ipmap.ipv6.ip_end1 ||
            (entry->ipmap.ipv6.ip_start1 == entry->ipmap.ipv6.ip_end1 && entry->ipmap.ipv6.ip_start2 > entry->ipmap.ipv6.ip_end2)) {
        fprintf(stderr, "[%s]: The ipv6 ip seg order is error.\n", __FUNCTION__);
        return -1;
    }
    if ((val = (unsigned int)atoi(buf[4])) >= max_entry_num) {
        fprintf(stderr, "[%s]: view number is too bigger (%u > %u)\n", __FUNCTION__, val, max_entry_num);
        return -1;
    }
    entry->id = (adns_viewid_t)val;
    return 0;
}

extern char *g_ipfile_path;
extern adns_viewid_t ip_bitmap_get(uint64_t ip, adns_socket_id_t socket_id);
extern adns_viewid_t ipv6_bitmap_get(struct in6_addr ipaddr, adns_socket_id_t socket_id);

int iplib_load_init();
int iplib_init();
void iplib_cleanup();


#endif


