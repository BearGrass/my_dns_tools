#include<assert.h>
#include<arpa/inet.h>

#include "ip_filter.h"
#include "log.h"
#include "dns_pkt.h"
#include "storage.h"

#define IP_FILTER_SIZE      ((uint64_t)(1UL << 32) * sizeof(uint8_t))
#define MAN_IP_BLACKLIST_FILE  ".man_ip_blacklist_active"
#define MAX_IP_BLACKLIST_NUM   50
#define IPV6_HASH_TBL_SIZE  (1<<12)
#define IPV6_FILTER_CNT  (1024)

const struct rte_memzone *ip_blacklist_mz = NULL;
uint8_t *g_ip_filter_db = NULL;
static uint32_t g_ip_bl_list[MAX_IP_BLACKLIST_NUM];
static int g_ip_bl_len = 0;
hash_table *g_ipv6_filter_db;
static struct rte_mempool *ipv6_filter_pool;

static inline uint32_t
ipv6_filter_hash_val(const uint8_t p[16]) {
    return (rte_jhash(p, 16, JHASH_INITVAL) & (IPV6_HASH_TBL_SIZE - 1));
}

static inline void load_vip(uint32_t *vips, ip_filter_mask_t mask) {
    int i;

    for (i = 0; i < VIP_IPADDR_NUM_MAX; i++) {
        if (vips[i] != 0) {
            set_ip_filter(vips[i], mask);
            RTE_LOG(INFO, LDNS, "Set ipaddr_%d.%d.%d.%d with filter mask %d as %d\n",
                    NIP_STR(vips[i]), mask, get_ip_filter(vips[i], mask));
        } else {
            break;
        }
    }
}

static inline void load_vip6(uint8_t vips[][16], ip_filter_mask_t mask) {
    int i;

    for (i = 0; i < VIP_IPADDR_NUM_MAX; i++) {
        uint64_t *ip64 = (uint64_t *)&vips[i];
        if (ip64[0] == 0 && ip64[1] == 0) {
            break;
        } else {
            set_ipv6_filter(vips[i], mask);
            RTE_LOG(INFO, LDNS, "Set ip6addr " NIP6_FMT " with filter mask %d as %d\n",
                       NIP6(vips[i]), mask, get_ipv6_filter(vips[i], mask));
        }
    }
}

void __load_vips() {
    load_vip(g_rec_vip, IP_FILTER_MASK_RECUS);
    load_vip(g_auth_vip, IP_FILTER_MASK_CACHE);
    load_vip(g_sec_vip, IP_FILTER_MASK_SEC);
    load_vip6(g_rec_vip6, IP_FILTER_MASK_RECUS);
    load_vip6(g_auth_vip6, IP_FILTER_MASK_CACHE);
    load_vip6(g_sec_vip6, IP_FILTER_MASK_SEC);
}

int init_ip_filter()
{
    char name[RTE_MEMZONE_NAMESIZE];

    snprintf(name, IP_FILTER_SIZE, "ip_filter_db_%d", 0);
    ip_blacklist_mz = rte_memzone_reserve(name, IP_FILTER_SIZE, 0, 0);
    if (ip_blacklist_mz == NULL) {
        RTE_LOG(ERR, LDNS, "Fail to create %s", name);
        return -1;
    }
    memset(ip_blacklist_mz->addr, 0, IP_FILTER_SIZE);
    g_ip_filter_db = (uint8_t *)ip_blacklist_mz->addr;

    sprintf(name, "ipv6_filter_db_%d", 0);
    g_ipv6_filter_db = create_hash_table(name, IPV6_HASH_TBL_SIZE,
            rte_lcore_to_socket_id(rte_lcore_id()));
    if (g_ipv6_filter_db == NULL) {
        RTE_LOG(ERR, LDNS, "Fail to create %s", name);
        return -1;
    }

    sprintf(name, "ipv6_filter_pool");
    ipv6_filter_pool = rte_mempool_create(name, IPV6_FILTER_CNT, sizeof(ipv6_filter),
            32, 0, NULL, NULL, NULL, NULL,
            rte_lcore_to_socket_id(rte_lcore_id()), MEMPOOL_F_SP_PUT);
    if (ipv6_filter_pool == NULL) {
        RTE_LOG(ERR, LDNS, "Fail to create %s", name);
        return -1;
    }

    __load_vips();

    return 0;
}

static inline ipv6_filter *
__get_ipv6_filter_info(uint8_t ipv6_addr[16], uint32_t idx) {
    hash_table *tb = &g_ipv6_filter_db[idx];
    ipv6_filter *ip6Info = NULL;

    list_for_each_entry(ip6Info, &tb->list, list)
    {
        if (memcmp(ipv6_addr, ip6Info->ipv6_addr, 16) == 0) {
            return ip6Info;
        }
    }

    return NULL;
}

ipv6_filter *get_ipv6_filter_info(uint8_t ipv6_addr[16]) {
    return __get_ipv6_filter_info(ipv6_addr, ipv6_filter_hash_val(ipv6_addr));
}

static inline ipv6_filter *
__alloc_ipv6_filter(uint8_t ipv6_addr[16], uint32_t idx) {
    ipv6_filter *ip6Info = NULL;

    if (rte_mempool_get(ipv6_filter_pool, (void **)&ip6Info) < 0) {
        ALOG(SERVER, ERROR, "Fail to get ipv6 filter from mempool %s", ipv6_filter_pool->name);
        return NULL;
    }

    rte_memcpy(ip6Info->ipv6_addr, ipv6_addr, 16);
    ip6Info->filter = 0;
    INIT_LIST_HEAD((&ip6Info->list));

    return ip6Info;
}

void set_ipv6_filter(uint8_t ipv6_addr[16], ip_filter_mask_t mask) {
    uint32_t idx = ipv6_filter_hash_val(ipv6_addr);
    ipv6_filter *ip6Info = __get_ipv6_filter_info(ipv6_addr, idx);
    if(ip6Info == NULL) {
        ip6Info = __alloc_ipv6_filter(ipv6_addr, idx);
        if(ip6Info == NULL) {
            return;
        }
        ip6Info->filter |= (uint8_t)mask;
        list_add_tail(&ip6Info->list, &g_ipv6_filter_db[idx].list);
        g_ipv6_filter_db[idx].size++;
        return;
    }

    ip6Info->filter |= (uint8_t)mask;
}

void unset_ipv6_filter(uint8_t ipv6_addr[16], ip_filter_mask_t mask) {
    uint32_t idx = ipv6_filter_hash_val(ipv6_addr);
    ipv6_filter *ip6Info = __get_ipv6_filter_info(ipv6_addr, idx);
    if(ip6Info == NULL) {
        return;
    }

    ip6Info->filter &= ~(uint8_t)mask;
}

static void fix_line(char *line)
{
    int len, i;

    while (1) {
        if (line == NULL)
            break;
        len = strlen(line);
        for (i = 0; i < len; i++) {
            if (line[i] == ' ') {
                while (i < len) {
                    line[i] = '\0';
                    i++;
                }
                break;
            }
        }
        len = strlen(line);
        if (line[len - 1] == '\r' || line[len - 1] == '\n'
            || line[len - 1] == ' ' || line[len - 1] == '\t') {
            line[len - 1] = '\0';
            continue;
        }
        break;

    }
}

// TODO: charge_man_ipv6_blacklist_state
void charge_man_ipv6_blacklist_state(){}

void charge_man_ip_blacklist_state()   //only called at misc core
{
    uint32_t tmp_ip_bl_len = 0;
    uint32_t tmp_ip_bl_list[MAX_IP_BLACKLIST_NUM];
    uint32_t temp_ip = 0;
    uint32_t i, j;

/*    ALOG(SERVER, WARN, "Now begin load man_ip_blacklist from file %s",
         MAN_IP_BLACKLIST_FILE);*/
    FILE *fp = fopen(MAN_IP_BLACKLIST_FILE, "r");
    if (!fp) {
        ALOG(SERVER, ERROR, "Open man_ip_blacklist file %s fail", MAN_IP_BLACKLIST_FILE);
        return;
    }

    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
        fix_line(line);
        if (line == NULL)
            continue;
        temp_ip = inet_addr(line);

        if(temp_ip == INADDR_NONE) {
            ALOG(SERVER, ERROR,
                "Invalid format (%s) in man_ip_blacklist data from file %s",
                line, MAN_IP_BLACKLIST_FILE);
            continue;
        }

        if (tmp_ip_bl_len >= MAX_IP_BLACKLIST_NUM) {
            ALOG(SERVER, WARN,
                    "Exceed max ip blacklist size (%d) in man_ip_blacklist data from file %s",
                    MAX_IP_BLACKLIST_NUM, MAN_IP_BLACKLIST_FILE);
            break;
        }
        tmp_ip_bl_list[tmp_ip_bl_len++] = temp_ip;
        set_ip_filter(temp_ip, IP_FILTER_MASK_BLOCK);
        //ALOG(SERVER, INFO, "load ip %s from man_ip_blacklist", line);
    }
    free(line);
    fclose(fp);

    for(i = 0; i < g_ip_bl_len; i++) {
        for(j = 0; j < tmp_ip_bl_len; j++) {
            if(g_ip_bl_list[i] == tmp_ip_bl_list[j]) {
                break;
            }
        }

        if (j == tmp_ip_bl_len) {
            unset_ip_filter(g_ip_bl_list[i], IP_FILTER_MASK_BLOCK);
        }
    }

    memcpy(g_ip_bl_list, tmp_ip_bl_list, tmp_ip_bl_len * sizeof(uint32_t));
    g_ip_bl_len = tmp_ip_bl_len;
}
