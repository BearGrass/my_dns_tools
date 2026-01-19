
#ifndef _FWDCTL_SHARE_H_
#define _FWDCTL_SHARE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "status.h"

#define FWD_VERSION 4
#define FWD_VERSION_STR "3.2.1"

#define CMD_MSG_MAGIC 0X1234F9A9
#define VALID_CMD_MSG(msg) ((msg)->magic == CMD_MSG_MAGIC)
#define FWD_VIEW_BACKUP_SPLIT "->"
#define FWD_DEL_SPLIT "/"
#define FWD_DEL_BATCH_SPLIT "@"
#define FWD_DEL_STYPE_SPLIT '@'
#define FWD_DEL_BATCH_ENTRY_SPLIT ","
#define ADNS_IO_BUFLEN (2*1024*1024)
#define MVNODES 100000

enum {
	ADNS_GET_INFO = 0,

	/* rndc operation */
	FWD_STATS,
	FWD_REQ_STATS,
	FWD_DROP_STATS,
	FWD_VIEW_STATS,
	FWD_VIEW_STATE,
	FWD_DNS_STATE,
	FWD_DNS_CNTS,
	FWD_CACHE_STATE,
	FWD_VIEW_NODES,
	FWD_SET_VIEW_NODES_TTL_THRESHOLD,
	FWD_PREFETCH_STATS,
	FWD_STATSRESET,
	FWD_SET_LOG,
	FWD_CPU_UTIL,
	FWD_MEMORY_INFO,
	FWD_SET_BACKUP,
	FWD_DEL,
	FWD_DEL_REG,
	FWD_DENY_DNS_START,
	FWD_DENY_DNS_STOP,
	RNDC_START,
	RNDC_STOP,
	RNDC_RELOAD,
	FWD_GET_VERSION,
	FWD_SET_OVERSEA_STATUS,
	FWD_SET_BLACK_STATUS,
	FWD_SET_WHITE_STATUS,
	FWD_SET_MAN_WHITE_STATUS,
	FWD_SET_MAN_BLACK_STATUS,
	FWD_SET_SHARE_STATUS,
	FWD_SET_IPLIB,
	FWD_GET_WILD_ATTACK_STATUS,
	FWD_SET_KNI_QPS_LIMIT_NUM,
    FWD_BATCH_DNSCACHE = 100,
    FWD_BATCH_DNSCACHE_UPDATE,
    FWD_BATCH_DNSCACHE_SET,
    FWD_LIST_DNSCACHE_DOMAIN,
    FWD_LIST_DNSCACHE_DETAIL,
    FWD_GET_DNSCACHE_KAFKA_OFFSET,
    FWD_SET_DNSCACHE_KAFKA_OFFSET,
    FWD_INIT_LOAD_DATA,
    FWD_INIT_SHOW_STATUS,
    FWD_EXPORT_SNAPSHOT,
    FWD_IMPORT_SNAPSHOT,
    FWD_USER_BATCH_SET,
    FWD_USER_LIST,
    FWD_GET_USER_QUEUE_OFFSET,
    FWD_SET_USER_QUEUE_OFFSET,
	//alisocket
	ALISS_CMD,


	CMD_MAX
};



struct cmd_msg {
	uint32_t magic;
	uint32_t version;
    int opcode;
    int flags;
    int seq;
	int cmd;
	int ret_val;
    int req_len;
	int rsp_len;
    char data[0];
} __attribute__((packed));

#ifndef RTE_MAX_NUMA_NODES
    #define RTE_MAX_NUMA_NODES  8
#endif

#ifndef RTE_MEMZONE_NAMESIZE
    #define RTE_MEMZONE_NAMESIZE 32
#endif

#ifndef RTE_MAX_MEMZONE
    #define RTE_MAX_MEMZONE 2560
#endif

struct fdns_malloc_socket_stats {
    size_t heap_totalsz_bytes; /**< Total bytes on heap */
    size_t heap_freesz_bytes;  /**< Total free bytes on heap */
    size_t greatest_free_size; /**< Size in bytes of largest free block */
    unsigned free_count;       /**< Number of free elements on heap */
    unsigned alloc_count;      /**< Number of allocated elements on heap */
    size_t heap_allocsz_bytes; /**< Total allocated bytes on heap */
};

struct mem_info_t {
    uint64_t    count;

    uint64_t    used;
    uint64_t    total;

    struct fdns_malloc_socket_stats heap_stats[RTE_MAX_NUMA_NODES];
    uint64_t    used_per_socket[RTE_MAX_NUMA_NODES];
    uint64_t    total_per_socket[RTE_MAX_NUMA_NODES];

    struct      zone_info_t {
        char        name[RTE_MEMZONE_NAMESIZE];
        uint64_t    len;
        int32_t     socket_id;
        uint8_t     is_pool;
        struct      pool_detail_t {
            uint64_t    base_size;
            uint64_t    elt_count;
            double      elt_size;
            uint64_t    elt_net_size;
            uint64_t    avail_count;
        } pool_detail;
    } zone_info_list[RTE_MAX_MEMZONE];
};

typedef enum SNAPSHOT_OP {
    SS_EXPORT,
    SS_IMPORT,
    SS_OP_NUM,
} SNAPSHOT_OP_T;

typedef enum DNSCACHE_OP {
    DC_LIST,
    DC_SET,
    DC_UPDATE,
    DC_OP_NUM
}DNSCACHE_OP_T;

typedef enum KAFKA_OFFSET_OP {
    SET_OFFSET,
    GET_OFFSET,
    KAFKA_OP_NUM,
}KAFKA_OFFSET_OP_T;

typedef enum INIT_OP {
    LOAD_DATA,
    SHOW_STATUS,
    INIT_OP_NUM,
}INIT_OP_T;

typedef enum USER_OP {
    ADD_USER,
    DEL_USER,
    CHG_USER,
    CHG_USER_STATUS,
    ADD_USER_IP_RANGE,
    DEL_USER_IP_RANGE,
    CHG_USER_IP_RANGE,
    LIST_USER,
    USER_OP_NUM,
} USER_OP_T;

static const char *const snapshot_op_str[SS_OP_NUM] = {
    "export", "import"
};

static const char * const dnscache_op_str[DC_OP_NUM] = {
        "list", "set", "update"
};

static const char * const queue_op_str[INIT_OP_NUM] = {
        "set", "get"
};

static const char * const init_op_str[KAFKA_OP_NUM] = {
        "load", "show"
};

static const char * const user_op_str[USER_OP_NUM] = {
    "add_user", "del_user", "change_user", "change_user_status",
    "add_user_ip_range", "del_user_ip_range", "change_user_ip_range",
    "list",
};

#endif

