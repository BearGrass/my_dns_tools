#ifndef __QTYPE_H_
#define __QTYPE_H_

#include<stdint.h>

#include "rte_core.h"

#define QT(x) get_query_qtype(x)
#define QTYPE_LEN 15
#define U16_MAX 0xffff
extern char dns_qtype[RTE_MAX_NUMA_NODES][U16_MAX + 1][QTYPE_LEN];
extern char status_str[16][20];
extern void init_dns_qtype();
static inline char * __attribute__ ((always_inline))
get_query_qtype(uint16_t qtype) {
    int socket_id = rte_socket_id();
    if (strlen(dns_qtype[socket_id][qtype]) == 0) {
        return "UNKNOW";
    }
    return dns_qtype[socket_id][qtype];
}

#endif
