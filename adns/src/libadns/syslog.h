#ifndef _ADNS_SYSLOG_H_
#define _ADNS_SYSLOG_H_


#include <string.h>
#include <stdio.h>
#include <stdint.h>


#include <rte_ether.h>


#define ADNS_SYSLOG_PORT_SIZE    65535
#define ADNS_SYSLOG_MAX_PORTS    32
#define ADNS_SYSLOG_TAG_MAX_LEN    32


struct adns_syslog {
    uint16_t src_port[RTE_MAX_LCORE][ADNS_SYSLOG_PORT_SIZE];
    uint8_t  current_port[RTE_MAX_LCORE];
    uint16_t max_port;

    struct   ether_addr d_addr[ADNS_SYSLOG_MAX_PORTS];  /* gateway MAC address */
    uint32_t ipv4_dst_addr;                             /* syslog server ip */
    uint32_t ipv4_src_addr[ADNS_SYSLOG_MAX_PORTS];      /* local ip address */
    uint16_t dst_port;                                  /* syslog server port */
    uint8_t  cur_using_port;                            /* nic port, for HA of query_sta syslog sending */
    char     tag[ADNS_SYSLOG_TAG_MAX_LEN];
    uint8_t  domain_sta_on;                             /* send query statistic syslog to jlogserver */
    uint8_t  domain_sta_log_on;                         /* write query statistics log to disk for SLS */
    uint32_t estimated_domain_num;                      /* estimated domain number to write query statistics */
    uint32_t sta_send_interval;                         /* send query statistic interval for every domain */
} __attribute__((packed));


extern struct rte_mempool *g_syslogmbuf_pool;
extern struct adns_syslog g_syslog_ctl;


#endif


