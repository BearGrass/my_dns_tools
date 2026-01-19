#include <stdio.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_config.h>
#include "node.h"
#include "zone.h"
#include "adns.h"
#include "list.h"
#include "ring_list.h"
#include "log.h"
#include "syslog.h"
#include "adns_counter.h"
#include "dname.h"

extern char g_time_str[];
extern char *g_hostname;
extern char g_idcname[];
extern uint64_t HZ;

int ns_send_syslog_ipv4(uint8_t port, const char *fmt, ...);

struct query_sta_list g_sta_list[RTE_MAX_LCORE];

static int send_syslog(struct adns_node * node)
{
    uint64_t queries = 0, cur_queries = 0;
    uint64_t bytes = 0, cur_bytes = 0;
    char * dname_str = NULL, * zone_str = NULL;
    int ret = -1;

    if(node == NULL){
        return -1;
    }

    ret = adns_counter_sum_get_queries_bytes(node->counter_id, &cur_queries, &cur_bytes);
    if (ret == -1) {
        return -1;
    }

    queries = cur_queries - node->pre_sta_queries;
    bytes = cur_bytes - node->pre_sta_bytes;
    if (queries == 0 || bytes == 0) {
        return 0;
    }
    node->pre_sta_queries = cur_queries;
    node->pre_sta_bytes = cur_bytes;

    dname_str = adns_dname_to_str(node->name);
    zone_str = adns_dname_to_str((node->zone)->name);

    /* STA for query statistics, maybe a poor name */
    if (g_syslog_ctl.domain_sta_on == 1) {
    ret = ns_send_syslog_ipv4(g_syslog_ctl.cur_using_port,
        "<86>ADNS-STA-%s,%s,%s,"
        "%s,%s,"
        "%u,%u,%s\n",
         g_syslog_ctl.tag, g_idcname, g_hostname,
         zone_str, dname_str,
         queries, bytes, g_time_str);
    }

    if (g_syslog_ctl.domain_sta_log_on == 1) {
        log_query_statis_info(rte_lcore_id(), "lcore %d,ADNS-STA,%s,%s,"
        		"%u,%u,%s\n",
        	    rte_lcore_id(), zone_str, dname_str,
                queries, bytes, g_time_str);
    }

    free(dname_str);
    free(zone_str);

    return 0;
}

int rlist_add_tail(struct rlist_head * newly_added, int io_core_id)
{
    int success = 0;
    volatile struct rlist_head * local_tail;

    if (newly_added == NULL) {
        return -1;
    }

    if (g_sta_list[io_core_id].rtail == NULL) {
        newly_added->next = newly_added;
        /* this is executed always before rlist_iterate(),
         * thus this doesn't raise contention and need no synchronization */
        g_sta_list[io_core_id].rtail = newly_added;
    }
    else {
        while (success == 0) {
            local_tail = g_sta_list[io_core_id].rtail;
            newly_added->next = local_tail->next;
            success = rte_atomic64_cmpset( (volatile uint64_t *)&(g_sta_list[io_core_id].rtail->next), (uint64_t)(local_tail->next), (uint64_t)newly_added );
        }
    }
    g_sta_list[io_core_id].node_num ++;
    return 0;
}

int rlist_iterate(int io_core_id)
{
    int step;

    if (g_syslog_ctl.domain_sta_on == 0 && g_syslog_ctl.domain_sta_log_on == 0) {
        return 0;
    }

    for (step = 0; step < QUERY_STA_BURST_CNT; step++) {
        if (g_sta_list[io_core_id].rtail == NULL) {
            /* empty queue */
            return 0;
        }
        else {
            uint64_t current;
            struct adns_node * node;
            struct rlist_head * cur_head;
            struct node_stub * cur_node_stub;
            int success = 0;

            /* first, check the current node stub is to be deleted or not */
            while (success == 0) {
                cur_head = g_sta_list[io_core_id].rtail->next;
                cur_node_stub = list_entry(cur_head, struct node_stub, rlist_entry);
                if (cur_node_stub->is_deleted == false) {
                    break;
                }
                if (cur_head->next == cur_head) {
                    /* the only one left is to be deleted */
                    success = rte_atomic64_cmpset((volatile uint64_t *)&(g_sta_list[io_core_id].rtail), (uint64_t)cur_head, (uint64_t)NULL);
                }
                else {
                    success = rte_atomic64_cmpset((volatile uint64_t *)&(g_sta_list[io_core_id].rtail->next), (uint64_t)cur_head, (uint64_t)cur_head->next);
                }
            }
            if (cur_node_stub->is_deleted == true) {
                g_sta_list[io_core_id].node_num --;
                node_stub_free(cur_node_stub);
                continue;
            }

            /* second, process the node */
            if ( (node = cur_node_stub->node_ptr) == NULL) {
                return -1;
            }

            current = rte_get_timer_cycles();
            if (current - node->pre_sta_timestamp < QUERY_STA_SEND_INTERVAL) {
                /* no element's timestamp is ready, the list is ordered */
                return 0;
            }

            if (g_syslog_ctl.domain_sta_on == 1 || g_syslog_ctl.domain_sta_log_on == 1) {
                send_syslog(node);
            }

            node->pre_sta_timestamp = current;
            for(success = 0; success == 0; ) {
                success = rte_atomic64_cmpset((volatile uint64_t *)&(g_sta_list[io_core_id].rtail), (uint64_t)g_sta_list[io_core_id].rtail, (uint64_t)(g_sta_list[io_core_id].rtail->next) );
            }
        }
    }
    return 0;
}

