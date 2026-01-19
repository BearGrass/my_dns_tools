/*
 * qos.c
 *
 *  Created on: 2019年12月2日
 *      Author: mogu.lwp
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <rte_cycles.h>

#include "iplib.h"
#include "fwd_type.h"
#include "ldns.h"
#include "log.h"
#include "qos.h"

uint32_t g_fwd_qps_limit_on[FWD_QPSLIMIT_MAX_NUM];
uint32_t g_fwd_qps_quota[FWD_QPSLIMIT_MAX_NUM];    //for pkts other than  ospf+bgp
qps_limit_st_t kni_limit_tbl[FWD_QPSLIMIT_MAX_NUM];
uint8_t g_kni_qps_limit_on_status;
char *qpslimit_id_name_map[] = { "other", "doh", "dohs", "dot", "ip", "fwd" };
qps_limit_st_t *fwd_ip_limit_tbl[RTE_MAX_LCORE] = {NULL};

int fwd_qps_limit_init() {
    uint32_t lcore;
    char name_temp[20];
    adns_socket_id_t socket_id;

	socket_id = rte_lcore_to_socket_id(rte_lcore_id());
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		struct lcore_params *lp = &app.lcore_params[lcore];
		if ((lp->type != e_LCORE_IO) && (lp->type != e_LCORE_KNI)) {
			continue;
		}
		snprintf(name_temp, sizeof(name_temp), "ip_limit_tbl_%u", lcore);
		fwd_ip_limit_tbl[lcore] = rte_zmalloc_socket(name_temp,
				sizeof(qps_limit_st_t) * IPLIMIT_SIZE, 0, socket_id);
		if (fwd_ip_limit_tbl[lcore] == NULL) {
			RTE_LOG(ERR, LDNS, "[%s]: Failed to alloc %s\n", __FUNCTION__,
					name_temp);
			return -1;
		}
	}

    /*for (i = 0; i < KNI_QPSLIMIT_MAX_NUM; i ++) {
        sprintf(name_temp, "kni_qps_tbl_%d", i);
        kni_limit_tbl[i] = rte_zmalloc_socket("kni_qps_tbl",
                sizeof(qps_limit_st_t), 0, socket_id);
        if (kni_limit_tbl[i] == NULL) {
            RTE_LOG(ERR, LDNS, "[%s]: Failed to alloc kni_limit_tbl[%d]\n",
                    __FUNCTION__, i);
            return -1;
        }
    }*/

    TSC_HZ = rte_get_tsc_hz();
    TSC_100MS = (TSC_HZ + MS_PER_S - 1) / MS_PER_S * 100;
    return 0;
}
