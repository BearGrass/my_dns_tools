#include "qps_limit.h"
#include "adns.h"
#include "adns_types.h"


uint64_t TSC_HZ = 0;
uint64_t TSC_100MS = 0;

qps_limit_st_t *dnssec_zone_limit_tbl = NULL;
qps_limit_st_t *dnssec_ip_limit_tbl = NULL;
qps_limit_st_t *dnssec_global_limit = NULL;
qps_limit_st_t *ip_limit_tbl = NULL;

// dnssec qps limit is switched on by default
uint32_t  g_dnssec_qps_limit_on = 1;
// default dnssec zone qps quota is set to 800 
uint32_t g_dnssec_zone_qps_quota = 800;
// default source IP dnssec qps quota is set to 800 
uint32_t g_dnssec_ip_qps_quota = 800;
// default dnssec global qps quota is set to 50000
uint32_t g_dnssec_qps_quota = 50000;

int sysctl_tcp_in_53_drop = 0;
int sysctl_tcp_in_53_rate = 1;
int sysctl_tcp_in_53_quota = 1000;
int sysctl_tcp_in_53_total_quota = 50000;
int sysctl_tcp_in_53_total_pps_quota  = 243000;

int qps_limit_init() {
	adns_socket_id_t socket_id;

	socket_id = rte_lcore_to_socket_id(rte_lcore_id());

	// dnssec zone qps quota
	dnssec_zone_limit_tbl = rte_zmalloc_socket("dnssec_zone_limit_tbl",
			sizeof(qps_limit_st_t) * g_dnssec_zone_max_num, 0, socket_id);
	if (dnssec_zone_limit_tbl == NULL) {
		RTE_LOG(ERR, ADNS, "[%s]: Failed to alloc dnssec_zone_limit_tbl\n", __FUNCTION__);
		return -1;
	}

	// dnssec ip qps quota
	dnssec_ip_limit_tbl = rte_zmalloc_socket("dnssec_ip_limit_tbl",
			sizeof(qps_limit_st_t) * IPLIMIT_SIZE, 0, socket_id);
	if (dnssec_ip_limit_tbl == NULL) {
		RTE_LOG(ERR, ADNS, "[%s]: Failed to alloc dnssec_ip_limit_tbl\n", __FUNCTION__);
		return -1;
	}

	// dnssec global qps quota
	dnssec_global_limit = rte_zmalloc_socket("dnssec_global_limit", sizeof(qps_limit_st_t), 0, socket_id);
	if (dnssec_global_limit == NULL) {
		RTE_LOG(ERR, ADNS, "[%s]: Failed to alloc dnssec_global_limit\n", __FUNCTION__);
		return -1;
	}

	ip_limit_tbl = rte_zmalloc_socket("ip_limit_tbl", sizeof(qps_limit_st_t) * (IPLIMIT_SIZE+1), 0, socket_id);
	if (ip_limit_tbl == NULL) {
		RTE_LOG(ERR, ADNS, "[%s]: Failed to alloc ip_limit_tbl\n", __FUNCTION__);
		return -1;
	}

	TSC_HZ = rte_get_tsc_hz();
	TSC_100MS = (TSC_HZ + MS_PER_S - 1) / MS_PER_S * 100;

	return 0;
}
