#ifndef _ADNS_SHARE_H_
#define _ADNS_SHARE_H_


extern uint32_t g_zone_num;
extern uint32_t g_dnssec_zone_num;
extern uint32_t g_dnssec_cache_num;
extern uint32_t g_private_route_zone_num;
extern uint32_t g_domain_num;
extern uint32_t g_rr_num;
extern uint32_t g_rdata_ctl_num;
extern uint32_t g_private_rdata_ctl_num;
extern uint32_t g_rrset_memory_num;
extern struct rr_detail_num_t{
    uint32_t A_num;
    uint32_t AAAA_num;
    uint32_t NS_num;
    uint32_t CNAME_num;
    uint32_t MX_num;
    uint32_t PTR_num;
    uint32_t TXT_num;
    uint32_t SRV_num;
    uint32_t CAA_num;
    uint32_t RRSIG_num;  // only for DNSKEY rrsig, other type rrset is signed online
} g_rr_detail_num;

#define INCREASE_RR_DETAIL_NUM(type, num) \
    do{ \
        switch((type)) { \
            case ADNS_RRTYPE_A: \
                g_rr_detail_num.A_num += (num); \
                break; \
            case ADNS_RRTYPE_AAAA: \
                g_rr_detail_num.AAAA_num += (num); \
                break; \
            case ADNS_RRTYPE_NS: \
                g_rr_detail_num.NS_num += (num); \
                break; \
            case ADNS_RRTYPE_CNAME: \
                g_rr_detail_num.CNAME_num += (num); \
                break; \
            case ADNS_RRTYPE_MX: \
                g_rr_detail_num.MX_num += (num); \
                break; \
            case ADNS_RRTYPE_PTR: \
                g_rr_detail_num.PTR_num += (num); \
                break; \
            case ADNS_RRTYPE_TXT: \
                g_rr_detail_num.TXT_num += (num); \
                break; \
            case ADNS_RRTYPE_SRV: \
                g_rr_detail_num.SRV_num += (num); \
                break; \
            case ADNS_RRTYPE_CAA: \
                g_rr_detail_num.CAA_num += (num); \
                break; \
           default: \
                break; \
        } \
    }while(0)

#define INCREASE_RR_NUM(num) (g_rr_num += (num))
#define INCREASE_DOMAIN_NUM(num) (g_domain_num += (num))
#define INCREASE_ZONE_NUM(num) (g_zone_num += (num))
#define INCREASE_DNSSEC_ZONE_NUM(num) (g_dnssec_zone_num += (num))
#define INCREASE_DNSSEC_CACHE_NUM(num) (g_dnssec_cache_num += (num))
#define INCREASE_PRIVATE_ROUTE_ZONE_NUM(num) (g_private_route_zone_num += (num))
#define INCREASE_RDATA_CTL_NUM(num) (g_rdata_ctl_num += (num))
#define INCREASE_PRIVATE_RDATA_CTL_NUM(num) (g_private_rdata_ctl_num += (num))
#define INCREASE_RRSET_MEMORY_NUM(num) (g_rrset_memory_num += (num))


#define DECREASE_RR_DETAIL_NUM(type, num) \
    do{ \
        switch((type)) { \
            case ADNS_RRTYPE_A: \
                g_rr_detail_num.A_num -= (num); \
                break; \
            case ADNS_RRTYPE_AAAA: \
                g_rr_detail_num.AAAA_num -= (num); \
                break; \
            case ADNS_RRTYPE_NS: \
                g_rr_detail_num.NS_num -= (num); \
                break; \
            case ADNS_RRTYPE_CNAME: \
                g_rr_detail_num.CNAME_num -= (num); \
                break; \
            case ADNS_RRTYPE_MX: \
                g_rr_detail_num.MX_num -= (num); \
                break; \
            case ADNS_RRTYPE_PTR: \
                g_rr_detail_num.PTR_num -= (num); \
                break; \
            case ADNS_RRTYPE_TXT: \
                g_rr_detail_num.TXT_num -= (num); \
                break; \
            case ADNS_RRTYPE_SRV: \
                g_rr_detail_num.SRV_num -= (num); \
                break; \
            case ADNS_RRTYPE_CAA: \
                g_rr_detail_num.CAA_num -= (num); \
                break; \
           default: \
                break; \
        } \
    }while(0)

#define DECREASE_RR_NUM(num) (g_rr_num -= (num))
#define DECREASE_DOMAIN_NUM(num) (g_domain_num -= (num))
#define DECREASE_ZONE_NUM(num) (g_zone_num -= (num))
#define DECREASE_DNSSEC_ZONE_NUM(num) (g_dnssec_zone_num -= (num))
#define DECREASE_DNSSEC_CACHE_NUM(num) (g_dnssec_cache_num -= (num))
#define DECREASE_PRIVATE_ROUTE_ZONE_NUM(num) (g_private_route_zone_num -= (num))
#define DECREASE_RDATA_CTL_NUM(num) (g_rdata_ctl_num -= (num))
#define DECREASE_PRIVATE_RDATA_CTL_NUM(num) (g_private_rdata_ctl_num -= (num))
#define DECREASE_RRSET_MEMORY_NUM(num) (g_rrset_memory_num -= (num))


#endif
