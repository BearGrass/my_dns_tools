#define __STDC_LIMIT_MACROS
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <tr1/memory>
#include <arpa/inet.h>
#include "adnsapi.pb.h"
#include "adns_api_params.h"
#include "zonedb.h"
#include "zone.h"
#include "node.h"
#include "errcode.h"
#include "rcu.h"

using namespace std;
using namespace google;
extern "C" {
    int __add_zone(struct adns_zonedb *zonedb, const char *name, uint8_t *rdata, int rdata_len,
                            uint32_t ttl, uint8_t enable_cname_cascade, struct adns_zone **zone_added, char *err);
    int __del_zone(struct adns_zonedb *zonedb, const char *name, char *err);
    int __set_zone_dnssec(struct adns_zone *zone, int enable_dnssec, char *err);
}

tr1::shared_ptr<adnsapi::LookupZoneOutput> adns_api_zone_lookup(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::LookupZoneOutput> output(new ::adnsapi::LookupZoneOutput());
    ::adnsapi::RetCode ret_code;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;

    string * zoneName = NULL;
    adns_zone * zone = NULL;
    adnsapi::ZoneAttr * zoneAttr = NULL;
    adnsapi::ZoneAttr::Soa * soa = NULL;
    const adns_dname_t *soa_dname = NULL;
    int soa_dname_len = 0;
    char *domain_str = NULL;
    const uint32_t *soa_num32 = NULL;

    err_buf[0] = '\0';

    ::adnsapi::LookupZoneInput zoneNameInput;
    ret = zoneNameInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: deserialization failed.\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_zone_lookup]: deserialization failed.";
        goto FINISH;
    }

    zoneName = zoneNameInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    ret = adns_zonedb_get_zone(g_datacore_db, zoneName->c_str(), &zone, err_buf);
    if (ret < 0) {
        err = err_buf;
        log_server_warn(rte_lcore_id(), "[%s] find zone %s, ret = %d, FAILURE\n", 
                __FUNCTION__, zoneName->c_str(), ret);
        ret_code = ::adnsapi::RET_ERR_ZONE_LOOKUP_FAILURE;
        goto FINISH;
    }

    zoneAttr = output->mutable_zone_attr();
    zoneAttr->set_cname_opt( (zone->enable_cname_cascade == 1) ? true : false);
    zoneAttr->set_wildcard_opt(false);
    zoneAttr->set_private_route_opt(false);

    soa = zoneAttr->mutable_soa();

    soa_dname = zone->soa.data;
    domain_str = adns_dname_to_str(soa_dname);
    soa_dname_len = adns_dname_size(soa_dname);
    soa->set_ns(domain_str);
    free(domain_str);
    
    soa_dname = soa_dname + soa_dname_len;
    domain_str = adns_dname_to_str(soa_dname);
    soa_dname_len = adns_dname_size(soa_dname);
    soa->set_mail(domain_str);
    free(domain_str);
    
    soa_num32 = (const uint32_t *)(soa_dname + soa_dname_len);
    soa->set_serial(ntohl(*soa_num32));
    soa_num32++;
    soa->set_refresh(ntohl(*soa_num32));
    soa_num32++;
    soa->set_retry(ntohl(*soa_num32));
    soa_num32++;
    soa->set_expire(ntohl(*soa_num32));
    soa_num32++;
    soa->set_nxttl(ntohl(*soa_num32));

    log_server_warn(rte_lcore_id(), "[%s]: lookup zone %s, SUCCESS.\n",
            __FUNCTION__, zoneName->c_str());
    ret_code = adnsapi::RET_OK;
FINISH:
    output->mutable_base()->set_code(ret_code);
    output->mutable_base()->set_msg(err);
    return output;
}


tr1::shared_ptr<adnsapi::CommonOutput> adns_api_zone_setattr(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;

    string * zoneName = NULL;
    adns_zone * zone = NULL;

    adnsapi::ZoneAttr * zoneAttr = NULL;
    adnsapi::ZoneAttr::Soa * soa = NULL;

    int rdataLen = 0;
    char rdata[ADNS_SOA_RRLEN] = {0};

    ::adnsapi::SetZoneAttrInput setZoneAttrInput;
    ret = setZoneAttrInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: deserialization failed.\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_zone_setattr]: deserialization failed.";
        goto FINISH;
    }

    zoneName = setZoneAttrInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }
    ret = adns_zonedb_get_zone(g_datacore_db, zoneName->c_str(), &zone, err_buf);
    if (ret < 0) {
        err = err_buf;
        log_server_warn(rte_lcore_id(), "[%s] find zone %s, ret = %d, FAILURE\n", 
                __FUNCTION__, zoneName->c_str(), ret);
        ret_code = ::adnsapi::RET_ERR_ZONE_LOOKUP_FAILURE;
        goto FINISH;
    }

    zoneAttr = setZoneAttrInput.mutable_zone_attr();
    if (zoneAttr->has_soa() == true) {
        soa = zoneAttr->mutable_soa(); 
    	ret = ::adnsapi::Params::soa2Rdata(soa->ns(), soa->mail(), soa->serial(), soa->refresh(), 
            	soa->retry(), soa->expire(), soa->nxttl(), rdata, rdataLen, err);
    	if (ret < 0 ) {
        	log_server_warn(rte_lcore_id(), "[%s]: zone %s soa to rdata transform failed\n", 
                	__FUNCTION__, zoneName->c_str());
        	ret_code = ::adnsapi::RET_ERR_ZONE_ADD_FAILURE;
        	goto FINISH;
    	}
    	memcpy(zone->soa.data, rdata, rdataLen);
    	zone->soa.len = rdataLen;
        log_server_warn(rte_lcore_id(), "[%s]: zone %s soa to rdata transform ok, err=%s\n", 
				__FUNCTION__, zoneName->c_str(), err.c_str());
	}

    if (zoneAttr->has_cname_opt() == true) {
        zone->enable_cname_cascade = zoneAttr->cname_opt();
    }
    if (zoneAttr->has_wildcard_opt() == true) {
        zone->wildcard_fallback_enable = zoneAttr->wildcard_opt();
    }
    if (zoneAttr->has_private_route_opt() == true) {
        zone->private_route_enable = zoneAttr->private_route_opt();
    }
    if (zoneAttr->has_dnssec_opt() == true) {
        if (__set_zone_dnssec(zone, zoneAttr->dnssec_opt(), err_buf) < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: zone %s set dnssec_opt error\n", __FUNCTION__, zoneName->c_str());
        	ret_code = ::adnsapi::RET_ERR_DNSSEC_SET_ZONE_ERROR;
        	goto FINISH;
        }
    }

    log_server_warn(rte_lcore_id(), "[%s]: set zone %s attr, SUCCESS.\n",
            __FUNCTION__, zoneName->c_str());
    ret_code = adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_zone_add(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;

    string * zoneName = NULL;
    adns_zone * zone = NULL;
    int rdataLen = 0;
    char rdata[ADNS_SOA_RRLEN] = {0};

    ::adnsapi::AddZoneInput addZoneInput;
    ::adnsapi::ZoneAttr * zoneAttr = addZoneInput.mutable_zone_attr();
    ::adnsapi::ZoneAttr::Soa * soa = zoneAttr->mutable_soa();

    ret = addZoneInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: deserialization failed.\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_zone_add]: deserialization failed.";
        goto FINISH;
    }

    zoneName = addZoneInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateZoneName(*soa->mutable_ns(), err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate soa ns name %s error.\n", 
                __FUNCTION__, soa->mutable_ns()->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_SOA_NS_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateZoneName(*soa->mutable_mail(), err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate soa mail name %s error.\n", 
                __FUNCTION__, soa->mutable_mail()->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_SOA_MAIL_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::soa2Rdata(soa->ns(), soa->mail(), soa->serial(), soa->refresh(), 
            soa->retry(), soa->expire(), soa->nxttl(), rdata, rdataLen, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: zone %s soa to rdata transform failed\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_ZONE_ADD_FAILURE;
        goto FINISH;
    }
    
    ret = __add_zone(g_datacore_db, zoneName->c_str(), (uint8_t*)rdata, rdataLen, soa->nxttl(), zoneAttr->cname_opt(), NULL, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: zone %s adding failed\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_ZONE_ADD_FAILURE;
        err = err_buf;
        goto FINISH;
    }

    if (zoneAttr->has_dnssec_opt() == true) {
        ret = adns_zonedb_get_zone(g_datacore_db, zoneName->c_str(), &zone, err_buf);
        if (ret < 0) {
            err = err_buf;
            log_server_warn(rte_lcore_id(), "[%s] find zone %s, ret = %d, FAILURE\n", 
                    __FUNCTION__, zoneName->c_str(), ret);
            ret_code = ::adnsapi::RET_ERR_ZONE_LOOKUP_FAILURE;
            goto FINISH;
        }
        if (__set_zone_dnssec(zone, zoneAttr->dnssec_opt(), err_buf) < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: zone %s set dnssec_opt error\n", __FUNCTION__, zoneName->c_str());
        	ret_code = ::adnsapi::RET_ERR_DNSSEC_SET_ZONE_ERROR;
        	goto FINISH;
        }
    }

    log_server_warn(rte_lcore_id(), "[%s]: add zone %s, SUCCESS.\n",
            __FUNCTION__, zoneName->c_str());
    ret_code = adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_zone_del(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;
    string * zoneName = NULL;

    ::adnsapi::DelZoneInput delZoneInput;

    ret = delZoneInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: deserialization failed.\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_zone_del]: deserialization failed.";
        goto FINISH;
    }

    zoneName = delZoneInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    ret = __del_zone(g_datacore_db, zoneName->c_str(), err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: zone %s deletion failed\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_ZONE_ADD_FAILURE;
        err = err_buf;
        goto FINISH;
    }

    log_server_warn(rte_lcore_id(), "[%s]: delete zone %s, SUCCESS.\n",
            __FUNCTION__, zoneName->c_str());
    ret_code = adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}
