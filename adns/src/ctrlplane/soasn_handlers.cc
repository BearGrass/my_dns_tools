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
using namespace std::tr1;
using namespace google;

shared_ptr<adnsapi::LookupSoaSnOutput> adns_api_lookupsoasn(char * querybuf, uint32_t querysize)
{
    shared_ptr<adnsapi::LookupSoaSnOutput> output(new ::adnsapi::LookupSoaSnOutput());
    ::adnsapi::RetCode ret_code;
    string err;
    string * zoneName = NULL;
    adns_zone * zone = NULL;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;

    err_buf[0] = '\0';

    ::adnsapi::ZoneNameInput zoneNameInput;
    ret = zoneNameInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_lookupsoasn]: deserialization failed.";
        goto FINISH;
    }

    zoneName = zoneNameInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    ret = adns_zonedb_get_zone(g_datacore_db, zoneName->c_str(), &zone, err_buf);
    if (ret < 0) {
        err = err_buf;
        log_server_warn(rte_lcore_id(), "[%s] find zone %s, ret = %d, FAILURE\n", __FUNCTION__, zoneName->c_str(), ret);
        ret_code = ::adnsapi::RET_ERR_LOOKUP_SOA_SN_FIND_ZONE_FAILURE;
        goto FINISH;
    }
    output->set_sn(zone->soa.sn);

    log_server_warn(rte_lcore_id(), "[%s]: lookup zone %s soa sn (=%u), SUCCESS.\n",
            __FUNCTION__, zoneName->c_str(), zone->soa.sn);
    ret_code = adnsapi::RET_OK;
FINISH:
    output->mutable_base()->set_code(ret_code);
    output->mutable_base()->set_msg(err);
    return output;
}


shared_ptr<adnsapi::CommonOutput> adns_api_setsoasn(char * querybuf, uint32_t querysize)
{
    shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code;
    string err;
    string * zoneName = NULL;
    adns_zone * zone = NULL;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;
    uint8_t * zone_soa = NULL;
    uint8_t * lp = NULL;
    uint32_t new_sn = 0;

    ::adnsapi::SetSoaSnInput setSoaSnInput;
    ret = setSoaSnInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_lookupsoasn]: deserialization failed.";
        goto FINISH;
    }

    zoneName = setSoaSnInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    new_sn = setSoaSnInput.sn();

    ret = adns_zonedb_get_zone(g_datacore_db, zoneName->c_str(), &zone, err_buf);
    if (ret < 0) {
        err = err_buf;
        log_server_warn(rte_lcore_id(), "[%s] find zone %s, ret = %d, FAILURE\n", __FUNCTION__, zoneName->c_str(), ret);
        ret_code = ::adnsapi::RET_ERR_LOOKUP_SOA_SN_FIND_ZONE_FAILURE;
        goto FINISH;
    }

    zone_soa = zone->soa.data;
    lp = zone_soa;
    do { // by pass soa ns
        lp = adns_wire_next_label(lp);
    } while(*lp != '\0');
    lp += 1;
    do { // by pass soa mail
        lp = adns_wire_next_label(lp);
    } while(*lp != '\0');
    lp += 1;

    zone->soa.sn = new_sn;
    *(uint32_t*)(lp) = (uint32_t)htonl(new_sn);

    log_server_warn(rte_lcore_id(), "[%s]: increase zone %s soa sn to %u, SUCCESS.\n",
            __FUNCTION__, zoneName->c_str(), zone->soa.sn);
    ret_code = adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}
