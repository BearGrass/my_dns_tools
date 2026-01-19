#define __STDC_LIMIT_MACROS
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <tr1/memory>
#include <map>
#include "adnsapi.pb.h"
#include "log.h"
#include "rr_handlers.h"
#include "zone_handlers.h"
#include "refreshzone_handlers.h"
#include "domain_handlers.h"
#include "soasn_handlers.h"
#include "dnssec_handlers.h"

using namespace std;

extern "C" {
int adns_api_dispatch(char * querybuf, uint32_t querysize, char * respbuf, uint32_t * p_respsize);
}

typedef enum __cmd_index {
    NOT_EXIST = 0,

    ADD_ZONE,
    DEL_ZONE,
    LOOKUP_ZONE,
    SET_ZONE_ATTR,
    REFRESH_ZONE,

    ADD_DOMAIN,
    DEL_DOMAIN,
    LOOKUP_DOMAIN,
    SET_DOMAIN_ATTR,
    REFRESH_DOMAIN,

    ADD_RR,
    DEL_RR,
    LOOKUP_RR,
    SET_RR_ATTR,

	LOOKUP_SOA_SN,
    SET_SOA_SN,

    SET_DNSSEC,
    ADD_KEY,
    DEL_ZSK,
    ADD_DNSKEY_RRSIG,
}cmd_index_t;

class Api_index
{
    /* make use of the std::map (RB-tree) to do the cmd name mapping */
    map<string, cmd_index_t> _index;

    public:
    Api_index()
    {
        /* cmd string (wire format) --> cmd index */
        _index["addzone"] = ADD_ZONE;
        _index["delzone"] = DEL_ZONE;
        _index["lookupzone"] = LOOKUP_ZONE;
        _index["setzoneattr"] = SET_ZONE_ATTR;
        _index["refreshzone"] = REFRESH_ZONE;

        _index["deldomain"] = DEL_DOMAIN;
        _index["lookupdomain"] = LOOKUP_DOMAIN;
        _index["setdomainattr"] = SET_DOMAIN_ATTR;
        _index["refreshdomain"] = REFRESH_DOMAIN;

        _index["addrr"] = ADD_RR;
        _index["delrr"] = DEL_RR;
        _index["lookuprr"] = LOOKUP_RR;
        _index["setrrattr"] = SET_RR_ATTR;

        _index["lookupsoasn"] = LOOKUP_SOA_SN;
        _index["setsoasn"] = SET_SOA_SN;

        _index["setdnssec"] = SET_DNSSEC;
        _index["addkey"] = ADD_KEY;
        _index["delzsk"] = DEL_ZSK;
        _index["adddnskeyrrsig"] = ADD_DNSKEY_RRSIG;
    }

    cmd_index_t operator[](const string & api_str) const
    {
        map<string, cmd_index_t>::const_iterator it = _index.find(api_str);
        if (it == _index.end())
            return NOT_EXIST;
        else
            return it->second;
    }
};
const Api_index g_api_index;

int adns_api_dispatch(char * querybuf, uint32_t querysize, char * respbuf, uint32_t * p_respsize)
{
    /* safely check command name length is under 32 */
    const uint32_t CMD_NAME_LEN = 32;
    size_t cmd_len = 0;

    querybuf[CMD_NAME_LEN - 1] = '\0';
    cmd_len = strlen(querybuf);

    string adnsapi_type(querybuf, cmd_len);
    switch (g_api_index[adnsapi_type]) {
        case REFRESH_ZONE: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_zone_refresh(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case REFRESH_DOMAIN: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_domain_refresh(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case ADD_RR: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_rr_add(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case DEL_RR: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_rr_del(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case LOOKUP_RR: {
            tr1::shared_ptr<adnsapi::LookupRrOutput> output;
            output = adns_api_rr_lookup(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case SET_RR_ATTR: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_rr_setattr(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case ADD_ZONE: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_zone_add(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case DEL_ZONE: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_zone_del(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case LOOKUP_ZONE: {
            tr1::shared_ptr<adnsapi::LookupZoneOutput> output;
            output = adns_api_zone_lookup(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case SET_ZONE_ATTR: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_zone_setattr(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case SET_DOMAIN_ATTR: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_domain_setattr(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case LOOKUP_DOMAIN: {
            tr1::shared_ptr<adnsapi::LookupDomainOutput> output;
            output = adns_api_domain_lookup(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            break;
        }
        case DEL_DOMAIN: {
            tr1::shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_domain_del(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            return 0;
        }
        case LOOKUP_SOA_SN: {
            shared_ptr<adnsapi::LookupSoaSnOutput> output;
            output = adns_api_lookupsoasn(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            return 0;
        }
        case SET_SOA_SN: {
            shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_setsoasn(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            return 0;
        }
        case SET_DNSSEC: {
            shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_setdnssec(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            return 0;
        }
        case ADD_KEY: {
            shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_addkey(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            return 0;
        }
        case DEL_ZSK: {
            shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_delzsk(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            return 0;
        }
        case ADD_DNSKEY_RRSIG: {
            shared_ptr<adnsapi::CommonOutput> output;
            output = adns_api_adddnskeyrrsig(querybuf + CMD_NAME_LEN, querysize - CMD_NAME_LEN);
            *p_respsize = output->ByteSizeLong();
            output->SerializeToArray(respbuf, *p_respsize);
            return 0;
        }
        default:
            log_server_error(0, "[%s] cmd name unregistered, cmd name: %s.\n", __FUNCTION__, querybuf);
            return -1;
    }

    return 0;
}


