#define __STDC_LIMIT_MACROS
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <string>
#include <iostream>
#include <tr1/memory>
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

extern "C" {
extern int __add_zone(struct adns_zonedb *zonedb, const char *name, uint8_t *rdata, int rdata_len, uint32_t ttl,
        uint8_t enable_cname_cascade, struct adns_zone **zone_added, char *err);
extern int adns_zone_get_node(struct adns_zone *zone, const char *domain, struct adns_node **p_node, char *err);
extern void cmd_set_err(char *str, const char *fmt, ...);
extern int do_replace_zone(const char * name, struct adns_zone * old_zone, struct adns_zone * new_zone, char *err);
extern int adns_zone_add_rr(struct adns_zone *zone, const char *domain, uint8_t custom_view, adns_viewid_t view_id,
        uint16_t type, uint32_t ttl, char *rdata, int rdata_len, int weight, const char *original_rdata, char *err,
        struct adns_node ** p_node);
extern int __set_zone_dnssec(struct adns_zone *zone, int enable_dnssec, char *err);
extern int __add_zone_dnskeyrrsig(struct adns_zone *zone, uint8_t *sig, uint16_t sig_len, 
                      uint16_t tag_num, uint16_t active_key, uint16_t alt_zsk_tag, char *err);
int __schedule_mode_set_node(struct adns_node *node, const char *domain_str, uint16_t type,
                            uint8_t custom_view, adns_viewid_t view_id, uint8_t sche_set_to_line, uint8_t mode, char *err);
}

typedef protobuf::Map< string, ::adnsapi::DomainAttrRrlist > DomainMap;
typedef protobuf::Map< string, ::adnsapi::DomainAttrRrlist >::iterator DomainMapIter;

int refreshzone_create_dangled_zone(const char * zone_str, ::adnsapi::ZoneAttr * zoneAttr,
        adns_zone ** p_old_zone, adns_zone ** p_new_zone, string & err)
{
    int ret = -1;
    adns_zone * old_zone = NULL;
    adns_zone * new_zone = NULL;
    char err_buf[CMD_RESP_ERR_LEN];
    char rdata_buf[ADNS_SOA_RRLEN];
    int rdata_len = 0;
    const ::adnsapi::ZoneAttr::Soa & soa = zoneAttr->soa();

    err_buf[0] = '\0';
    rdata_buf[0] ='\0';

    ret = adns_zonedb_get_zone(g_datacore_db, zone_str, &old_zone, err_buf);
    if (ret < 0 && ret != -3) {
        log_server_warn(rte_lcore_id(), "[%s] find old zone %s, ret = %d, FAILURE\n", __FUNCTION__, zone_str, ret);
        ret = -1;
        goto FINISH;
    }
    err_buf[0] = '\0'; // if zone do not exist, adns_zonedb_get_zone will set the err_buf, clear it here.

    ret = ::adnsapi::Params::soa2Rdata(soa.ns(), soa.mail(), soa.serial(), soa.refresh(), soa.retry(),
            soa.expire(), soa.nxttl(), rdata_buf, rdata_len, err);
    if (ret < 0) {
        ret = -2;
        goto FINISH;
    }

    ret = __add_zone(NULL, zone_str, (uint8_t*)rdata_buf, rdata_len, soa.nxttl(), zoneAttr->cname_opt(), &new_zone, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s] create dangled new zone %s, ret = %d, FAILURE\n",
                __FUNCTION__, zone_str, ret);
        ret = -3;
        goto FINISH;
    }
    
    new_zone->soa.sn = soa.serial();

    *p_old_zone = old_zone;
    *p_new_zone = new_zone;

FINISH:
    if (strlen(err_buf) != 0)
        err = err_buf;
    return ret;
}

int refreshzone_set_domain_attr(adns_zone * zone, const string & domainName, ::adnsapi::SchdlMode mode, uint32_t mode4a, string & err)
{
    int ret = -1;
    adns_node *node = NULL;
    char err_buf[CMD_RESP_ERR_LEN];

    err_buf[0] = '\0';

    ret = adns_zone_get_node(zone, domainName.c_str(), &node, err_buf);
    if (ret < 0) {
        cmd_set_err(err_buf, "[%s]: fail to get node %s when set schedule mode, "
                "check if a record is added before this entry.\n", __FUNCTION__, domainName.c_str());
        log_server_warn(rte_lcore_id(), "[%s]: get node %s when set schedule mode, FAILURE\n",
                __FUNCTION__, domainName.c_str());
        ret = ADNS_ADMIN_REFRESH_ZONE_SET_SCHED_ERROR;
        goto FINISH;
    }
    node->A_schedule_mode = mode;
    node->AAAA_schedule_mode = mode4a & 0x1;

FINISH:
    if (strlen(err_buf) != 0)
        err = err_buf;
    return ret;
}

int refreshzone_attach_rr(adns_zone * zone, const string & domainName, ::adnsapi::Rr & rr, uint8_t is_custom,
        int view_id, char * rdata, int rdata_len, string & err, adns_node ** p_node)
{
    int ret = -1;
    char err_buf[CMD_RESP_ERR_LEN];

    err_buf[0] = '\0';

    ret = adns_zone_add_rr(zone, domainName.c_str(), is_custom, view_id, rr.rr_index().rrtype(), rr.rr_attr().ttl(),
            rdata, rdata_len, rr.rr_attr().weight(), rr.rr_index().rdata().c_str(), err_buf, p_node); 
    if (ret < 0) {
        err = err_buf;
        log_server_warn(rte_lcore_id(), "[%s] attach record to new zone, ret = %d, FAILURE\n", __FUNCTION__, ret);
        return ret;
    }
    return 0;
}

int refreshzone_replace(const string & zoneName, adns_zone * old_zone, adns_zone * new_zone, string & err)
{
    int ret = -1;
    char err_buf[CMD_RESP_ERR_LEN];

    err_buf[0] = '\0';

    ret = do_replace_zone(zoneName.c_str(), old_zone, new_zone, err_buf);
    if (ret < 0) {
        cmd_set_err(err_buf, "[%s]: fail to replace zone, ret = %d\n", __FUNCTION__, ret);
        log_server_warn(rte_lcore_id(), "[%s]: replace zone, ret = %d\n, FAILURE", __FUNCTION__, ret);
        ret = ADNS_ADMIN_REFRESH_ZONE_REPLACE_ERROR;
    }

    typedef void (*pfn) (void *);
    ret = call_rcu( (pfn)adns_zone_free, old_zone);
    if (ret < 0) {
        cmd_set_err(err_buf, "[%s]: fail to register rcu event\n", __FUNCTION__);
        log_server_warn(rte_lcore_id(), "[%s] register rcu event, ret = %d, FAILURE\n", __FUNCTION__);
        ret = ADNS_ADMIN_REFRESH_ZONE_RCU_REGISTER_ERROR;
    }

    if (strlen(err_buf) != 0)
        err = err_buf;
    return ret;
}

// TODO: log printing
shared_ptr<adnsapi::CommonOutput> adns_api_zone_refresh(char * querybuf, uint32_t querysize)
{
    shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];

    adns_zone * old_zone = NULL;
    adns_zone * new_zone = NULL;

    DomainMap * domains = NULL;
    ::adnsapi::ZoneAttr * zoneAttr = NULL;
    ::adnsapi::ZoneAttr::Soa * soa = NULL;
    ::adnsapi::DnskeyRrsigAttr *dnskeyRrsigAttr = NULL;
    ::adnsapi::Rrsig *rrsig = NULL;

    ::google::protobuf::uint32 tag_num;
    ::google::protobuf::uint32 alt_zsk;
    ::google::protobuf::uint32 active_zsk;

    string * zoneName = NULL;
    int ret = -1;
    uint8_t is_custom_view = 0;

    int view_id = -1;
    ::adnsapi::LineAttr *line_attr = NULL;

    ::adnsapi::RefreshZoneInput rzInput;
    ret = rzInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_refreshzone]: deserialization failed.";
        goto FINISH;
    }

    zoneName = rzInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    zoneAttr = rzInput.mutable_zone_attr();
    soa = zoneAttr->mutable_soa();
    ret = ::adnsapi::Params::validateDomainName(*soa->mutable_ns(), err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate soa ns name %s error.\n", __FUNCTION__, soa->ns().c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_SOA_NS_INVALID;
        goto FINISH;
    }
    ret = ::adnsapi::Params::validateDomainName(*soa->mutable_mail(), err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate soa mail name %s error.\n", __FUNCTION__, soa->mail().c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_SOA_MAIL_INVALID;
        goto FINISH;
    }

    ret = refreshzone_create_dangled_zone(zoneName->c_str(), zoneAttr, &old_zone, &new_zone, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: dangled zone %s creation error.\n", __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_CREATE_DANGLED_ZONE_FAILURE;
        goto FINISH;
    }

    // if dnssec_opt is set
    if (zoneAttr->has_dnssec_opt()) {
        ret = __set_zone_dnssec(new_zone, zoneAttr->dnssec_opt(), err_buf);
        if (ret < 0) {
            adns_zone_free(new_zone);
            log_server_warn(rte_lcore_id(), "[%s]: set dnssec opt %d for zone %s error.\n", __FUNCTION__, zoneAttr->dnssec_opt(), zoneName->c_str());
            ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_CREATE_DANGLED_ZONE_FAILURE;
            goto FINISH;
        }
    }

    // if dnskey_rrsig_attr is set
    if (rzInput.has_dnskey_rrsig_attr()) {
        char rdata[ADNS_SOA_RRLEN]; // ADNS_SOA_RRLEN is large enough for rrsig rdata
        int rdata_len;

        dnskeyRrsigAttr = rzInput.mutable_dnskey_rrsig_attr();
        rrsig = dnskeyRrsigAttr->mutable_rrsig();
        ret = ::adnsapi::Params::rrsig2Rdata(rrsig->type_covered(), rrsig->algorithm(), rrsig->labels(),
                    rrsig->original_ttl(), rrsig->signature_expiration(), rrsig->signature_inception(), rrsig->key_tag(), 
                    rrsig->signer(), rrsig->signature(),
                    rdata, rdata_len, err);
        if (ret < 0) {
            adns_zone_free(new_zone);
            log_server_warn(rte_lcore_id(), "[%s]: convert RRsig error %u\n", __FUNCTION__);
            ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_ADD_DNSKEY_RRSIG_FAILURE;
            err = err_buf;
            goto FINISH;
        }

        tag_num = dnskeyRrsigAttr->tag_num();
        if (tag_num < 1 || tag_num > 2) {
            adns_zone_free(new_zone);
            log_server_warn(rte_lcore_id(), "[%s]: invalid key tag num %u\n", __FUNCTION__, tag_num);
            ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_ADD_DNSKEY_RRSIG_FAILURE;
            err = err_buf;
            goto FINISH;
        }

        alt_zsk = dnskeyRrsigAttr->alt_zsk();
        if (alt_zsk > max_key_tag) {
            adns_zone_free(new_zone);
            log_server_warn(rte_lcore_id(), "[%s]: invalid key tag %u\n", __FUNCTION__, alt_zsk);
            ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_ADD_DNSKEY_RRSIG_FAILURE;
            err = err_buf;
            goto FINISH;
        }

        active_zsk = dnskeyRrsigAttr->active_zsk();
        if (active_zsk > max_key_tag) {
            adns_zone_free(new_zone);
            log_server_warn(rte_lcore_id(), "[%s]: invalid key tag %u\n", __FUNCTION__, active_zsk);
            ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_ADD_DNSKEY_RRSIG_FAILURE;
            err = err_buf;
            goto FINISH;
        }
        ret = __add_zone_dnskeyrrsig(new_zone, (uint8_t*)rdata, (uint16_t)rdata_len, (uint16_t)tag_num, (uint16_t)active_zsk, (uint16_t)alt_zsk, err_buf);
        if (ret < 0) {
            adns_zone_free(new_zone);
            log_server_warn(rte_lcore_id(), "[%s]: add dnskey rrsig error %u\n", __FUNCTION__);
            ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_ADD_DNSKEY_RRSIG_FAILURE;
            err = err_buf;
            goto FINISH;
        }
    }

    /* { domain_name: domain_attributes, ... } */
    domains = rzInput.mutable_domains();
    for (DomainMapIter dmIter = domains->begin(); dmIter != domains->end(); dmIter++) {
        adns_node * node = NULL;

        string domainName = dmIter->first; // map key would always be const, so copy
        ::adnsapi::DomainAttrRrlist & dmAttrRrlist = dmIter->second;

        ret = ::adnsapi::Params::validateDomainName(domainName, err, *zoneName);
        if (ret < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: validate domain name %s error.\n", __FUNCTION__, domainName.c_str());
            ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
            adns_zone_free(new_zone);
            goto FINISH;
        }

        /* rrlist[] */
        for (int i = 0; i < dmAttrRrlist.rrlist_size(); i++) {
            char rdata[TXT_MAX_SIZE];
            int rdata_len = 0;
            ::adnsapi::Rr* rr = dmAttrRrlist.mutable_rrlist(i);

            view_id = ::adnsapi::Params::parseViewStr(*rr->mutable_rr_index()->mutable_view(), rr->mutable_rr_index()->cview(), is_custom_view, err);
            if (view_id < 0) {
                log_server_warn(rte_lcore_id(), "[%s]: invalid view %s.\n", __FUNCTION__, rr->rr_index().view().c_str());
                ret_code = ::adnsapi::RET_ERR_PARAMS_RR_VIEW_INVALID;
                adns_zone_free(new_zone);
                goto FINISH;
            }
            ret = ::adnsapi::Params::validateRrclass(*rr->mutable_rr_index()->mutable_rrclass(), err);
            if (ret < 0) {
                log_server_warn(rte_lcore_id(), "[%s]: invalid rr class %s.\n", __FUNCTION__, rr->rr_index().rrclass().c_str());
                ret_code = ::adnsapi::RET_ERR_PARAMS_RR_CLASS_INVALID;
                adns_zone_free(new_zone);
                goto FINISH;
            }
            ret = ::adnsapi::Params::parseRdata(*zoneName, domainName, *rr->mutable_rr_index()->mutable_rdata(),
                        rr->rr_index().rrtype(), rdata, rdata_len, err);
            if (ret < 0) {
                log_server_warn(rte_lcore_id(), "[%s]: parsing rdata error, rdata %s, rrtype %d.\n",
                        __FUNCTION__, rr->rr_index().rdata().c_str(), rr->rr_index().rrtype());
                ret_code = ::adnsapi::RET_ERR_PARAMS_RR_RDATA_INVALID;
                adns_zone_free(new_zone);
                goto FINISH;
            }
            ret = ::adnsapi::Params::validateWeight(rr->rr_attr().weight(), err, rr->rr_index().rrtype());
            if (ret < 0) {
                log_server_warn(rte_lcore_id(), "[%s]: invalid rr weight %d.\n", __FUNCTION__, rr->rr_attr().weight());
                ret_code = ::adnsapi::RET_ERR_PARAMS_RR_WEIGHT_INVALID;
                adns_zone_free(new_zone);
                goto FINISH;
            }

            ret = refreshzone_attach_rr(new_zone, domainName, *rr, is_custom_view, view_id, rdata, rdata_len, err, &node);
            if (ret < 0) {
                log_server_warn(rte_lcore_id(), "[%s]: failed to attach rr (name %s type %d, rdata %s) to dangled zone %s.\n",
                        __FUNCTION__, domainName.c_str(), rr->rr_index().rrtype(), rr->rr_index().rdata().c_str(), zoneName->c_str());
                ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_ATTACH_RR_FAILURE;
                adns_zone_free(new_zone);
                goto FINISH;
            }
            
        }
        if (dmAttrRrlist.rrlist_size() != 0) { // to have a domain, we have to add a rr
            ret = refreshzone_set_domain_attr(new_zone, domainName, dmAttrRrlist.domain_attr().schdl_mode(), dmAttrRrlist.domain_attr().schdl_mode_4a(), err);
            if (ret < 0) {
                log_server_warn(rte_lcore_id(), "[%s]: set domain %s attributes error.\n", __FUNCTION__, domainName.c_str());
                ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_SET_DOMAIN_ATTR_FAILURE;
                adns_zone_free(new_zone);
                goto FINISH;
            }
        }

        for (int i = 0; i < dmAttrRrlist.line_attrs_size(); i++) {
            line_attr = dmAttrRrlist.mutable_line_attrs(i);
            is_custom_view = 0;
            if (line_attr != NULL) {
                if (line_attr->schdl_type() != ::adnsapi::RRTYPE_A && line_attr->schdl_type() != ::adnsapi::RRTYPE_AAAA) {
                    log_server_warn(rte_lcore_id(), "[%s]: Set line algorithm, invalid type %u.\n", __FUNCTION__, line_attr->schdl_type());
                    ret_code = ::adnsapi::RET_ERR_PARAMS_LINE_ATTR_TYPE_INVALID;
                    err = err_buf;
                    adns_zone_free(new_zone);
                    goto FINISH;
                }
                view_id = ::adnsapi::Params::parseViewStr(*line_attr->mutable_view(), line_attr->cview(), is_custom_view, err);
                if (view_id < 0) {
                    log_server_warn(rte_lcore_id(), "[%s]: invalid view %s.\n", __FUNCTION__, line_attr->view().c_str());
                    ret_code = ::adnsapi::RET_ERR_PARAMS_LINE_ATTR_VIEW_INVALID;
                    err = err_buf;
                    adns_zone_free(new_zone);
                    goto FINISH;
                }
                if (__schedule_mode_set_node(node, domainName.c_str(), line_attr->schdl_type(), is_custom_view, view_id, 1, line_attr->schdl_mode(), err_buf) != 0) {
                    ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_SET_LINE_ALGORITHM_FAILURE;
                    err = err_buf;
                    adns_zone_free(new_zone);
                    if (is_custom_view == 0) {
                        log_server_warn(rte_lcore_id(), "[%s]: Set schedule mode for domain: %s, type: %u, view: %s error", 
                                                __FUNCTION__, domainName.c_str(), line_attr->schdl_type(), line_attr->view().c_str());
                    } else {
                        log_server_warn(rte_lcore_id(), "[%s]: Set schedule mode for domain: %s, type: %u, custome view: %u error", 
                                                __FUNCTION__, domainName.c_str(), line_attr->schdl_type(), line_attr->cview());
                    }
                    goto FINISH;
                }
            }
        }
    }

    ret = refreshzone_replace(*zoneName, old_zone, new_zone, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: replace zone %s error.\n", __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_ZONE_REFRESH_REPLACE_FAILURE;
        adns_zone_free(new_zone);
        goto FINISH;
    }

    log_server_warn(rte_lcore_id(), "[%s]: refresh zone %s, SUCCESS.\n", __FUNCTION__, zoneName->c_str());
    ret_code = ::adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}
