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
#include "refreshzone_handlers.h"

using namespace std;
using namespace google;
extern "C" {
int __del_domain(struct adns_zonedb *zonedb, const char *zone_str, const char *domain, uint8_t custom_view, adns_viewid_t view_id, char *err);
int __del_domain_all(struct adns_zonedb *zonedb, const char *zone_str, const char *domain, char *err);
int __schedule_mode_set(struct adns_zonedb *zonedb, const char *zone_str, const char *domain_str, uint16_t type, 
                        uint8_t custom_view, adns_viewid_t view_id, uint8_t sche_set_to_line, uint8_t mode, char *err);
int adns_zone_get_node(struct adns_zone *zone, const char *domain, struct adns_node **p_node, char *err);
void cmd_set_err(char *str, const char *fmt, ...);
int __refresh_domain_create_node_dangled(struct adns_zone * zone, const char *domain,
        struct adns_node * old_node_parent, struct adns_node * old_node_child, struct adns_node ** p_node, char *err);
int adns_node_add_rr(struct adns_node *node, const char *domain, uint8_t custom_view, adns_viewid_t view_id, uint16_t type, uint32_t ttl,
        const char *rdata, int rdata_len, int weight, const char *original_rdata, char *err);
int do_replace_node(struct adns_zone *zone, const char * domain_name, struct adns_node *old_node, struct adns_node *new_node,
        adns_viewid_t ns_view_list[], adns_viewid_t view_list[], char * err_buf);
int adns_zone_add_rr(struct adns_zone *zone, const char *domain, uint8_t custom_view, adns_viewid_t view_id, adns_type_t type, 
        uint32_t ttl, char *rdata, int rdata_len, int weight, const char *original_rdata, char *err, struct adns_node ** p_node);
int __schedule_mode_set_node(struct adns_node *node, const char *domain_str, uint16_t type,
                            uint8_t custom_view, adns_viewid_t view_id, uint8_t sche_set_to_line, uint8_t mode, char *err);
}

int lookup_domain(const char * zone_str, const char * domain_str, uint8_t & schdl_mode, char * err_buf)
{
    int ret = -1;
    adns_zone * zone = NULL;
    adns_node * node = NULL;

    ret = adns_zonedb_get_zone(g_datacore_db, zone_str, &zone, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: find zone %s, ret = %d, FAILURE\n", __FUNCTION__, zone_str, ret);
        return -1;
    }

    ret = adns_zone_get_node(zone, domain_str, &node, err_buf);
    if (ret < 0) {
        cmd_set_err(err_buf, "[%s]: fail to get node %s.", __FUNCTION__, domain_str);
        log_server_warn(rte_lcore_id(), "[%s]: fail to get node %s.", __FUNCTION__, domain_str);
        return -2;
    }

    schdl_mode = node->A_schedule_mode | node->AAAA_schedule_mode;

    return 0;
}

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_domain_del(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code = ::adnsapi::RET_OK;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;
    int view_id = -1;
    uint8_t is_custom_view = 0;

    string * zoneName = NULL, * domainName = NULL, *view_name = NULL;

    ::adnsapi::DelDomainInput delDomainInput;
    ret = delDomainInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: deserialization failed.\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_domain_del]: deserialization failed.";
        goto FINISH;
    }

    zoneName = delDomainInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    domainName = delDomainInput.mutable_domain_name();
    ret = ::adnsapi::Params::validateDomainName(*domainName, err, *zoneName);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate domain name %s error.\n", 
                __FUNCTION__, domainName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
        goto FINISH;
    }
    
    view_name = delDomainInput.mutable_view();
    if ( view_name->empty() &&  delDomainInput.cview() < 0) {
        ret = __del_domain_all(g_datacore_db, zoneName->c_str(), domainName->c_str(), err_buf);
        if (ret < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: del domain all view %s from zone %s error.\n", 
                    __FUNCTION__, domainName->c_str(), zoneName->c_str());
            ret_code = ::adnsapi::RET_ERR_DOMAIN_DEL_FAILURE;
            err = err_buf;
            goto FINISH;
        }
        log_server_warn(rte_lcore_id(), "[%s]: delete domain %s from zone %s, SUCCESS.\n",__FUNCTION__, domainName->c_str(), zoneName->c_str());
        goto FINISH;
    }

    view_id = ::adnsapi::Params::parseViewStr(*view_name, delDomainInput.cview(), is_custom_view, err);
    if (view_id < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate view %s error.\n", __FUNCTION__, view_name->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_VIEW_INVALID;
        goto FINISH;
    }
    
    ret = __del_domain(g_datacore_db, zoneName->c_str(), domainName->c_str(), is_custom_view, view_id, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: del domain %s from zone %s view %s error.\n", 
                __FUNCTION__, domainName->c_str(), zoneName->c_str(), view_name->c_str());
        ret_code = ::adnsapi::RET_ERR_DOMAIN_DEL_FAILURE;
        err = err_buf;
        goto FINISH;
    }
    log_server_warn(rte_lcore_id(), "[%s]: delete domain %s from zone %s, view %s, SUCCESS.\n",
            __FUNCTION__, domainName->c_str(), zoneName->c_str(), view_name->c_str());
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_domain_setattr(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code = ::adnsapi::RET_OK;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;
	uint16_t type;
    int view_id = -1, cview = -1;
    uint8_t is_custom_view = 0, sche_set_to_line = 0;

    string * zoneName = NULL, * domainName = NULL, * view_name = NULL;

    ::adnsapi::DomainAttr * domainAttr = NULL;
    ::adnsapi::SchdlMode mode;

    ::adnsapi::SetDomainAttrInput setDomainAttrInput;
    ret = setDomainAttrInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: deserialization failed.\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_domain_setattr]: deserialization failed.";
        goto FINISH;
    }

    zoneName = setDomainAttrInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    domainName = setDomainAttrInput.mutable_domain_name();
    ret = ::adnsapi::Params::validateDomainName(*domainName, err, *zoneName);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate domain name %s error.\n", 
                __FUNCTION__, domainName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
        goto FINISH;
    }

    if (setDomainAttrInput.has_view() == true) {
        view_name = setDomainAttrInput.mutable_view();
    }
    if (setDomainAttrInput.has_cview() == true) {
        cview = setDomainAttrInput.cview();
    }

    if ( (view_name == NULL || view_name->empty()) && cview < 0) {
        sche_set_to_line = 0;
    } else {
        view_id = ::adnsapi::Params::parseViewStr(*view_name, cview, is_custom_view, err);
        if (view_id < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: validate view %s error.\n", __FUNCTION__, view_name->c_str());
            ret_code = ::adnsapi::RET_ERR_PARAMS_RR_VIEW_INVALID;
            goto FINISH;
        }
        sche_set_to_line = 1;
    }
    

    domainAttr = setDomainAttrInput.mutable_domain_attr();
    mode = domainAttr->schdl_mode();
    type = (uint16_t)domainAttr->schdl_type();
    ret = __schedule_mode_set(g_datacore_db, zoneName->c_str(), domainName->c_str(), type, is_custom_view, view_id, sche_set_to_line, mode, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: set domain %s from zone %s schedule mode to %s (type=%d), ERROR.\n", 
                __FUNCTION__, domainName->c_str(), zoneName->c_str(), ::adnsapi::SchdlMode_Name(mode).c_str(), ::adnsapi::SchdlMode_Name(mode).c_str(), type);
        ret_code = ::adnsapi::RET_ERR_DOMAIN_SET_ATTR_FAILURE;
        err = err_buf;
        goto FINISH;
    }

    log_server_warn(rte_lcore_id(), "[%s]: set domain %s from zone %s attr, schedule mode to %s, SUCCESS.\n",
            __FUNCTION__, domainName->c_str(), zoneName->c_str(), ::adnsapi::SchdlMode_Name(mode).c_str());
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

tr1::shared_ptr<adnsapi::LookupDomainOutput> adns_api_domain_lookup(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::LookupDomainOutput> output(new ::adnsapi::LookupDomainOutput());
    ::adnsapi::RetCode ret_code = ::adnsapi::RET_OK;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;
    uint8_t mode = -1;

    string * zoneName = NULL, * domainName = NULL;

    ::adnsapi::LookupDomainInput lookupDomainInput;
    ret = lookupDomainInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: deserialization failed.\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_domain_lookup]: deserialization failed.";
        goto FINISH;
    }

    zoneName = lookupDomainInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    domainName = lookupDomainInput.mutable_domain_name();
    ret = ::adnsapi::Params::validateDomainName(*domainName, err, *zoneName);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate domain name %s error.\n", 
                __FUNCTION__, domainName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
        goto FINISH;
    }

    ret = lookup_domain(zoneName->c_str(), domainName->c_str(), mode, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: lookup domain %s from zone %s error.\n", 
                __FUNCTION__, domainName->c_str(), zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_DOMAIN_LOOKUP_FAILURE;
        err = err_buf;
        goto FINISH;
    }

    if (::adnsapi::SchdlMode_IsValid(mode) == false) {
        log_server_warn(rte_lcore_id(), "[%s]: internal schedule mode %d domain %s from zone %s, error.\n", 
                __FUNCTION__, mode, domainName->c_str(), zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_DOMAIN_LOOKUP_FAILURE;
        err = "adns internal schedule mode error";
        goto FINISH;
    }
    output->mutable_domain_attr()->set_schdl_mode((adnsapi::SchdlMode)mode);

    log_server_warn(rte_lcore_id(), "[%s]: set domain %s from zone %s attr: schedule mode %s, SUCCESS.\n",
            __FUNCTION__, domainName->c_str(), zoneName->c_str(), 
            ::adnsapi::SchdlMode_Name((::adnsapi::SchdlMode)mode).c_str());
FINISH:
    output->mutable_base()->set_code(ret_code);
    output->mutable_base()->set_msg(err);
    return output;
}

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_domain_refresh(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code = ::adnsapi::RET_OK;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;

    string * zoneName = NULL, * domainName = NULL;
    const char * domainName_cstr = NULL;
    ::adnsapi::DomainAttrRrlist * dmAttrRrlist = NULL;
    ::adnsapi::DomainAttr * domainAttr = NULL;
    struct adns_zone * zone = NULL;
    struct adns_node * old_node = NULL, * new_node = NULL, * node_hint = NULL;
    ::adnsapi::Rr* rr = NULL;
    ::adnsapi::LineAttr *line_attr = NULL;
    int view_id = -1;

    uint16_t total_view_num = g_view_max_num + g_private_route_per_zone_max_num;
    adns_viewid_t ns_view_list[total_view_num], view_list[total_view_num];
    memset(ns_view_list, 0, sizeof(adns_viewid_t) * total_view_num);
    memset(view_list, 0, sizeof(adns_viewid_t) * total_view_num);

    char rdata[TXT_MAX_SIZE];
    int rdata_len = 0;
    uint8_t is_custom_view = 0;

    ::adnsapi::RefreshDomainInput refreshDomainInput;
    ret = refreshDomainInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: deserialization failed.\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_domain_refresh]: deserialization failed.";
        goto FINISH;
    }

    zoneName = refreshDomainInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error.\n", 
                __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    domainName = refreshDomainInput.mutable_domain_name();
    ret = ::adnsapi::Params::validateDomainName(*domainName, err, *zoneName);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate domain name %s error.\n", 
                __FUNCTION__, domainName->c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
        goto FINISH;
    }

    domainName_cstr = domainName->c_str();
    dmAttrRrlist = refreshDomainInput.mutable_domain_attr_rrlist();
    domainAttr = dmAttrRrlist->mutable_domain_attr();

    ret = adns_zonedb_get_zone(g_datacore_db, zoneName->c_str(), &zone, err_buf);
    if (ret < 0) {
        err = err_buf;
        log_server_warn(rte_lcore_id(), "[%s]: find zone %s, ret = %d, FAILURE\n", __FUNCTION__, zoneName->c_str(), ret);
        ret_code = ::adnsapi::RET_ERR_DOMAIN_REFRESH_FIND_ZONE_FAILURE;
        goto FINISH;
   }

    ret = adns_zone_get_node(zone, domainName_cstr, &old_node, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: old node %s do not exists, refreshing continues.", __FUNCTION__, domainName_cstr);
        if (ret != -3) {
            err = err_buf;
            log_server_warn(rte_lcore_id(), "[%s]: find old node %s error.", __FUNCTION__, domainName_cstr);
            ret_code = ::adnsapi::RET_ERR_DOMAIN_REFRESH_FIND_ZONE_FAILURE;
            goto FINISH;
        }
    }

    if (old_node != NULL) {
        ret = __refresh_domain_create_node_dangled(zone, domainName_cstr, old_node->parent, old_node->wildcard_child, &new_node, err_buf);
        if (ret < 0 || new_node == NULL) {
            err = err_buf;
            ret_code = ::adnsapi::RET_ERR_DOMAIN_REFRESH_CREATE_DANGLED_DOMAIN_FAILURE;
            goto FINISH;
        }
        /* domain attr */
        new_node->AAAA_schedule_mode = domainAttr->schdl_mode_4a() & 0x1;
        new_node->A_schedule_mode = domainAttr->schdl_mode();
    }

    for (int i = 0; i < dmAttrRrlist->rrlist_size(); i++) {
        rdata[0] = '\0';
        rdata_len = 0;
        rr = dmAttrRrlist->mutable_rrlist(i);
        is_custom_view = 0;

        view_id = ::adnsapi::Params::parseViewStr(*rr->mutable_rr_index()->mutable_view(), rr->mutable_rr_index()->cview(), is_custom_view, err);
        if (view_id < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: invalid view %s.\n", __FUNCTION__, rr->rr_index().view().c_str());
            ret_code = ::adnsapi::RET_ERR_PARAMS_RR_VIEW_INVALID;
            adns_node_free(new_node);
            goto FINISH;
        }

        ret = ::adnsapi::Params::validateRrclass(*rr->mutable_rr_index()->mutable_rrclass(), err);
        if (ret < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: invalid rr class %s.\n", __FUNCTION__, rr->rr_index().rrclass().c_str());
            ret_code = ::adnsapi::RET_ERR_PARAMS_RR_CLASS_INVALID;
            adns_node_free(new_node);
            goto FINISH;
        }

        ret = ::adnsapi::Params::parseRdata(*zoneName, *domainName, *rr->mutable_rr_index()->mutable_rdata(),
                    rr->rr_index().rrtype(), rdata, rdata_len, err);
        if (ret < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: parsing rdata error, rdata %s, rrtype %d.\n",
                    __FUNCTION__, rr->rr_index().rdata().c_str(), rr->rr_index().rrtype());
            ret_code = ::adnsapi::RET_ERR_PARAMS_RR_RDATA_INVALID;
            adns_node_free(new_node);
            goto FINISH;
        }

        ret = ::adnsapi::Params::validateWeight(rr->rr_attr().weight(), err, rr->rr_index().rrtype());
        if (ret < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: invalid rr weight %d.\n", __FUNCTION__, rr->rr_attr().weight());
            ret_code = ::adnsapi::RET_ERR_PARAMS_RR_WEIGHT_INVALID;
            adns_node_free(new_node);
            goto FINISH;
        }

        if (old_node != NULL) {
            ret = adns_node_add_rr(new_node, domainName_cstr, is_custom_view, view_id, rr->rr_index().rrtype(), rr->rr_attr().ttl(),
                        rdata, rdata_len, rr->rr_attr().weight(), rr->rr_index().rdata().c_str(), err_buf);
            if (ret < 0) {
                adns_node_free(new_node);
                err = err_buf;
                ret_code = ::adnsapi::RET_ERR_DOMAIN_REFRESH_ATTACH_RR_FAILURE;
                goto FINISH;
            }
            if (rr->rr_index().rrtype() == ::adnsapi::RRTYPE_NS) {
                ns_view_list[is_custom_view ? view_id + g_view_max_num : view_id] = 1;
            }
            view_list[is_custom_view ? view_id + g_view_max_num : view_id] = 1;
        } else {
            ret = adns_zone_add_rr(zone, domainName->c_str(), is_custom_view, view_id, rr->rr_index().rrtype(), rr->rr_attr().ttl(),
                    rdata, rdata_len, rr->rr_attr().weight(), rr->rr_index().rdata().c_str(), err_buf, &node_hint);
            if (ret < 0) {
                adns_node_free(new_node);
                err = err_buf;
                ret_code = ::adnsapi::RET_ERR_DOMAIN_REFRESH_ATTACH_RR_FAILURE;
                goto FINISH;
            }
        }
    }

    for (int i = 0; i < dmAttrRrlist->line_attrs_size(); i++) {
        line_attr = dmAttrRrlist->mutable_line_attrs(i);
        is_custom_view = 0;
        if (line_attr != NULL) {
            if (line_attr->schdl_type() != ::adnsapi::RRTYPE_A && line_attr->schdl_type() != ::adnsapi::RRTYPE_AAAA) {
                log_server_warn(rte_lcore_id(), "[%s]: Set line algorithm, invalid type %u.\n", __FUNCTION__, line_attr->schdl_type());
                ret_code = ::adnsapi::RET_ERR_PARAMS_LINE_ATTR_TYPE_INVALID;
                err = err_buf;
                adns_node_free(new_node);
                goto FINISH;
            }
            view_id = ::adnsapi::Params::parseViewStr(*line_attr->mutable_view(), line_attr->cview(), is_custom_view, err);
            if (view_id < 0) {
                log_server_warn(rte_lcore_id(), "[%s]: invalid view %s.\n", __FUNCTION__, line_attr->view().c_str());
                ret_code = ::adnsapi::RET_ERR_PARAMS_LINE_ATTR_VIEW_INVALID;
                err = err_buf;
                adns_node_free(new_node);
                goto FINISH;
            }
            if (__schedule_mode_set_node(new_node, domainName_cstr, line_attr->schdl_type(), is_custom_view, view_id, 1, line_attr->schdl_mode(), err_buf) != 0) {
                ret_code = ::adnsapi::RET_ERR_DOMAIN_REFRESH_SET_LINE_ALGORITHM_FAILURE;
                err = err_buf;
                adns_node_free(new_node);
                if (is_custom_view == 0) {
                    log_server_warn(rte_lcore_id(), "[%s]: Set schedule mode for domain: %s, type: %u, view: %s error", 
                                            __FUNCTION__, domainName_cstr, line_attr->schdl_type(), line_attr->view().c_str());
                } else {
                    log_server_warn(rte_lcore_id(), "[%s]: Set schedule mode for domain: %s, type: %u, custome view: %u error", 
                                            __FUNCTION__, domainName_cstr, line_attr->schdl_type(), line_attr->cview());
                }
                goto FINISH;
            }
        }
    }
    /* domain attr */
    if ((old_node == NULL) && (node_hint != NULL)) {
        node_hint->AAAA_schedule_mode = domainAttr->schdl_mode_4a() & 0x1;
        node_hint->A_schedule_mode = domainAttr->schdl_mode();
    }

    if (old_node != NULL) {
        ret = do_replace_node(zone, domainName_cstr, old_node, new_node, ns_view_list, view_list, err_buf); // err_buf is not used inside
        if (ret < 0) {
            if (ret == -1) {
                adns_node_free(new_node);
            }
            err = "[adns_api_domain_refresh]: fail to replace node"; // so here we assign it
            log_server_warn(rte_lcore_id(), "[%s]: replace zone, ret = %d\n, FAILURE", __FUNCTION__, ret);
            ret_code = ::adnsapi::RET_ERR_DOMAIN_REFRESH_REPLACE_FAILURE;
            goto FINISH;
        }

        typedef void (*pfn) (void *);
        ret = call_rcu( (pfn)adns_node_free, old_node);
        if (ret < 0) {
            err = "[adns_api_domain_refresh]: fail to register rcu event";
            log_server_warn(rte_lcore_id(), "[%s] register rcu event, ret = %d, FAILURE\n", __FUNCTION__, ret);
            ret_code = ::adnsapi::RET_ERR_DOMAIN_REFRESH_REPLACE_FAILURE;
            goto FINISH;
        }
    }

    log_server_warn(rte_lcore_id(), "[%s]: refresh domain %s from zone %s, SUCCESS.\n",
            __FUNCTION__, domainName_cstr, zoneName->c_str());
    ret_code = ::adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}
