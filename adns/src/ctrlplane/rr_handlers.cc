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
#include "rrset.h"
#include "errcode.h"
#include "rcu.h"
#include "adns_types.h"

using namespace std;
using namespace google;

extern "C" {
extern void cmd_set_err(char *str, const char *fmt, ...);
extern int adns_zone_add_rr(struct adns_zone *zone, const char *domain, uint8_t custom_view, adns_viewid_t view_id,
        adns_type_t type, uint32_t ttl, char *rdata, int rdata_len, int weight, const char *original_rdata, char *err, struct adns_node ** p_node);
extern int __del_rr(struct adns_zonedb *zonedb, const char *zone_str, const char *domain,
        uint8_t custom_view, adns_viewid_t view_id, adns_type_t type, char *rdata, int rdata_len, const char *original_rdata, char *err);
extern int __edit_rr(struct adns_zonedb *zonedb, const char *zone_str, const char *domain, uint8_t custom_view, adns_viewid_t view_id,
        adns_type_t type, int64_t ttl, char *rdata, int rdata_len, int64_t weight, const char *original_rdata, char *err, int set_ttl);
extern int adns_zone_get_node(struct adns_zone *zone, const char *domain, struct adns_node **p_node, char *err);
}

int add_rr(const char * zone_str, const char * domain_str, uint8_t is_custom,
        adns_viewid_t view_id, adns_type_t type, uint32_t ttl, char * rdata, int rdata_len, int weight, 
        const char * rdata_orig, char * err_buf)
{
    int ret = -1;
    adns_zone * zone = NULL;
    adns_node * node_hint = NULL;

    ret = adns_zonedb_get_zone(g_datacore_db, zone_str, &zone, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s] find old zone %s, ret = %d, FAILURE, %s\n", __FUNCTION__, zone_str, ret, err_buf);
        return -1;
    }

    ret = adns_zone_add_rr(zone, domain_str, is_custom, view_id, type, ttl,
            rdata, rdata_len, weight, rdata_orig, err_buf, &node_hint);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: add rr --zone %s --domain %s  is_custom=%d, --view %d --ttl %d --type %d -r \"%s\" -w %d, ret = %d, FAILURE. %s\n", 
                __FUNCTION__, zone_str, domain_str, is_custom, view_id, ttl, type, rdata_orig, weight, ret, err_buf);
        return -2;
    }

    log_server_warn(rte_lcore_id(), "[%s]: add rr --zone %s --domain %s is_custom=%d, --view %d --ttl %d --type %d -r \"%s\" -w %d, ret = %d, SUCCESS. %s\n",
                                                 __FUNCTION__, zone_str, domain_str, is_custom, view_id, ttl, type, rdata_orig, weight, ret, err_buf);
    return 0;
}

int del_rr(const char * zone_str, const char * domain_str, uint8_t is_custom, adns_viewid_t view_id, 
        adns_type_t type, char * rdata, int rdata_len, const char * rdata_orig, char * err_buf)
{
    int ret = -1;

    ret = __del_rr(g_datacore_db, zone_str, domain_str, is_custom, view_id, type, rdata, rdata_len, rdata_orig, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: del rr --zone %s --domain %s --view %d --type %d -r \"%s\", ret = %d, FAILURE. %s\n",
                __FUNCTION__, zone_str, domain_str, view_id, type, rdata_orig, ret, err_buf);
        return -1;
    }

    log_server_warn(rte_lcore_id(), "[%s]: del rr --zone %s --domain %s --view %d --type %d -r \"%s\", SUCCESS. %s\n",
            __FUNCTION__, zone_str, domain_str, view_id, type, rdata_orig, err_buf);
    return 0;
}

int lookup_rr(const char * zone_str, const char * domain_str, uint8_t custom_view, adns_viewid_t view_id,
        adns_type_t type, char * rdata, int rdata_len, const char * rdata_orig, uint32_t & ttl, uint32_t & weight, char * err_buf)
{
    int ret = -1;
    adns_zone * zone = NULL;
    adns_node * node = NULL;
    adns_rrset * rrset = NULL;
    adns_rdata_ctl * rdata_ctl = NULL;
    struct adns_rdata *elem = NULL, *elem_next = NULL;
    struct list_head *h_list =  NULL;

    ret = adns_zonedb_get_zone(g_datacore_db, zone_str, &zone, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: find old zone %s, ret = %d, FAILURE. %s\n", __FUNCTION__, zone_str, ret, err_buf);
        return -1;
    }

    ret = adns_zone_get_node(zone, domain_str, &node, err_buf);
    if (ret < 0) {
        cmd_set_err(err_buf, "[%s]: fail to get node %s. %s", __FUNCTION__, domain_str, err_buf);
        log_server_warn(rte_lcore_id(), "[%s]: fail to get node %s.", __FUNCTION__, domain_str);
        return -2;
    }

    rrset = adns_node_get_rrset(node, type);
    if (rrset == NULL) {
        cmd_set_err(err_buf, "[%s]: RRset of node %s (type = %d) does not exist\n", __FUNCTION__, domain_str, type);
        log_server_warn(rte_lcore_id(), "[%s]: RRset of node %s (type = %d) does not exist\n", __FUNCTION__, domain_str, type);
        return -3;
    }
    ttl = rrset->ttl;

    if (custom_view) {
        rdata_ctl = adns_rrset_get_private_rdata_ctl(rrset, (adns_private_route_id_t)view_id);
    }
    else {
        rdata_ctl = adns_rrset_get_rdata_ctl(rrset, view_id);
    }
    if (rdata_ctl == NULL) {
        cmd_set_err(err_buf, "[%s]: Rdata_ctl of node %s(type = %d, %sview_id = %d) does not exist\n",
                            __FUNCTION__, domain_str, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        log_server_warn(rte_lcore_id(), "[%s]: Rdata_ctl of node %s(type = %d, %sview_id = %d) does not exist\n",
                            __FUNCTION__, domain_str, type, custom_view? CUSTOM_VIEW_PREFIX : "", view_id);
        return -4;
    }

    h_list =  &(rdata_ctl->list);
    list_for_each_entry_safe(elem, elem_next, h_list, list) {
        if ((elem->len == rdata_len) && (!memcmp(elem->data, rdata, rdata_len))) {
            weight = elem->cw;  // reluctant to add large weight
            return 0;
        }
    }

    cmd_set_err(err_buf, "[%s]: rdata %s of node %s (type = %d) does not exist\n", __FUNCTION__, rdata_orig, domain_str, type);
    log_server_warn(rte_lcore_id(), "[%s]: rdata %s of node %s (type = %d) does not exist\n", __FUNCTION__, rdata_orig, domain_str, type);
    return -5;
}

int set_rr_attr(const char * zone_str, const char * domain_str, uint8_t is_custom, adns_viewid_t view_id,
        adns_type_t type, int64_t ttl, char * rdata, int rdata_len, int64_t weight, const char * rdata_orig, char * err_buf)
{
    int ret = -1;

    ret = __edit_rr(g_datacore_db, zone_str, domain_str, is_custom, view_id, type, ttl, rdata, rdata_len, weight, rdata_orig, err_buf, ttl<=0xffffffff && ttl >=0);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: set rr attr --zone %s --domain %s --view %d --type %d -r \"%s\", ret = %d, FAILURE. %s\n",
                __FUNCTION__, zone_str, domain_str, view_id, type, rdata_orig, ret, err_buf);
        return -1;
    }

    log_server_warn(rte_lcore_id(), "[%s]: set rr attr --zone %s --domain %s --view %d --type %d -r \"%s\", SUCCESS.\n",
            __FUNCTION__, zone_str, domain_str, view_id, type, rdata_orig);
    return 0;
}

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_rr_add(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code;
    string err;

    int ret = -1;
    uint8_t is_custom_view = 0;
    int view_id = -1;
    char rdata[TXT_MAX_SIZE];
    int rdata_len = 0;
    char err_buf[CMD_RESP_ERR_LEN];

    string * zone_name = NULL;
    string * domain_name = NULL;
    ::adnsapi::RrIndex * rr_index = NULL;
    ::adnsapi::RrAttr * rr_attr = NULL;

    ::adnsapi::AddRrInput addrr_input;
    ret = addrr_input.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_addrr]: deserialization failed.";
        goto FINISH;
    }

    zone_name = addrr_input.mutable_zone_name();
    domain_name = addrr_input.mutable_domain_name();
    rr_index = addrr_input.mutable_rr_index();
    rr_attr = addrr_input.mutable_rr_attr();

    ret = ::adnsapi::Params::validateZoneName(*zone_name, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error. %s\n", __FUNCTION__, zone_name->c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateDomainName(*domain_name, err, *zone_name);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate soa ns name %s error. %s\n", __FUNCTION__, domain_name->c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
        goto FINISH;
    }

    view_id = ::adnsapi::Params::parseViewStr(*rr_index->mutable_view(), rr_index->cview(), is_custom_view, err);
    if (view_id < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate view %s error. %s\n", __FUNCTION__, rr_index->view().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_VIEW_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateRrclass(*rr_index->mutable_rrclass(), err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate class %s error. %s\n", __FUNCTION__, rr_index->rrclass().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_CLASS_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::parseRdata(*zone_name, *domain_name, *rr_index->mutable_rdata(),
                rr_index->rrtype(), rdata, rdata_len, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate rdata %s error. %s\n", __FUNCTION__, rr_index->rdata().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_RDATA_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateWeight(rr_attr->weight(), err, rr_index->rrtype());
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate weight %d error. %s\n", __FUNCTION__, rr_attr->weight(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_WEIGHT_INVALID;
        goto FINISH;
    }

    ret = add_rr(zone_name->c_str(), domain_name->c_str(), is_custom_view, view_id,
            rr_index->rrtype(), rr_attr->ttl(),
            rdata, rdata_len, rr_attr->weight(), rr_index->rdata().c_str(), err_buf);
    if (ret < 0) {
        err = err_buf;
        ret_code = ::adnsapi::RET_ERR_RR_ADD_FAILURE;
        goto FINISH;
    }

    ret_code = ::adnsapi::RET_OK;

FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_rr_del(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code;
    string err;

    int ret = -1;
    uint8_t is_custom_view = 0;
    int view_id = -1;
    char rdata[TXT_MAX_SIZE];
    int rdata_len = 0;
    char err_buf[CMD_RESP_ERR_LEN];

    string * zone_name = NULL;
    string * domain_name = NULL;
    ::adnsapi::RrIndex * rr_index = NULL;

    ::adnsapi::DelRrInput delrr_input;
    ret = delrr_input.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_addrr]: deserialization failed.";
        goto FINISH;
    }

    zone_name = delrr_input.mutable_zone_name();
    domain_name = delrr_input.mutable_domain_name();
    rr_index = delrr_input.mutable_rr_index();

    ret = ::adnsapi::Params::validateZoneName(*zone_name, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error. %s\n", __FUNCTION__, zone_name->c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateDomainName(*domain_name, err, *zone_name);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate soa ns name %s error. %s\n", __FUNCTION__, domain_name->c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
        goto FINISH;
    }

    view_id = ::adnsapi::Params::parseViewStr(*rr_index->mutable_view(), rr_index->cview(), is_custom_view, err);
    if (view_id < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate view %s error. %s\n", __FUNCTION__, rr_index->view().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_VIEW_INVALID;
        goto FINISH;
    } 

    ret = ::adnsapi::Params::validateRrclass(*rr_index->mutable_rrclass(), err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate class %s error. %s\n", __FUNCTION__, rr_index->rrclass().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_CLASS_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::parseRdata(*zone_name, *domain_name, *rr_index->mutable_rdata(),
                rr_index->rrtype(), rdata, rdata_len, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate rdata %s error. %s\n", __FUNCTION__, rr_index->rdata().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_RDATA_INVALID;
        goto FINISH;
    }

    ret = del_rr(zone_name->c_str(), domain_name->c_str(), is_custom_view, view_id, rr_index->rrtype(),
            rdata, rdata_len, rr_index->rdata().c_str(), err_buf);
    if (ret < 0) {
        err = err_buf;
        ret_code = ::adnsapi::RET_ERR_RR_DEL_FAILURE;
        goto FINISH;
    }

    ret_code = ::adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

tr1::shared_ptr<adnsapi::LookupRrOutput> adns_api_rr_lookup(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::LookupRrOutput> output(new ::adnsapi::LookupRrOutput());
    ::adnsapi::RetCode ret_code;
    string err;

    int ret = -1;
    int view_id = -1;
    char rdata[TXT_MAX_SIZE];
    int rdata_len = 0;
    char err_buf[CMD_RESP_ERR_LEN];
    uint32_t ttl = -1;
    uint32_t weight = -1;
    uint8_t is_custom_view = 0;

    string * zone_name = NULL;
    string * domain_name = NULL;
    ::adnsapi::RrIndex * rr_index = NULL;
    ::adnsapi::RrAttr * rr_attr = NULL;

    ::adnsapi::LookupRrInput lookuprr_input;
    ret = lookuprr_input.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_addrr]: deserialization failed.";
        goto FINISH;
    }

    zone_name = lookuprr_input.mutable_zone_name();
    domain_name = lookuprr_input.mutable_domain_name();
    rr_index = lookuprr_input.mutable_rr_index();

    ret = ::adnsapi::Params::validateZoneName(*zone_name, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error. %s\n", __FUNCTION__, zone_name->c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateDomainName(*domain_name, err, *zone_name);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate soa ns name %s error. %s\n", __FUNCTION__, domain_name->c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
        goto FINISH;
    }

    view_id = ::adnsapi::Params::parseViewStr(*rr_index->mutable_view(), rr_index->cview(), is_custom_view, err);
    if (view_id < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate view %s error. %s\n", __FUNCTION__, rr_index->view().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_VIEW_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateRrclass(*rr_index->mutable_rrclass(), err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate class %s error. %s\n", __FUNCTION__, rr_index->rrclass().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_CLASS_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::parseRdata(*zone_name, *domain_name, *rr_index->mutable_rdata(),
                rr_index->rrtype(), rdata, rdata_len, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate rdata %s error. %s\n", __FUNCTION__, rr_index->rdata().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_RDATA_INVALID;
        goto FINISH;
    }

    ret = lookup_rr(zone_name->c_str(), domain_name->c_str(), is_custom_view, view_id, rr_index->rrtype(),
            rdata, rdata_len, rr_index->rdata().c_str(), ttl, weight, err_buf);
    if (ret < 0) {
        err = err_buf;
        ret_code = ::adnsapi::RET_ERR_RR_LOOKUP_FAILURE;
        goto FINISH;
    }
    rr_attr = output->mutable_rr_attr();
    rr_attr->set_weight(weight);
    rr_attr->set_ttl(ttl);

    ret_code = ::adnsapi::RET_OK;
FINISH:
    output->mutable_base()->set_code(ret_code);
    output->mutable_base()->set_msg(err);
    return output;
}

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_rr_setattr(char * querybuf, uint32_t querysize)
{
    tr1::shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code;
    string err;

    int ret = -1;
    int view_id = -1;
    char rdata[TXT_MAX_SIZE];
    int rdata_len = 0;
    char err_buf[CMD_RESP_ERR_LEN];
    int64_t weight = -1;
    int64_t ttl = -1;
    uint8_t is_custom_view = 0;

    string * zone_name = NULL;
    string * domain_name = NULL;
    ::adnsapi::RrIndex * rr_index = NULL;
    ::adnsapi::RrAttr * rr_attr = NULL;

    ::adnsapi::SetRrAttrInput setrr_input;
    ret = setrr_input.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_addrr]: deserialization failed.";
        goto FINISH;
    }

    zone_name = setrr_input.mutable_zone_name();
    domain_name = setrr_input.mutable_domain_name();
    rr_index = setrr_input.mutable_rr_index();
    rr_attr = setrr_input.mutable_rr_attr();

    ret = ::adnsapi::Params::validateZoneName(*zone_name, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate zone name %s error. %s\n", __FUNCTION__, zone_name->c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateDomainName(*domain_name, err, *zone_name);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate soa ns name %s error. %s\n", __FUNCTION__, domain_name->c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_DOMAIN_INVALID;
        goto FINISH;
    }

    view_id = ::adnsapi::Params::parseViewStr(*rr_index->mutable_view(), rr_index->cview(), is_custom_view, err);
    if (view_id < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate view %s error. %s\n", __FUNCTION__, rr_index->view().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_VIEW_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::validateRrclass(*rr_index->mutable_rrclass(), err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate class %s error. %s\n", __FUNCTION__, rr_index->rrclass().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_CLASS_INVALID;
        goto FINISH;
    }

    ret = ::adnsapi::Params::parseRdata(*zone_name, *domain_name, *rr_index->mutable_rdata(),
                rr_index->rrtype(), rdata, rdata_len, err);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: validate rdata %s error. %s\n", __FUNCTION__, rr_index->rdata().c_str(), err.c_str());
        ret_code = ::adnsapi::RET_ERR_PARAMS_RR_RDATA_INVALID;
        goto FINISH;
    }

    if (rr_attr->has_weight() == true) {
        ret = ::adnsapi::Params::validateWeight(rr_attr->weight(), err, rr_index->rrtype());
        if (ret < 0) {
            log_server_warn(rte_lcore_id(), "[%s]: validate weight %d error. %s\n", __FUNCTION__, rr_attr->weight(), err.c_str());
            ret_code = ::adnsapi::RET_ERR_PARAMS_RR_WEIGHT_INVALID;
            goto FINISH;
        }
        weight = rr_attr->weight();
    } else {
        weight = -1;
    }

    if (rr_attr->has_ttl() == true) {
        ttl = rr_attr->ttl();
    } else {
        ttl = -1;
    }

    ret = set_rr_attr(zone_name->c_str(), domain_name->c_str(), is_custom_view, view_id,
            rr_index->rrtype(), ttl, rdata, rdata_len, weight, rr_index->rdata().c_str(), err_buf);
    if (ret < 0) {
        err = err_buf;
        ret_code = ::adnsapi::RET_ERR_RR_SET_ATTR_FAILURE;
        goto FINISH;
    }

    ret_code = ::adnsapi::RET_OK;

FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;

}

