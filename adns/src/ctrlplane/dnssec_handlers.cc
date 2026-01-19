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
#include "errcode.h"
#include "rcu.h"
#include "dnssec.h"
#include "base64.h"

using namespace std;
using namespace std::tr1;
using namespace google;

#define max_key_data_len (DNS_KEY_ECDSA256SIZE * 2 + 2)

extern "C" {
    int __set_dnssec(struct adns_zonedb *zonedb, char *name, int enable_dnssec, char *err);
    int __add_key(char *key_data, int data_len, uint16_t type, char *err);
    int __add_dnskeyrrsig(struct adns_zonedb *zonedb, char *name, uint8_t *sig, uint16_t sig_len, 
                      uint16_t tag_num, uint16_t active_key, uint16_t alt_zsk, char *err);
    int __del_zsk(uint16_t key_tag, char *err);
}

shared_ptr<adnsapi::CommonOutput> adns_api_setdnssec(char * querybuf, uint32_t querysize)
{
    shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code = ::adnsapi::RET_OK;
    string err;
    string * zoneName = NULL;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;
    ::adnsapi::DnssecOpt dnssec_opt = ::adnsapi::DNSSEC_OFF;

    err_buf[0] = '\0';

    ::adnsapi::SetDnssecInput SetDnssecInput;
    ret = SetDnssecInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: argument error\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_setdnssec]: deserialization failed.";
        goto FINISH;
    }

    zoneName = SetDnssecInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    dnssec_opt = SetDnssecInput.dnssec_opt();

    ret = __set_dnssec(g_datacore_db, (char *)zoneName->c_str(), dnssec_opt, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: set zone %s dnssec %u error\n", 
                __FUNCTION__, zoneName->c_str(), dnssec_opt);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_SET_ZONE_ERROR;
        err = err_buf;
        goto FINISH;
    }

    
    log_server_warn(rte_lcore_id(), "[%s]: set zone %s dnssec %u, SUCCESS.\n",
            __FUNCTION__, zoneName->c_str(), dnssec_opt);
    ret_code = adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

shared_ptr<adnsapi::CommonOutput> adns_api_addkey(char * querybuf, uint32_t querysize)
{
    shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code = ::adnsapi::RET_OK;
    string err;
    string *pub_key = NULL;
    string *priv_key = NULL;
    ::adnsapi::KeyType key_type = ::adnsapi::ZSK;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;
    err_buf[0] = '\0';
    size_t m_pub_key_len = 0, m_priv_key_len = 0;
    unsigned char m_pub_key[DNS_KEY_ECDSA256SIZE], m_priv_key[DNS_KEY_ECDSA256SIZE];
    unsigned char key_data[max_key_data_len];
    int key_data_len = 0;
    char *p_key_data;

    ::adnsapi::AddKeyInput AddKeyInput;
    ret = AddKeyInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: argument error\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_addkey]: deserialization failed.";
        goto FINISH;
    }
    key_type = AddKeyInput.key_type();

    if (AddKeyInput.has_priv_key() && key_type == ::adnsapi::KSK) {
        log_server_warn(rte_lcore_id(), "[%s]: KSK not allowed to add private key\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_KEY_ERROR;
        err = "[adns_api_addkey]: KSK not allowed to add private key.";
        goto FINISH;
    }

    pub_key = AddKeyInput.mutable_pub_key();
    ret = base64_decode(m_pub_key, DNS_KEY_ECDSA256SIZE, &m_pub_key_len, (const unsigned char *)pub_key->c_str(), pub_key->length());
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: Base64 decoding public key error\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_KEY_ERROR;
        err = "[adns_api_addkey]: Base64 decoding public key error.";
        goto FINISH;
    }

    priv_key = AddKeyInput.mutable_priv_key();
    ret = base64_decode(m_priv_key, DNS_KEY_ECDSA256SIZE, &m_priv_key_len, (const unsigned char *)priv_key->c_str(), priv_key->length());
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: Base64 decoding private key error\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_KEY_ERROR;
        err = "[adns_api_addkey]: Base64 decoding private key error.";
        goto FINISH;
    }

    p_key_data = (char *)key_data;
    *p_key_data = m_pub_key_len;
    p_key_data += 1;
    key_data_len += 1;
    memcpy(p_key_data, m_pub_key, m_pub_key_len);
    p_key_data += m_pub_key_len;
    key_data_len += m_pub_key_len;
    if (key_type == ::adnsapi::ZSK) {
        *p_key_data = m_priv_key_len;
        p_key_data += 1;
        key_data_len += 1;
        memcpy(p_key_data, m_priv_key, m_priv_key_len);
        key_data_len += m_priv_key_len;
    }

    ret = __add_key((char *)key_data, key_data_len, key_type, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: add %u key error\n", __FUNCTION__, key_type);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_KEY_ERROR;
        err = err_buf;
        goto FINISH;
    }

    log_server_warn(rte_lcore_id(), "[%s]: add key SUCCESS.\n", __FUNCTION__);
    ret_code = adnsapi::RET_OK;

FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

shared_ptr<adnsapi::CommonOutput> adns_api_delzsk(char * querybuf, uint32_t querysize)
{
    shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code = ::adnsapi::RET_OK;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    int ret = -1;

    err_buf[0] = '\0';
    ::google::protobuf::uint32 key_tag;

    ::adnsapi::DelZskInput DelZskInput;
    ret = DelZskInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: argument error\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_delzsk]: deserialization failed.";
        goto FINISH;
    }

    key_tag = DelZskInput.key_tag();
    if (key_tag > max_key_tag) {
        log_server_warn(rte_lcore_id(), "[%s]: invalid key tag %u error\n", __FUNCTION__, key_tag);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_DEL_ZSK_ERROR;
        err = err_buf;
        goto FINISH;
    }

    ret = __del_zsk((uint16_t)key_tag, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: del  ZSK error\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_DEL_ZSK_ERROR;
        err = err_buf;
        goto FINISH;
    }

    
    log_server_warn(rte_lcore_id(), "[%s]: del old ZSK, SUCCESS.\n", __FUNCTION__);
    ret_code = adnsapi::RET_OK;
FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}

shared_ptr<adnsapi::CommonOutput> adns_api_adddnskeyrrsig(char * querybuf, uint32_t querysize)
{
    shared_ptr<adnsapi::CommonOutput> output(new ::adnsapi::CommonOutput());
    ::adnsapi::RetCode ret_code = ::adnsapi::RET_OK;
    string err;
    char err_buf[CMD_RESP_ERR_LEN];
    char rdata[ADNS_SOA_RRLEN]; // ADNS_SOA_RRLEN is large enough for rrsig rdata
    int rdata_len;
    int ret = -1;
    string * zoneName = NULL;
    ::adnsapi::Rrsig rrsig;
    err_buf[0] = '\0';
    ::google::protobuf::uint32 tag_num;
    ::google::protobuf::uint32 alt_zsk;
    ::google::protobuf::uint32 active_zsk;

    ::adnsapi::AddDnskeyRrsigInput AddDnskeyRrsigInput;
    ret = AddDnskeyRrsigInput.ParseFromArray(querybuf, querysize);
    if (ret == false) {
        log_server_warn(rte_lcore_id(), "[%s]: argument error\n", __FUNCTION__);
        ret_code = ::adnsapi::RET_ERR_DESERIALIZE_FAILURE;
        err = "[adns_api_adddnskeyrrsig]: deserialization failed.";
        goto FINISH;
    }

    zoneName = AddDnskeyRrsigInput.mutable_zone_name();
    ret = ::adnsapi::Params::validateZoneName(*zoneName, err);
    if (ret < 0) {
        ret_code = ::adnsapi::RET_ERR_PARAMS_ZONE_INVALID;
        goto FINISH;
    }

    rrsig = AddDnskeyRrsigInput.dnskey_rrsig_attr().rrsig();
    ret = ::adnsapi::Params::rrsig2Rdata(rrsig.type_covered(), rrsig.algorithm(), rrsig.labels(),
                    rrsig.original_ttl(), rrsig.signature_expiration(), rrsig.signature_inception(), rrsig.key_tag(), 
                    rrsig.signer(), rrsig.signature(),
                    rdata, rdata_len, err);
    if (ret < 0) {
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
        goto FINISH;
    }

    tag_num = AddDnskeyRrsigInput.dnskey_rrsig_attr().tag_num();
    if (tag_num < 1 || tag_num > 2) {
        log_server_warn(rte_lcore_id(), "[%s]: invalid key tag num %u\n", __FUNCTION__, tag_num);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
        err = err_buf;
        goto FINISH;
    }

    alt_zsk = AddDnskeyRrsigInput.dnskey_rrsig_attr().alt_zsk();
    if (alt_zsk > max_key_tag) {
        log_server_warn(rte_lcore_id(), "[%s]: invalid key tag %u\n", __FUNCTION__, alt_zsk);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
        err = err_buf;
        goto FINISH;
    }

    active_zsk = AddDnskeyRrsigInput.dnskey_rrsig_attr().active_zsk();
    if (active_zsk > max_key_tag) {
        log_server_warn(rte_lcore_id(), "[%s]: invalid key tag %u\n", __FUNCTION__, active_zsk);
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
        err = err_buf;
        goto FINISH;
    }

    ret = __add_dnskeyrrsig(g_datacore_db, (char *)zoneName->c_str(), (uint8_t *)rdata, rdata_len, (uint16_t)tag_num, (uint16_t)active_zsk, (uint16_t)alt_zsk, err_buf);
    if (ret < 0) {
        log_server_warn(rte_lcore_id(), "[%s]: add dnskey rrsig for zone %s error\n", __FUNCTION__, zoneName->c_str());
        ret_code = ::adnsapi::RET_ERR_DNSSEC_ADD_DNSKEY_RRSIG_ERROR;
        err = err_buf;
        goto FINISH;
    }

    log_server_warn(rte_lcore_id(), "[%s]: add dnskey rrsig for zone %s SUCCESS.\n", __FUNCTION__, zoneName->c_str());
    ret_code = adnsapi::RET_OK;

FINISH:
    output->set_code(ret_code);
    output->set_msg(err);
    return output;
}
