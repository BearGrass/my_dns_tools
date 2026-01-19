#include <ctype.h>
#include <cstdarg>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <climits>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <algorithm>
#include <functional>
#include <locale>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <vector>
#include "adns_types.h"
#include "view_maps.h"
#include "libadns.h"
#include "descriptor.h"
#include "consts.h"
#include "dname.h"
#include "adnsapi.pb.h"
#include "base64.h"

namespace adnsapi {
namespace Params {

/* helpers */
static inline std::string &ltrim(std::string &s) {
    s.erase(s.begin(),
            std::find_if(
                s.begin(),
                s.end(),
                std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

static inline std::string &rtrim(std::string &s) {
    s.erase(std::find_if(
                s.rbegin(),
                s.rend(),
                std::not1(std::ptr_fun<int, int>(std::isspace))).base(),
            s.end());
    return s;
}

static inline std::string &trim(std::string &s) {
    return ltrim(rtrim(s));
}

static inline void str_sprintf(std::string& input, const std::string& fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);

    char *tmp = 0;
    /* vasprintf() is a GNU extension, thus hinders portability
     * while other solutions won't fit well
     * (stringstream not taking valist, unwilling to introducing boost)
     * keep it here */
    vasprintf(&tmp, fmt.c_str(), ap);

    va_end(ap);

    input = tmp;
    free(tmp);
}

static int string_to_uint16(const char *str)
{
    int base = 10;
    char *endptr;
    unsigned long long int val;
    unsigned long long int uint16_t_max = ((unsigned long long int) 1 << 16) - 1;
    unsigned int uint16_t_len_max = 5;

    /*check NULL, negative*/
    if ((str == NULL) || (str[0] == '-')) {
        fprintf(stdout, "not legal uint16_t %s\n", str);
        return -1; 
    }

    if (strlen(str) > uint16_t_len_max) {
        fprintf(stdout, "not legal uint16_t %s\n", str);
        return -1; 
    }
    errno = 0;    /* To distinguish success/failure after call */
    val = strtoull(str, &endptr, base);

    /* Check for various possible errors */
    if ((errno == ERANGE && (val == ULLONG_MAX))
            || (errno != 0 && val == 0)) {
        return -1;
    }

    if (endptr == str){
        fprintf(stdout, "[%s]: No digits were found\n", __FUNCTION__);
        return -1;
    }

    /* If we got here, strtol() successfully parsed a number */
    if (*endptr != '\0') {        /* Not necessarily an error... */
        fprintf(stdout, "[%s]: Further characters after number: %s\n", __FUNCTION__, endptr);
        return -1;
    }

    if (val > uint16_t_max) {
        return -1; 
    }

    return val;
}
/* helpers end */


/*
 * 校验内容:
 * 1,域名长度
 *     不超过最大长度
 *     不为0
 *     为1, 且不为根 '.'
 *     大于1, 首个字符不能为'.'
 * 2,各个label长度
 *     不超过最大长度
 * 3,各个字符
 *     alpha || digit || '-' || '_' || '.'
 *     没有 trim 的不能加入, 
 *     '*' 后面必须存在字符并且是 '.'
 *     不能包含两个连续的 '.'
 * 4,如果是PTR类型的
 *     必须以 '.in-addr.arpa.' 结尾, 可以没有 '.'
 *
 * 如果是zone
 *     不能包含'*'
 */
static int __nameCheck(std::string & name, const int isDomainName, const int isPtrName, std::string & err)
{
    std::string::size_type domain_len = name.length();
    if (domain_len > DOMAIN_MAX_SIZE) {
        str_sprintf(err, "[%s]: domain_len large than %d\n", __FUNCTION__, DOMAIN_MAX_SIZE);
        return -1;
    }
    if (domain_len == 0) {                       /*null domain string*/
        str_sprintf(err, "[%s]: null domain string\n", __FUNCTION__);
        return -1;
    }
    if ((domain_len == 1) && (name[0] != '.')) {    /* . root domain*/
        str_sprintf(err, "[%s]: error domain %s\n", __FUNCTION__, name.c_str());
        return -1;
    }
    if ((domain_len > 1) && (name[0] == '.')) {
        str_sprintf(err, "[%s]: domain name can't start with a dot %s\n", __FUNCTION__, name.c_str());
        return -1;
    }

    unsigned label_len = 0;
    for (std::string::size_type index = 0; index != name.size(); index++) {
        if (isalpha(name[index]) || isdigit(name[index]) || (name[index] == '-') || (name[index] == '_') || (name[index] == '.') ||
                ((isDomainName) && (name[index] == '*') && ((index + 1) < domain_len) && (name[index + 1] == '.')) ) {
            if (isupper(name[index])) {
                name[index] = tolower(name[index]);
            }
            if (name[index] == '.') {
                if (name[index - 1] == '.') {  /*check two continious dote (e.g: www..com)*/
                    str_sprintf(err, "[%s]: lable1..label2 %s\n", __FUNCTION__, name.c_str());
                    return -1;
                }
                label_len = 0;
            } else {
                ++label_len;
            }

            if (label_len > LABEL_MAX_SIZE) {
                str_sprintf(err, "[%s]: label large than %d\n", __FUNCTION__, LABEL_MAX_SIZE);
                return -1;
            }
            continue;
        }
        str_sprintf(err, "[%s]: the domain name has invalid charactor\n", __FUNCTION__);
        return -1;
    }

    /* add dot for non-FQDN name */
    if (name[domain_len - 1] != '.') {
        name.append(".");
    }

    return 0;
}

static int __domainIsSubOfZone(const char *zone, const char *domain)
{
    int zone_len, domain_len;
    int T;

    if (zone == NULL || domain == NULL) {
        return -1;
    }

    zone_len = strlen(zone);
    domain_len = strlen(domain);
    if (!(zone_len && domain_len)) {
        return -1;
    }

    if (zone_len > domain_len) {
        return -1;
    }

    if ((zone_len != domain_len) && domain[domain_len - zone_len - 1] != '.') {
        return -1;
    }

    T = zone_len;
    while(T--) {
        if (zone[--zone_len] != domain[--domain_len]) {
            return -1;
        }
    }
    return 0;
}

/* 
 * TODO: should check prefix is an IP address ?
 */
int validatePtrName(std::string & ptrName, std::string & err)
{
    return __nameCheck(ptrName, false, true, err);
}

int validateDomainName(std::string & domainName, std::string & err, const std::string & zoneName = "")
{
    int ret = -1;
    ret = __nameCheck(domainName, true, false, err);
    if (ret < 0) return ret;
    if (zoneName.length()) {
        ret = __domainIsSubOfZone(zoneName.c_str(), domainName.c_str());
        if (ret < 0) {
            str_sprintf(err, "[%s]: zone %s is not the sub of domain %s\n",
                    __FUNCTION__, zoneName.c_str(), domainName.c_str());
            return ret;
        }
    }
    return 0;
}

int validateZoneName(std::string & zoneName, std::string & err)
{
    return __nameCheck(zoneName, false, false, err);
}

int validateWeight(uint32_t weight, std::string & err, RrType type)
{
    if ((RRTYPE_A != type) && (RRTYPE_AAAA != type) && (RRTYPE_CNAME != type)) {
            return 0;
    } else if (weight > WEIGHT_MAX) {
        str_sprintf(err, "[%s]: type %u weight %u exceed maximum %u.\n", __FUNCTION__, type, weight, WEIGHT_MAX);
        return -1;
    }
    return 0;
}

int parseViewStr(std::string & view_name, int32_t cview, uint8_t & is_custom, std::string & err)
{
    int view_id = -1;
    is_custom = 0;

    trim(view_name);

    if (view_name.empty() && cview < 0) {
        str_sprintf(err, "[%s]: no view or custom_view, view=[%s], cview=[%d]\n", __FUNCTION__, view_name.c_str(), cview);
        view_id = -1;
        return -1;
    }

    if (!view_name.empty() && cview >= 0) {
        str_sprintf(err, "[%s]: two view ? view=%s, cview=%d\n", __FUNCTION__, view_name.c_str(), cview);
        view_id = -1;
        return -1;
    }

    if (!view_name.empty()) {
        if (strcasecmp(view_name.c_str(), "default") == 0) {
            view_id = 0;
        }
        else {
            view_id = view_name_to_id(view_name.c_str());
            if (view_id < 0) {
                str_sprintf(err, "[%s]: Illegal rr view %s\n", __FUNCTION__, view_name.c_str());
                return -1;
            }
        }
    } else if (cview >= 0) {
        view_id = cview;
        if (view_id < 0) {
            str_sprintf(err, "[%s]: Illegal rr cview %s\n", __FUNCTION__, view_name.c_str());
        }
        is_custom = 1;
    } 

    return view_id;
}

/* this was implemented in adns_adm.c formerly */
int validateRrclass(std::string & rrclass, std::string & err)
{
    unsigned int i;

    trim(rrclass);

    for (i = 0; i < ARRAY_SIZE(class_maps); i++) {
        if (strcasecmp(class_maps[i].name, rrclass.c_str()) == 0)
            return class_maps[i].id;
    }

    return -1;
}

static int __parseAname(std::string & rdata, int af, char * rdataOutput, int & rdataLen)
{
    char ip[64];

    trim(rdata);

    if (1 != ((af == AF_INET) ? inet_pton(AF_INET, rdata.c_str(), ip) : inet_pton(AF_INET6, rdata.c_str(), ip)) ) {
        return -1;
    }

    if (af == AF_INET) {
        memcpy(rdataOutput, ip, 4);
        rdataLen = 4;
    }
    else if (af == AF_INET6) {
        memcpy(rdataOutput, ip, 16);
        rdataLen = 16;
    }

    return 0;
}

/*
 * mx record format:
 * owner-name           ttl  class   rr  pref name
 * example.com.         3w   IN      MX  10   mail.example.com.
 */
static int __parseMx(std::string & rdata, char * rdataOutput, int & rdataLen, std::string & err)
{
    adns_dname_t * dname = NULL;
    int mx_dname_length = 0;

    /* pre */
    trim(rdata);
    std::string::size_type blankspace_pos = rdata.find(" ");
    if (blankspace_pos == std::string::npos) {
        str_sprintf(err, "[%s]: Even no blank space, %s\n", __FUNCTION__, rdata.c_str());
        return -1;
    }
    std::string priority = rdata.substr(0, blankspace_pos);
    std::string mx_name = rdata.substr(blankspace_pos + 1);

    /* process the priority */
    if (string_to_uint16(priority.c_str()) < 0) {
        str_sprintf(err, "[%s]: mx priority error, %s\n", __FUNCTION__, priority.c_str());
        return -1;
    }
    uint16_t _priority = (uint16_t)atoi(priority.c_str());

    /* process the mail server domain name */
    if (validateDomainName(mx_name, err) < 0) {
        return -1;
    }

    /* assemble output */
    *(uint16_t *)rdataOutput = htons(_priority);
    rdataLen = 2;

    dname = adns_dname_from_str(mx_name.c_str(), mx_name.length());
    if (dname == NULL) {
        return -1;
    }
    mx_dname_length = adns_dname_size(dname);
    if (mx_dname_length <= 0) {
        adns_dname_free(&dname);
        return -1;
    }
    memcpy(rdataOutput + rdataLen, dname, mx_dname_length);
    rdataLen += mx_dname_length;
    adns_dname_free(&dname);

    return 0;
}

static int __parseNormal(std::string & rdata, char * rdataOutput, int & rdataLen, std::string & err)
{
    int ret = -1;
    adns_dname_t * dname = NULL;

    trim(rdata);

    ret = validateDomainName(rdata, err);
    if (ret < 0) {
        return -1;
    }

    dname = adns_dname_from_str(rdata.c_str(), rdata.length());
    if (dname == NULL) {
        return -1;
    }
    rdataLen = adns_dname_size(dname);
    memcpy(rdataOutput, dname, rdataLen);
    adns_dname_free(&dname);

    return 0;
}

static int __parseTxt(std::string & rdata, char * rdataOutput, int & rdataLen, std::string & err)
{
    int len = 0;
    int cur_chstr_len = 0; // current charactor string length
    int cur_chstr_hdr_pos = 0; // the postion in the rdata to fill the header for current charactor string

    trim(rdata);

    len = rdata.length();
    if (len > TXT_MAX_SIZE) {
        err = "all txt len large than maximum";
        return -1;
    }

    int input_idx = 0, rdata_idx = 1;
    for (; input_idx < len; input_idx ++, rdata_idx++) {
        switch (rdata[input_idx]) {
            case '/':
                if (rdata[input_idx + 1] == ' ' || rdata[input_idx + 1] == '/') {
                    input_idx ++;
                }
                rdataOutput[rdata_idx] = rdata[input_idx];
                cur_chstr_len ++;
                break;
            case ' ':
                if (cur_chstr_len > RDATA_MAX_SIZE) {
                    err = "txt segment length exceeds maximum";
                    return -1;
                }
                cur_chstr_hdr_pos = rdata_idx - cur_chstr_len - 1;
                rdataOutput[cur_chstr_hdr_pos] = cur_chstr_len;
                cur_chstr_len = 0;
                break;
            default:
                rdataOutput[rdata_idx] = rdata[input_idx];
                cur_chstr_len ++;
                break;
        }
    }
    if (cur_chstr_len > RDATA_MAX_SIZE) {
        err = "txt segment length exceeds maximum";
        return -1;
    }
    cur_chstr_hdr_pos = rdata_idx - cur_chstr_len - 1;
    rdataOutput[cur_chstr_hdr_pos] = cur_chstr_len;

    if (rdata_idx > TXT_MAX_SIZE) {
        err = "all txt len large than maximum";
        return -1;
    }
    rdataLen = rdata_idx;

    return 0;
}

/*
 * srv rr format:
 * srvce.prot.owner-name  ttl  class   rr  pri  weight port target
 * _http._tcp.example.com.       IN    SRV 0    5      80   www.example.com.
 */
static int __parseSrv(std::string & rdata, char * rdataOutput, int & rdataLen, std::string & err)
{
    std::string delimiter = " ";
    size_t current;
    size_t next = -1;
    int i = 0;
    int srv_dname_length = 0;
    std::vector<std::string> srv_segments;
    adns_dname_t * dname = NULL;

    trim(rdata);
    rdataLen = 0;

    do
    {
      current = next + 1;
      next = rdata.find_first_of(delimiter, current);
      srv_segments.push_back(rdata.substr(current, next - current));
    }
    while (next != std::string::npos);

    for (i = 0 ; i < 3 ; ++i) {
        if (string_to_uint16(srv_segments[i].c_str()) < 0) {
            return -1;
        }
        *((uint16_t *)rdataOutput + i) = htons((uint16_t)atoi(srv_segments[i].c_str()));
        rdataLen += 2;
    }

    if (validateDomainName(srv_segments[3], err) < 0) {
        return -1;
    }

    dname = adns_dname_from_str(srv_segments[3].c_str(), srv_segments[3].length());
    if (dname == NULL) {
        return -1;
    }
    srv_dname_length = adns_dname_size(dname);
    if ( srv_dname_length <= 0) {
        adns_dname_free(&dname);
        return -1;
    }
    memcpy(rdataOutput + rdataLen, dname, srv_dname_length);
    rdataLen += srv_dname_length;
    adns_dname_free(&dname);

    return 0;
}

static inline int parse_caa_tag(std::string & caa_tag, std::string & err) {
    int tag_len = caa_tag.length();

    if (tag_len > CAA_TAG_LEN_MAX) {
        str_sprintf(err, "[%s]: caa tag length more than %d\n",
                __FUNCTION__, CAA_TAG_LEN_MAX);
        return -1;
    }

    if (tag_len < CAA_TAG_LEN_MIN) { /*null domain string*/
        str_sprintf(err, "[%s]: caa tag length less than %d\n",
                __FUNCTION__, CAA_TAG_LEN_MIN);
        return -1;
    }

    for (int i = 0; i < tag_len; i++) {
        if (!isalpha(caa_tag[i]) && !isdigit(caa_tag[i])) {
            return -1;
        }

        if (isupper(caa_tag[i])) {
            caa_tag[i] = (char) (tolower(caa_tag[i]));
        }
    }

    return tag_len;
}

static inline int parse_caa_value(std::string & caa_value, std::string & err) {
    int len = caa_value.length();

    if (len > CAA_VALUE_LEN_MAX) {
        str_sprintf(err, "[%s]: caa value len large than %d\n", __FUNCTION__, CAA_VALUE_LEN_MAX);
        return -1;
    }

    return len;
}

static int __parseCaa(std::string & rdata, char * rdataOutput, int & rdataLen, std::string & err)
{
    std::string delimiter = " ";
    size_t current;
    size_t next = -1;
    std::vector<std::string> caa_segments;
    int seg_count = 0;

    trim(rdata);
    rdataLen = 0;

    do
    {
      seg_count++;
      current = next + 1;
      if (seg_count < 3) {
        next = rdata.find_first_of(delimiter, current);
        caa_segments.push_back(rdata.substr(current, next - current));
      } else { /*seg_count == 3*/
        caa_segments.push_back(rdata.substr(current));
      }
    }
    while (next != std::string::npos && (seg_count < 3));
    
    if (seg_count < 3) {
        str_sprintf(err, "[%s]: not enough segments.\n", __FUNCTION__, rdata.c_str());
        return -1;
    }

    /* flag */
    int flag = string_to_uint16(caa_segments[0].c_str());   // only 2 possible value here, so uint16 is ok.
    if (flag < 0 || (flag != CAA_FLAGS_NONE && flag != CAA_FLAGS_CRITICAL)) {
        str_sprintf(err, "[%s]: caa flag error %d.\n", __FUNCTION__, flag);
        return -1;
    }
    *((uint8_t *)rdataOutput) = (uint8_t)atoi(caa_segments[0].c_str());
    rdataLen += 1;

    /* tag */
    int tag_len = parse_caa_tag(caa_segments[1], err);
    if (tag_len < 0) {
        return -1;
    }
    *(uint8_t*)(rdataOutput + rdataLen) = tag_len;
    rdataLen += 1;
    memcpy(rdataOutput + rdataLen, caa_segments[1].c_str(), tag_len);
    rdataLen += tag_len;

    /* value */
    trim(caa_segments[2]);
    int value_len = parse_caa_value(caa_segments[2], err);
    if (value_len < 0) {
        return -1;
    }
    memcpy(rdataOutput + rdataLen, caa_segments[2].c_str(), value_len);
    rdataLen += value_len;

    return 0;
}

int parseRdata(std::string & zoneName, std::string & domainName, std::string & rdata,
                        int type, char * rdataOutput, int & rdataLen, std::string & err)
{
    int ret = -1;

    switch (type) {
        case ADNS_RRTYPE_A:
            ret = __parseAname(rdata, AF_INET, rdataOutput, rdataLen);
            break;
        case ADNS_RRTYPE_AAAA:
            ret = __parseAname(rdata, AF_INET6, rdataOutput, rdataLen);
            break;
        case ADNS_RRTYPE_CNAME:
        case ADNS_RRTYPE_NS:
        case ADNS_RRTYPE_PTR:
            ret = __parseNormal(rdata, rdataOutput, rdataLen, err);
            break;
        case ADNS_RRTYPE_MX:
            ret = __parseMx(rdata, rdataOutput, rdataLen, err);
            break;
        case ADNS_RRTYPE_TXT:
            ret = __parseTxt(rdata, rdataOutput, rdataLen, err);
            break;
        case ADNS_RRTYPE_SRV:
            ret = __parseSrv(rdata, rdataOutput, rdataLen, err);
            break;
       case ADNS_RRTYPE_CAA:
            ret = __parseCaa(rdata, rdataOutput, rdataLen, err);
            break;

        default:
            str_sprintf(err, "[%s]: Unsupported rrtype %d.\n", __FUNCTION__, type);
            ret = -1;
            break;
    }

    return ret;
}

int soa2Rdata(const std::string & ns, const std::string & mail, uint32_t serial, 
            uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t nxttl, 
            char *rdata, int & rdataLen, std::string & err)

{
    adns_dname_t * primaryBuf = NULL;
    adns_dname_t * mailBuf = NULL;
    size_t primaryBufLen = 0;
    size_t mailBufLen = 0;

    rdataLen = 0;
    if (rdata == NULL) {
        str_sprintf(err, "[%s]: Null pointer input.\n", __FUNCTION__);
        return -1;
    }

    /* copy primary */
    primaryBuf = adns_dname_from_str(ns.c_str(), ns.length());
    if (primaryBuf == NULL) {
        str_sprintf(err, "[%s]: Failed to convert primary to string %s\n", __FUNCTION__, ns.c_str());
        return -1;
    }
    primaryBufLen = strlen((char*)primaryBuf) + 1;
    if ( rdataLen + primaryBufLen > ADNS_SOA_RRLEN) {
        str_sprintf(err, "[%s]: Primary is out of rdata max. %s\n", __FUNCTION__, ns.c_str());
        adns_dname_free(&primaryBuf);
        return -1;
    }
    memcpy(rdata + rdataLen, primaryBuf, primaryBufLen);
    rdataLen += primaryBufLen;
    adns_dname_free(&primaryBuf);

    /* copy mail */
    mailBuf = adns_dname_from_str(mail.c_str(), mail.length());
    if (mailBuf == NULL) {
        str_sprintf(err, "[%s]: Failed to convert mail to string %s\n", __FUNCTION__, mail.c_str());
        return -1;
    }
    mailBufLen = strlen((char*)mailBuf) + 1;
    if ( rdataLen + mailBufLen > ADNS_SOA_RRLEN) {
        str_sprintf(err, "[%s]: Mail is out of rdata max. %s\n", __FUNCTION__, mail.c_str());
        adns_dname_free(&mailBuf);
        return -1;
    }
    memcpy(rdata + rdataLen, mailBuf, mailBufLen);
    rdataLen += mailBufLen;
    adns_dname_free(&mailBuf);

    if ( rdataLen + sizeof(uint32_t)*5 > ADNS_SOA_RRLEN) {
        str_sprintf(err, "[%s]: out of rdata max. %d\n", __FUNCTION__, rdataLen+sizeof(uint32_t)*5);
        return -1;
    }

    *(uint32_t*)(rdata + rdataLen) = (uint32_t)htonl(serial);
    rdataLen += sizeof(uint32_t);
    *(uint32_t*)(rdata + rdataLen) = (uint32_t)htonl(refresh);
    rdataLen += sizeof(uint32_t);
    *(uint32_t*)(rdata + rdataLen) = (uint32_t)htonl(retry);
    rdataLen += sizeof(uint32_t);
    *(uint32_t*)(rdata + rdataLen) = (uint32_t)htonl(expire);
    rdataLen += sizeof(uint32_t);
    *(uint32_t*)(rdata + rdataLen) = (uint32_t)htonl(nxttl);
    rdataLen += sizeof(uint32_t);

    return 0;
}

int rrsig2Rdata(uint32_t type_covered, uint32_t algorithm, uint32_t labels, 
                    uint32_t original_ttl, uint32_t expiration, uint32_t inception, uint32_t key_tag, 
                    const std::string & signer, const std::string & signature,
                    char *rdata, int & rdata_len, std::string & err)
{
    adns_dname_t * signerBuf = NULL;
    size_t signerBufLen = 0;
    int ret = -1;
    rdata_len = 0;
    unsigned char rrsig[DNS_SIG_ECDSA256SIZE];
    size_t sig_len = 0;

    if (rdata == NULL) {
        str_sprintf(err, "[%s]: Null pointer input.\n", __FUNCTION__);
        return -1;
    }

    // check type covered
    if (type_covered != ADNS_RRTYPE_DNSKEY) {
        str_sprintf(err, "[%s]: DNSKRY RRsig type overed error.\n", __FUNCTION__);
        return -1;
    }
    *((uint16_t *)rdata) = htons((uint16_t)type_covered);
    rdata_len += 2;

    // check algorithm
    if (algorithm != ECDSA_P256_ALGO) {
        str_sprintf(err, "[%s]: DNSKRY RRsig algorithm error.\n", __FUNCTION__);
        return -1;
    }
    *(rdata + rdata_len) = algorithm;
    rdata_len += 1;

    // check lables
    *(rdata + rdata_len) = labels;
    rdata_len += 1;

    // check original ttl
    *(uint32_t *)(rdata + rdata_len) = (uint32_t)htonl(original_ttl);
    rdata_len += 4;

    // check expiration
    *(uint32_t *)(rdata + rdata_len) = (uint32_t)htonl(expiration);
    rdata_len += 4;

    // check inception
    *(uint32_t *)(rdata + rdata_len) = (uint32_t)htonl(inception);
    rdata_len += 4;

    // check key_tag
    *(uint16_t *)(rdata + rdata_len) = (uint16_t)htons((uint16_t)key_tag);
    rdata_len += 2;

    // check signer
    signerBuf = adns_dname_from_str(signer.c_str(), signer.length());
    if (signerBuf == NULL) {
        str_sprintf(err, "[%s]: Failed to convert signer from string %s\n", __FUNCTION__, signer.c_str());
        return -1;
    }
    signerBufLen = strlen((char*)signerBuf) + 1;

    if ((uint32_t)adns_dname_labels(signerBuf) != labels) {
        str_sprintf(err, "[%s]: label number error%s\n", __FUNCTION__, signer.c_str());
        adns_dname_free(&signerBuf);
        return -1;
    }

    memcpy(rdata + rdata_len, signerBuf, signerBufLen);
    rdata_len += signerBufLen;
    adns_dname_free(&signerBuf);

    // decode signature
    ret = base64_decode(rrsig, DNS_SIG_ECDSA256SIZE, &sig_len, (unsigned char*)signature.c_str(), signature.length());
    if (ret < 0) {
        str_sprintf(err, "[%s]: DNSKRY RRsig signature error.\n", __FUNCTION__);
        return -1;
    }

    memcpy(rdata + rdata_len, rrsig, sig_len);
    rdata_len += sig_len;

    return 0;
}

}
}
