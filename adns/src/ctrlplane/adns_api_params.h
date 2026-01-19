#include <string>

#define max_key_tag 65535

namespace adnsapi {
namespace Params {
    int validateZoneName(std::string & zoneName, std::string & err);
    int validateDomainName(std::string & domainName, std::string & err, const std::string & zoneName = "");
    int validatePtrName(std::string & ptrName, std::string & err);
    int validateWeight(uint32_t weight, std::string & err, RrType type);
    int parseViewStr(std::string & view_name, int32_t cview, uint8_t & is_custom, std::string & err);
    int validateRrclass(std::string & rrclass, std::string & err);
    int parseRdata(std::string & zoneName, std::string & domainName, std::string & rdata,
                        int type, char * rdataOutput, int & rdataLen, std::string & err);
    int soa2Rdata(const std::string & ns, const std::string & mail, uint32_t serial, 
                uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t nxttl, 
                char *rdata, int & rdataLen, std::string & err);
    int rrsig2Rdata(uint32_t type_covered, uint32_t algorithm, uint32_t labels, 
                    uint32_t original_ttl, uint32_t expiration, uint32_t inception, uint32_t key_tag, 
                    const std::string & signer, const std::string & signature,
                    char *rdata, int & rdatalen, std::string & err);
}
}
