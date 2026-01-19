#include "adnsapi.pb.h"
#include <tr1/memory>

using namespace std;
using namespace std::tr1;

shared_ptr<adnsapi::CommonOutput> adns_api_setdnssec(char * querybuf, uint32_t querysize);
shared_ptr<adnsapi::CommonOutput> adns_api_addkey(char * querybuf, uint32_t querysize);
shared_ptr<adnsapi::CommonOutput> adns_api_delzsk(char * querybuf, uint32_t querysize);
shared_ptr<adnsapi::CommonOutput> adns_api_adddnskeyrrsig(char * querybuf, uint32_t querysize);