#include "adnsapi.pb.h"
#include <tr1/memory>

using namespace std;

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_domain_setattr(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::LookupDomainOutput> adns_api_domain_lookup(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::CommonOutput> adns_api_domain_del(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::CommonOutput> adns_api_domain_refresh(char * querybuf, uint32_t querysize);

