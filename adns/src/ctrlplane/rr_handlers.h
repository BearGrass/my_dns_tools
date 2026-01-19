#include "adnsapi.pb.h"
#include <tr1/memory>

using namespace std;

tr1::shared_ptr<adnsapi::CommonOutput> adns_api_rr_add(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::CommonOutput> adns_api_rr_del(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::LookupRrOutput> adns_api_rr_lookup(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::CommonOutput> adns_api_rr_setattr(char * querybuf, uint32_t querysize);
