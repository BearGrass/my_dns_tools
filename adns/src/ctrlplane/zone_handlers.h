#include "adnsapi.pb.h"
#include <tr1/memory>

using namespace std;

tr1::shared_ptr<adnsapi::LookupZoneOutput> adns_api_zone_lookup(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::CommonOutput> adns_api_zone_setattr(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::CommonOutput> adns_api_zone_add(char * querybuf, uint32_t querysize);
tr1::shared_ptr<adnsapi::CommonOutput> adns_api_zone_del(char * querybuf, uint32_t querysize);

