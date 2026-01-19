#include "adnsapi.pb.h"
#include <tr1/memory>

using namespace std::tr1;

shared_ptr<adnsapi::CommonOutput> adns_api_zone_refresh(char * querybuf, uint32_t querysize);

