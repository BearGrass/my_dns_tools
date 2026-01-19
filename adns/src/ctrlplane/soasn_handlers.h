#include "adnsapi.pb.h"
#include <tr1/memory>

using namespace std;
using namespace std::tr1;

shared_ptr<adnsapi::LookupSoaSnOutput> adns_api_lookupsoasn(char * querybuf, uint32_t querysize);
shared_ptr<adnsapi::CommonOutput> adns_api_setsoasn(char * querybuf, uint32_t querysize);
