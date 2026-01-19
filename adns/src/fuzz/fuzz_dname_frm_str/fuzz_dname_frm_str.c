#include "dname.h"
#include "consts.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    adns_dname_t *dname = adns_dname_from_str(data, size);
    adns_dname_free(&dname);
    return 0;
}
