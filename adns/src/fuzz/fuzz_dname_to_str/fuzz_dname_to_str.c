#include "dname.h"
#include "consts.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *name_str = adns_dname_to_str(data);
    if (name_str != NULL) {
       free(name_str);
    }
    return 0;
}
