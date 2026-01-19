#include "murmurhash3.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint32_t val = mm3_hash(data, size);
    return 0;
}
