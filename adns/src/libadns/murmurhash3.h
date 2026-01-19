#ifndef _ADNS_MURMURHASH3_H_
#define _ADNS_MURMURHASH3_H_

#include <stdlib.h>
#include <stdint.h>


static inline uint32_t __attribute__((always_inline))
fmix(uint32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}


static inline uint32_t __attribute__((always_inline))
rotl32(uint32_t x, int8_t r)
{
    return (x << r) | (x >> (32 - r));
}


static inline uint32_t __attribute__((always_inline))
mm3_hash(const char* data, size_t len_)
{
    int i;
    uint32_t h1, c1, c2, k1;
    const uint8_t * tail;
    const int len = (int)len_;
    const int nblocks = (len>>2);
    const uint32_t * blocks = (const uint32_t*) (data + nblocks * 4);

    h1 = 0xc062fb4a;
    c1 = 0xcc9e2d51;
    c2 = 0x1b873593;

    for (i = -nblocks; i; i++) {
        k1 = blocks[i];

        k1 *= c1;
        k1 = rotl32(k1, 15);
        k1 *= c2;

        h1 ^= k1;
        h1 = rotl32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    tail = (const uint8_t*)(data + nblocks * 4);
    k1 = 0;
    switch (len & 3) {
        case 3:
            k1 ^= tail[2] << 16;

        case 2:
            k1 ^= tail[1] << 8;

        case 1:
            k1 ^= tail[0];
            k1 *= c1;
            k1 = rotl32(k1,15);
            k1 *= c2;
            h1 ^= k1;
    }

    h1 ^= len;
    h1 = fmix(h1);

    return h1;
}

#endif

