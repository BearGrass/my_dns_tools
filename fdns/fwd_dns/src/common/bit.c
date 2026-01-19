#include"bit.h"
#include<stdio.h>
#include<assert.h>
#include<string.h>
#include <stdint.h>
void set_bit(uint8_t * bitmap, uint32_t idx)
{
    *(bitmap + (idx >> 3)) |= (1 << (idx & 0x07));
}

void clear_bit(uint8_t * bitmap, uint32_t idx)
{
    *(bitmap + (idx >> 3)) &= ~(1 << (idx & 0x07));
}

int find_bit(uint8_t * bitmap, uint32_t idx)
{
    uint8_t v = *(bitmap + (idx >> 3));
    return ((v & (1 << (idx & 0x07))) != 0);
}

void set_all_bit(uint8_t * bitmap, int v, int size)
{
    memset(bitmap, v, size);
}
