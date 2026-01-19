#ifndef _DEF_BIT_H
#define _DEF_BIT_H
#include <stdint.h>
extern void set_bit(uint8_t *bitmap,uint32_t idx);
extern void clear_bit(uint8_t *bitmap,uint32_t idx);
extern int find_bit(uint8_t *bitmap,uint32_t idx);
extern void set_all_bit(uint8_t *bitmap,int v,int size);
#endif
