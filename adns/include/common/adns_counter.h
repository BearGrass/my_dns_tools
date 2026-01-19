#ifndef __ADNS_COUNTER_H_
#define __ADNS_COUNTER_H_

#define COUNTERS_MAX_NUM     ((1L << 32) - 1)
#define DEFAULT_NUM  64
#define UNUSED       0
#define USED         1
#define ADNS_INVALID_COUNTER_ID (-1)


#define  INVALID_COUNTER_ID(counter_id) \
    (counter_id >= g_adns_counter_num)


struct counter{
    union {
        uint64_t value;
        uint64_t bytes;
    };
    uint32_t queries;
}__attribute__((packed));


extern int adns_counter_get();
extern int adns_counter_del(unsigned int counter_id);
extern int adns_counter_add(unsigned int counter_id, uint64_t num);
extern int adns_counter_increase(int counter_id);
extern int adns_counter_sub(unsigned int counter_id, uint64_t num);
extern int adns_counter_decrease(int counter_id);
extern int adns_counter_sum_get(unsigned int counter_id, uint64_t *value);
extern int adns_counter_init_value(unsigned int counter_id);
extern int adns_counter_sum_get_queries_bytes(unsigned int counter_id, uint64_t *qps, uint64_t *bps);
extern int adns_counter_init(uint32_t init_num);
extern void adns_counter_cleanup();


#endif

