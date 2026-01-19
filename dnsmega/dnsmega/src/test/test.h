/*
 * Copyright (C)
 * Filename: test.h
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 * include test cases for unit test.
 */

#include <linux/string.h>
#include <linux/spinlock_types.h>

#include "../knl/lock.h"
#include "../knl/cache.h"
#include "../knl/timer.h"
#include "../knl/control.h"

#ifndef __TEST_H__
#define __TEST_H__

//#define DM_TEST 0

#define FUNC_LEN_MAX 50
#define PARA_NUM_MAX 10

#define TA_SUCCESS 0
#define TA_ERROR 1

#define EQUALL 1
#define NEQUALL 0

typedef int t_result;

/* TA:test answer
 * test output type
 */
enum {
    TA_INT = 0,
    TA_STRING,
    TA_POINT,

    TA_MAX,
};

/* testcase */
struct testcase {
    char func[FUNC_LEN_MAX];   /* test function name */
    void *para;                /* test function parameters */
    int paranum;
    int result;
};

void result_print(int res);

/* judge output is equal to standed
 * @output: output value
 * @std: std value
 * @type: test varable's type( TA_INT,TA_STRING... )
 * @flag: eqall or not equall
 *
 * @return: TA_SUCCESS or TA_ERROR
 */
t_result t_judge(char *func, void *output, void *std, int len, int type, int flag);

/* print all test's result */
void show_test_result(void);

extern struct node_t *get_node(const uint8_t * key, int klen);
extern void put_node(struct node_t *n);
extern int dm_cache_init(void);
extern void dm_cache_exit(void);

//extern int test_start(void);
//extern void test_exit(void);

#endif                          /* __TEST_H__ */
