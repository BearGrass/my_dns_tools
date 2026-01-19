/*
 * Copyright (C)
 * Filename: test.c
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 * include test cases for unit test.
 */

#include "test.h"

struct testcase tc[100];
int tc_len;

t_result t_judge(char *func, void *output, void *std, int len, int type, int flag) {
    t_result ret;
    strcpy(tc[tc_len].func, func);
    switch (type) {
        case TA_INT:
            ret = (*(int*)output == *(int*)std);
            if( !((ret == 1 )^(flag)) )
                goto success;
            else
                goto err;
            break;
        case TA_STRING:
            ret = memcmp(output, std, len);
            if( !((ret == 0 )^(flag)) )
                goto success;
            else
                goto err;
            break;
        case TA_POINT:
            if( !((output == std )^(flag)) )
                goto success;
            else
                goto err;
        default:
            goto err;
    }
success:
    tc[tc_len++].result = TA_SUCCESS;
    return TA_SUCCESS;
err:
    tc[tc_len++].result = TA_ERROR;
    return TA_ERROR;
}

void result_print(int res) {
    switch (res) {
        case DM_SUCCESS:
            pr_info("success\n");
            break;
        case DM_NOSUPPORT:
            pr_info("nosupport\n");
            break;
        case DM_ERROR:
            pr_info("error\n");
            break;
        default:
            pr_info("other\n");
    }
}

void show_test_result(void) {
    int i;
    char result[10];
    for(i = 0; i < tc_len; i ++) {
        if(tc[i].result == TA_SUCCESS) {
            strcpy(result, "success");
        } else if (tc[i].result == TA_ERROR ) {
            strcpy(result, "failed");
        }
        pr_info("[Testcase %d] Function %s test result is %s\n", i+1, tc[i].func, result);
    }
}
