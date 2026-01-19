/*
 * lib_mega_adm_test.c
 *
 *  Created on: Jan 22, 2019
 *      Author: mayong
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "lib_asmega_adm.h"
#include "test.h"
#include "errcode.h"
#include "lib_asmega.h"

static int
test_setup_max_tunnel_info(void) {
    int ret, i, view_id;
    am_tnl_info_t tnl_list[MAX_VIEW_ID_NUM];
    uint32_t rsize = MAX_VIEW_ID_NUM;

    for (i = 0, view_id = MIN_VIEW_ID; i < MAX_VIEW_ID_NUM; i++, view_id++) {
        tnl_list[i].tnl_id = i;
        tnl_list[i].view_id = view_id;
    }

    ret = lib_asmega_adm_set(tnl_list, MAX_VIEW_ID_NUM);

    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_OK, "Setup %d tnl info failed with errno %d",
            MAX_VIEW_ID_NUM, ret);

    ret = lib_asmega_adm_get(tnl_list, &rsize);

    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_OK, "Get tnl info failed with errno %d",
            ret);
    TEST_ASSERT_EQUAL(rsize, MAX_VIEW_ID_NUM,
            "Get tnl num %d not equal with set num %d",
            rsize, MAX_VIEW_ID_NUM);

    return TEST_SUCCESS;
}

static int
test_setup_range_tunnel_info(void) {
    int ret;
    am_tnl_info_t tnl_list[] = { { 0, MIN_VIEW_ID }, { MAX_TNL_ID/2, MAX_VIEW_ID/2 }, { MAX_TNL_ID, MAX_VIEW_ID } };
    uint32_t rsize = sizeof(tnl_list) / sizeof(am_tnl_info_t);
    uint32_t isize = rsize;

    ret = lib_asmega_adm_set(tnl_list, rsize);
    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_OK,
            "Setup %d tnl info failed with errno %d", rsize, ret);

    ret = lib_asmega_adm_get(tnl_list, &rsize);
    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_OK, "Get tnl info failed with errno %d",
            ret);
    TEST_ASSERT_EQUAL(rsize, isize,
            "Get tnl num %d not equal with set num %d", rsize, isize);

    return TEST_SUCCESS;
}

static int
test_setup_dup_tunnel_info(void) {
    int ret;
    am_tnl_info_t tnl_list[] = { { 0, 234 }, { 0, 123 }, { 12345, 1 } };

    ret = lib_asmega_adm_set(tnl_list, sizeof(tnl_list) / sizeof(am_tnl_info_t));

    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR,
            "Setup duplicate tnl info should failed with errno %d, but return %d",
            ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR, ret);

    return TEST_SUCCESS;
}

static int
test_setup_inv_tunnel_info(void) {
    int ret;
    am_tnl_info_t tnl_list1[] = { { 0, 234 }, { 1, MAX_VIEW_ID + 1 }};
    am_tnl_info_t tnl_list2[] = { { 2, 235 }, { 4, MIN_VIEW_ID - 1 }};
    am_tnl_info_t tnl_list3[] = { { 3, 236 }, { MAX_TNL_ID + 1, 123 }};

    ret = lib_asmega_adm_set(tnl_list1, sizeof(tnl_list1) / sizeof(am_tnl_info_t));
    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR,
            "Setup too big view id should failed with errno %d, but return %d",
            ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR, ret);

    ret = lib_asmega_adm_set(tnl_list2, sizeof(tnl_list2) / sizeof(am_tnl_info_t));
    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR,
            "Setup too little view id should failed with errno %d, but return %d",
            ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR, ret);

    ret = lib_asmega_adm_set(tnl_list3, sizeof(tnl_list3) / sizeof(am_tnl_info_t));
    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR,
            "Setup too big tunnel id should failed with errno %d, but return %d",
            ASMEGA_ADM_SET_SOCKOPT_BIND_ERROR, ret);

    ret = lib_asmega_adm_set(tnl_list3, MAX_VIEW_ID_NUM + 1);
    TEST_ASSERT_EQUAL(ret, ASMEGA_ADM_SET_SOCKOPT_TNL_NUM_ERROR,
            "Setup too big tunnel id should failed with errno %d, but return %d",
            ASMEGA_ADM_SET_SOCKOPT_TNL_NUM_ERROR, ret);

    return TEST_SUCCESS;
}

static struct unit_test_suite asmega_lib_testsuite  = {
    .suite_name = "AS Mega admin library Unit Test Suite",
    .setup = NULL,
    .teardown = NULL,
    .unit_test_cases = {
        TEST_CASE_ST(NULL, NULL, test_setup_max_tunnel_info),
        TEST_CASE_ST(NULL, NULL, test_setup_range_tunnel_info),
        TEST_CASE_ST(NULL, NULL, test_setup_dup_tunnel_info),
        TEST_CASE_ST(NULL, NULL, test_setup_inv_tunnel_info),

        TEST_CASES_END() /**< NULL terminate unit test array */
    }
};

REGISTER_TEST_COMMAND(asmega_lib_test, asmega_lib_testsuite);

