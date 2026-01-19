/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <sys/queue.h>

#include "test.h"


#define OPTEND -1
#define TEST_OK 0
#define TEST_ARG_ERR -1
#define TEST_SUITE_NOT_FOUND -2

static struct test_commands_list commands_list =
    TAILQ_HEAD_INITIALIZER(commands_list);

void
add_test_command(struct test_command *t)
{
    TAILQ_INSERT_TAIL(&commands_list, t, next);
}

void show_commands(const char *fmt)
{
    struct test_command *t;

    TAILQ_FOREACH(t, &commands_list, next) {
        printf(fmt, t->command);
    }
}

static int
unit_test_suite_runner(struct unit_test_suite *suite)
{
    int test_success;
    unsigned total = 0, executed = 0, skipped = 0, succeeded = 0, failed = 0;

    if (suite->suite_name) {
        printf(" + ------------------------------------------------------- +\n");
        printf(" + Test Suite : %s\n", suite->suite_name);
    }

    if (suite->setup)
        if (suite->setup() != 0)
            goto suite_summary;

    printf(" + ------------------------------------------------------- +\n");

    while (suite->unit_test_cases[total].testcase) {
        if (!suite->unit_test_cases[total].enabled) {
            skipped++;
            total++;
            continue;
        } else {
            executed++;
        }

        /* run test case setup */
        if (suite->unit_test_cases[total].setup)
            test_success = suite->unit_test_cases[total].setup();
        else
            test_success = TEST_SUCCESS;

        if (test_success == TEST_SUCCESS) {
            /* run the test case */
            test_success = suite->unit_test_cases[total].testcase();
            if (test_success == TEST_SUCCESS)
                succeeded++;
            else
                failed++;
        } else {
            failed++;
        }

        /* run the test case teardown */
        if (suite->unit_test_cases[total].teardown)
            suite->unit_test_cases[total].teardown();

        if (test_success == TEST_SUCCESS)
            printf(" + TestCase [%2d] : %s\n", total,
                    suite->unit_test_cases[total].success_msg ?
                    suite->unit_test_cases[total].success_msg :
                    "passed");
        else
            printf(" + TestCase [%2d] : %s\n", total,
                    suite->unit_test_cases[total].fail_msg ?
                    suite->unit_test_cases[total].fail_msg :
                    "failed");

        total++;
    }

    /* Run test suite teardown */
    if (suite->teardown)
        suite->teardown();

    goto suite_summary;

suite_summary:
    printf(" + ------------------------------------------------------- +\n");
    printf(" + Test Suite Summary \n");
    printf(" + Tests Total :       %2d\n", total);
    printf(" + Tests Skipped :     %2d\n", skipped);
    printf(" + Tests Executed :    %2d\n", executed);
    printf(" + Tests Passed :      %2d\n", succeeded);
    printf(" + Tests Failed :      %2d\n", failed);
    printf(" + ------------------------------------------------------- +\n");

    if (failed)
        return -1;

    return 0;
}

const char *const short_options = "hs:a";
const struct option long_options[] = {
    {"help", 0, NULL, 'h'},
    {"all", 0, NULL, 'a'},
    {"suite", 1, NULL, 's'},
};

static void usage_exit(const char *prg_name, const int exit_status)
{
    printf
        ("Unit test program.\n"
        "Usage: %s <command> [options]\n\n"
        "Commands:\n"
        "  -h --help        display this help message\n"
        "  -a --all         run all test suites\n"
        "  -s --suite       test suite name\n"
        "Support below test suites:\n",
        prg_name);
    show_commands("  %s\n");

    exit(exit_status);
}

static int run_test_suites(const char *st_name) {
    struct test_command *t;
    int ret = 0;
    int is_run = 0;

    TAILQ_FOREACH(t, &commands_list, next)
    {
        if ((st_name == NULL) || (!strcmp(st_name, t->command))) {
            ret = unit_test_suite_runner(t->suite);
            is_run = 1;
        }
    }

    if (is_run != 1) {
        printf("No test suite run\n");
        return TEST_SUITE_NOT_FOUND;
    }

    if (ret == 0)
        printf("Test OK\n");
    else
        printf("Test Failed\n");
    fflush(stdout);

    return ret;
}

int
main(int argc, char **argv)
{
    int ret;

    while ((ret = getopt_long(argc, argv, short_options, long_options,
                            NULL)) != OPTEND) {
        switch (ret) {
        case 'h':
            usage_exit(argv[0], TEST_OK);
            break;
        case 'a':
            return run_test_suites(NULL);
            break;
        case 's':
            return run_test_suites(optarg);
            break;
        default:
            usage_exit(argv[0], TEST_ARG_ERR);
            break;
        }
    }

    usage_exit(argv[0], TEST_ARG_ERR);

    return TEST_OK;
}
