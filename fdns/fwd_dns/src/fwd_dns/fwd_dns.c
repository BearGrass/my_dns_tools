
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <limits.h>
#include <assert.h>
#include <signal.h>

#include "rte_core.h"
#include "common.h"
#include "ldns.h"
#include "daemon.h"
#include "fwdctl_share.h"

static void ldns_print_copyright(void)
{
    printf("   VERSION[%s]\n\t\n", FWD_VERSION_STR);
    printf("   %s\n\t\n", LDNS_COPYRIGHT);
    printf("   %s \tauthors are: %s\n", LDNS_PROG_NAME, LDNS_AUTHORS);
}

void sighandler(int sig)
{
    exit(0);
}

int main(int argc, char **argv)
{
    int ret;
    unsigned lcore;

    ldns_print_copyright();

    if (argc < 5)               //just show version
        return 1;
    daemonize("fwd_dns.out", NULL);
    /* call before the rte_eal_init() */
    (void)rte_set_application_usage_hook(ldns_usage);

    signal(SIGTERM, sighandler);

    /* initialize EAL */
    rte_timer_subsystem_init();
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {

        fprintf(stderr, "rte_eal_init error\n");
        return -1;
    }
    argc -= ret;
    argv += ret;

    rte_delay_ms(1000);

    ret = ldns_parse_args(argc, argv);
    if (ret < 0) {
        RTE_LOG(INFO, LDNS, "Failed to parse arguments\n");
        return -1;
    }
    RTE_LOG(INFO, LDNS, "ldns_parse_args successed\n");

    ret = ldns_init();
    if (ret < 0) {
        RTE_LOG(INFO, LDNS, "Failed to init ldns, error: %d\n", ret);
        return -1;
    }
    RTE_LOG(INFO, LDNS, "ldns_init successed\n");

    rte_delay_ms(3000);
    /* Dump server parameter */
    RTE_LOG(INFO, LDNS, "start app_print_params\n");
    app_print_params();

    RTE_LOG(INFO, LDNS, "Init_ENV_done,Start ldns...\n");

    rte_eal_mp_remote_launch(lcore_main_loop, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if (rte_eal_wait_lcore(lcore) < 0) {
            return -1;
        }
    }

    return 0;
}
