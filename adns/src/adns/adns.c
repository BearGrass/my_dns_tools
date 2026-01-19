#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <limits.h>
#include <assert.h>

#include "rte_core.h"
#include "daemon.h"
#include "adns.h"

extern int ndns_adns_alloc_init();
extern int g_set_init_master();
static void adns_print_copyright(void)
{
    printf("   %s\n", ADNS_COPYRIGHT);
    printf("   authors are: %s\n", ADNS_AUTHORS);
}

#ifndef FUZZ
int main(int argc, char **argv)
{
    int ret;
    unsigned lcore;

    /* call before the rte_eal_init() */
    (void)rte_set_application_usage_hook(adns_usage);

    adns_print_copyright();

	/* inti cwd */
	run_dir = malloc(PATH_MAX);
	if (run_dir == NULL) {
		fprintf(stderr, "Init run dir error\n");
		return -ENOMEM;
	}
	run_dir = getcwd(run_dir, PATH_MAX);
	if (run_dir == NULL) {
		fprintf(stderr, "Init run dir error\n");
		return -1;
	}

	ret = init_lock();
	if (ret < 0) {
		fprintf(stderr, "Failed to lock init file\n");
		return -1;
	}

	/* run as daemon */
    ret = daemon_start();
    if (ret < 0) {
        fprintf(stderr, "Failed to start as daemon\n");
        return -1;
    }

    /* initialize EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Failed to init EAL\n");
        return -1;
    }
    argc -= ret;
    argv += ret;

    rte_delay_ms(1000);

    ret = adns_parse_args(argc, argv);
    if (ret < 0) {
        RTE_LOG(INFO, ADNS, "Failed to parse arguments\n");
        return -1;
    }

	ndns_adns_alloc_init(); //step 1.0, for globle var, dynamic, turn globle dyn to globle static
    ret = adns_init();
    if (ret < 0) {
        RTE_LOG(INFO, ADNS, "Failed to init adns, error: %d\n", ret);
        return -1;
    }
	g_set_init_master();   //step 1.1, for globle var, static

    rte_delay_ms(3000);
    /* Dump server parameter */
    app_print_params();

    RTE_LOG(INFO, ADNS, "Start adns...\n");

	init_unlock();

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
	    rte_eal_mp_remote_launch(lcore_main_loop, NULL, CALL_MASTER);
	        RTE_LCORE_FOREACH_SLAVE(lcore) {
		        if (rte_eal_wait_lcore(lcore) < 0) {
			    return -1;
		    }
	    }
	}

    RTE_LOG(INFO, ADNS, "Start adns end...\n");
    return 0;
}
#endif

