
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <limits.h>
#include <assert.h>

#include "rte_core.h"
#include "daemon.h"
#include "adns.h"

extern int g_get_init_tcp();
/**
 **每个进程初始化时，必须调用
 *主要用于获取共享内存
 *argv列表中，只有argv[5]是有意义的
 *argv[5]不允许改
 */
int proc_dns_init(char * corestr)
{
    int ret = 0;
    int argc = 0;
    char * argv[16];

    argc = 6;
    argv[0] = "/home/ndns/sbin/nginx";
    argv[1] = "-c";
    if (corestr != NULL) {
        argv[2] = corestr;
    } else {
        argv[2] = "0x3ff";
    }
    argv[3] = "-n";
    argv[4] = "4";
    argv[5] = "--proc-type=secondary";
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		return -1;
    }

	ret += g_get_init_tcp();      //step 1.1, for globle var, static
    return ret;
}

/**
 * 每个进程初始化时，必须调用这个函数
 * 用于per_lcore变量的引用 
 * 参数lcore，是进程实际运行的core，
 * lcore需要是adns启动时，占用的core
 * */
int proc_fix_lcore(int lcore)
{
	RTE_PER_LCORE(_lcore_id) = lcore;

    return RTE_PER_LCORE(_lcore_id);
}
