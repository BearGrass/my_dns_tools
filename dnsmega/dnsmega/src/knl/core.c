/*
 * Copyright (C)
 * Filename: core.c
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#include <linux/tcp.h>

#include "util.h"
#include "stats.h"
#include "dns.h"
#include "cache.h"
#include "timer.h"
#include "control.h"
#include "manage.h"
#include "qpslimit.h"

/*
 * compatible with VPC
 * VPC use VCTK_IN in PREROUTING and
 * use VCTK_OUT NF_INET_LOCAL_OUT
 */
#define VCTK_IN NF_IP_PRI_FIRST + 1
#define VCTK_OUT NF_IP_PRI_CONNTRACK + 1

//extern uint64_t g_ip_qps_limit_size;

unsigned int
dm_local_in(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
            const struct net_device *out, int (*okfn) (struct sk_buff *));

unsigned int
dm_local_out(unsigned int hook, struct sk_buff *skb,
             const struct net_device *in, const struct net_device *out,
             int (*okfn) (struct sk_buff *));

static struct nf_hook_ops dm_ops_filter[] __read_mostly = {
    {
     .hook = dm_local_in,
     .owner = THIS_MODULE,
     .pf = PF_INET,
     .hooknum = NF_INET_LOCAL_IN,
     //NF_IP_PRI_FILTER is the priority of iptables
     .priority = NF_IP_PRI_FILTER + 1,
     },
    {
     .hook = dm_local_out,
     .owner = THIS_MODULE,
     .pf = PF_INET,
     .hooknum = NF_INET_LOCAL_OUT,
     .priority = VCTK_OUT - 1,
     },
};

static int __init dnsmega_init(void)
{
    int ret;

    ret = dm_stats_init();
    if (ret < 0) {
        pr_err("stats init fail\n");
        goto stats;
    }

    ret = dm_control_init();
    if (ret < 0) {
        pr_err("control init fail\n");
        goto admin;
    }

    ret = dm_qpslimit_init();
    if (ret < 0) {
        pr_err("qpslimit init fail\n");
        goto qpslimit;
    }

    ret = dm_manage_init();
    if (ret < 0) {
        pr_err("manage init fail\n");
        goto manage;
    }

    ret = dm_cache_init();
    if (ret < 0) {
        pr_err("cache init fail\n");
        goto cache;
    }

    ret = dm_timer_init();
    if (ret < 0) {
        pr_err("timer init fail\n");
        goto timer;
    }

    ret = nf_register_hooks(dm_ops_filter, ARRAY_SIZE(dm_ops_filter));
    if (ret < 0) {
        pr_err("dp netfilter hook registed fail\n");
        goto nf_hook;
    }

    pr_info("DNS Mega initialization successful\n");
    return ret;

nf_hook:
    dm_timer_exit();
timer:
    dm_cache_exit();
cache:
    dm_manage_exit();
manage:
    dm_qpslimit_exit();
qpslimit:
    dm_control_exit();
admin:
    dm_stats_exit();
stats:
    return ret;
}

static void __exit dnsmega_exit(void)
{
    nf_unregister_hooks(dm_ops_filter, ARRAY_SIZE(dm_ops_filter));
    synchronize_net();
    dm_timer_exit();
    dm_cache_exit();
    dm_manage_exit();
    dm_stats_exit();
    dm_control_exit();
    dm_qpslimit_exit();

    pr_info("DNS Mega exit successful\n");
}

module_init(dnsmega_init);
module_exit(dnsmega_exit);
//module_param(g_ip_qps_limit_size, int, S_IRUGO);
MODULE_AUTHOR("yisong <songyi.sy@alibaba-inc.com>, mogu <mogu.lwp@alibaba-inc.com>");
MODULE_DESCRIPTION("Cache for DNS");
MODULE_LICENSE("GPL");
