/*
 * Copyright (C)
 * Filename: core.c
 * Author:
 * mogu.lwp <mogu.lwp@alibaba-inc.com>
 * Description:
 */

#include <linux/tcp.h>

#include "util.h"
#include "stats.h"
#include "dns.h"
#include "control.h"
#include "manage.h"
#include "pvt_tnl_db.h"

/*
 * compatible with VPC
 * VPC use VCTK_IN in PREROUTING and
 * use VCTK_OUT NF_INET_LOCAL_OUT
 */
#define VCTK_IN NF_IP_PRI_FIRST + 1
#define VCTK_OUT NF_IP_PRI_CONNTRACK + 1

//extern uint64_t g_ip_qps_limit_size;

unsigned int
as_local_in(unsigned int hook, struct sk_buff *skb, const struct net_device *in,
            const struct net_device *out, int (*okfn) (struct sk_buff *));

unsigned int
as_local_out(unsigned int hook, struct sk_buff *skb,
             const struct net_device *in, const struct net_device *out,
             int (*okfn) (struct sk_buff *));

static struct nf_hook_ops as_ops_filter[] __read_mostly = {
    {
     .hook = as_local_in,
     .owner = THIS_MODULE,
     .pf = PF_INET,
     .hooknum = NF_INET_PRE_ROUTING,
     //NF_IP_PRI_FILTER is the priority of iptables
     .priority = VCTK_IN - 1,
     },
    {
     .hook = as_local_out,
     .owner = THIS_MODULE,
     .pf = PF_INET,
     .hooknum = NF_INET_LOCAL_OUT,
     .priority = VCTK_OUT - 1,
     },
};

static int __init asmega_init(void)
{
    int ret;

    ret = as_stats_init();
    if (ret < 0) {
        pr_err("stats init fail\n");
        goto stats;
    }

    ret = as_control_init();
    if (ret < 0) {
        pr_err("control init fail\n");
        goto aasin;
    }

    ret = as_pvt_tnl_init();
    if (ret < 0) {
        pr_err("private tunnel init fail\n");
        goto aasin; //goto pvttnl;
    }

    ret = as_manage_init();
    if (ret < 0) {
        pr_err("manage init fail(err code %d)\n", ret);
        goto manage;
    }

    ret = nf_register_hooks(as_ops_filter, ARRAY_SIZE(as_ops_filter));
    if (ret < 0) {
        pr_err("dp netfilter hook registed fail\n");
        goto nf_hook;
    }

    pr_info("DNS Mega initialization successful\n");
    return ret;

nf_hook:
    as_manage_exit();
manage:
    as_control_exit();
/* Nothing to do now */
//pvttnl:
//   as_pvt_tnl_exit();
aasin:
    as_stats_exit();
stats:
    return ret;
}

static void __exit asmega_exit(void)
{
    nf_unregister_hooks(as_ops_filter, ARRAY_SIZE(as_ops_filter));
    synchronize_net();
    as_manage_exit();
    //as_pvt_tnl_exit();
    as_control_exit();
    as_stats_exit();

    pr_info("ASMega exit successful\n");
}

module_init(asmega_init);
module_exit(asmega_exit);
//module_param(g_ip_qps_limit_size, int, S_IRUGO);
MODULE_AUTHOR("mogu.lwp<mogu.lwp@alibaba-inc.com>");
MODULE_DESCRIPTION("Modify DNS");
MODULE_LICENSE("GPL");
