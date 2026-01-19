/*
 * Copyright (C)
 * Filename: manage.c
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 */

#include <linux/ctype.h>

#include "manage.h"
#include "util.h"
#include "dns.h"
#include "lib_asmega.h"
#include "pvt_tnl_db.h"

unsigned int ip_s2i(char *ip) {
    unsigned int tmp[4], result = 0;
    sscanf(ip, "%u.%u.%u.%u", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
    result = tmp[0] + (tmp[1]*(1<<8)) + (tmp[2]*(1<<16)) + (tmp[3]*(1<<24));
    return result;
}

static int recv_conf(struct sock *sk, int cmd, void __user * user,
                     unsigned int len)
{
    struct am_tnl_info tnl_info;

    switch (cmd) {
        case SOCKET_OPS_SET_BATCH:
            return as_pvt_tnl_set_all_from_usr(&g_tnl_db, user, len);
            break;
        case SOCKET_OPS_SET_BIND:
            if (copy_from_user(&tnl_info, user, sizeof(struct am_tnl_info))) {
                goto err;
            }
            return as_pvt_tnl_add(&g_tnl_db, tnl_info.tnl_id, tnl_info.view_id);
            break;
        case SOCKET_OPS_SET_UNBIND:
            if (copy_from_user(&tnl_info, user, sizeof(struct am_tnl_info))) {
                goto err;
            }
            return as_pvt_tnl_del(&g_tnl_db, tnl_info.tnl_id);
            break;
        case SOCKET_OPS_SET_CLEAR:
            return as_pvt_tnl_clean(&g_tnl_db);
            break;
        default:
            goto err;
    }

    return AS_SUCCESS;
err:
    return AS_ERROR;
}

static int send_conf(struct sock *sk, int cmd, void __user * user, int *len)
{
    if (cmd == SOCKET_OPS_GET_ALL) {
        return as_pvt_tnl_get_all_to_usr(&g_tnl_db, user, len);
    }

    return AS_ERROR;
}

static struct nf_sockopt_ops conf_sockops __read_mostly = {
    .pf = PF_INET,
    .set_optmin = SOCKET_OPS_SET_BASE,
    .set_optmax = SOCKET_OPS_SET_MAX,
    .set = recv_conf,
    .get_optmin = SOCKET_OPS_GET_BASE,
    .get_optmax = SOCKET_OPS_GET_MAX,
    .get = send_conf,
    .owner = THIS_MODULE,
};

int as_manage_init(void)
{
    int ret;
    ret = nf_register_sockopt(&conf_sockops);
    if (ret == AS_SUCCESS) {
        pr_info("DNS Mega manage initialization successful\n");
    }
    return ret;
}

void as_manage_exit(void)
{
    nf_unregister_sockopt(&conf_sockops);
}
