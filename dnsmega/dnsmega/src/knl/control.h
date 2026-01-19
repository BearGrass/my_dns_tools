/*
 * Copyright (C)
 * Filename: control.h
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description: define the interface between kernel and user
 */

#ifndef __CONTROL_H__
#define __CONTROL_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ctype.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <linux/seq_file.h>


#define DM_OFF 0
#define MAX_PARA_LEN 10

/* default sysctl option */
#define DM_ON 0
#define DNS_PORT	53
#define DM_MAX_CACHE_NUM (128 * 1024 * 1024)
#define DM_FORWARD_TIMEOUT_SEC 10
#define CACHE_EXPIRED_SEC 60
#define DM_REQ_WAITLIST_NUM 32
#define DM_BARELY_TRUSTED_SEC 5
#define DM_FORWARD_RATELIMIT_QPS 20000
#define DM_FORWARD_RATELIMIT_SEC 5
#define DM_CACHE_CLEAN_INTERVAL_MS 2000
#define DM_CACHE_CLEAN_BULK_NUM 5000
#define DM_IP_RATELIMIT_ON 0
#define DM_IP_RATELIMIT_QPS 5000
#define DM_IP_REC_RATELIMIT_ON 0
#define DM_IP_REC_RATELIMIT_QPS 500
#define DM_UPDATE_NXDOMAIN 1
#define DM_UPDATE_SERVFAIL 0

extern int sysctl_dm_on;
extern int sysctl_dm_max_cache_num;
extern int sysctl_dm_dns_port;
extern int sysctl_dm_forward_timeout_sec;
extern int sysctl_dm_expired_time;
extern int sysctl_dm_req_waitlist_num;
extern int sysctl_dm_barely_trusted_time;
extern int sysctl_dm_forward_ratelimit_qps;
extern int sysctl_dm_forward_ratelimit_sec;
extern int sysctl_dm_cache_clean_interval_ms;
extern int sysctl_dm_cache_clean_bulk_num;
extern int sysctl_dm_ip_ratelimit_qps;
extern int sysctl_dm_ip_ratelimit_on;
extern int sysctl_dm_ip_rec_ratelimit_qps;
extern int sysctl_dm_ip_rec_ratelimit_on;
extern int sysctl_dm_update_nxdomain_on;
extern int sysctl_dm_update_servfail_on;

/* register proc file */
struct dm_config {
    char name[64];                       /* proc file name */
    const struct file_operations proc_fops; /* proc interface file operations */
    int (*proc_show)(struct seq_file *m, void *v);
    int *value;
};

/* mega's proc director */
extern struct proc_dir_entry *mega_dir;
/* proc file array */
extern struct dm_config proc_cfg[];

extern int dm_control_init(void);
extern void dm_control_exit(void);

#endif                          /* __CONTROL_H__ */
