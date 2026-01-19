/*
 * Copyright (C)
 * Filename: control.c
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 */

#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#include "control.h"
#include "stats.h"
#include "cache.h"
#include "config.h"
#include "qpslimit.h"

static int proc_open(struct inode *inode, struct file *file);
static int get_data(char *realdata, const char __user * buffer,
                    unsigned long count);
static int proc_read(struct seq_file *m, void *v);
static ssize_t proc_write(struct file *file, const char __user *buffer,
                             size_t count, loff_t *f_pos);
static ssize_t clear_counters_write(struct file *file, const char __user * buffer,
                     size_t count, loff_t *f_pos);

static int version_read(struct seq_file *m, void *v);


/* sysctl option */
int sysctl_dm_on = DM_ON;                                                      //mega switch
int sysctl_dm_max_cache_num = DM_MAX_CACHE_NUM;
int sysctl_dm_dns_port = DNS_PORT;
int sysctl_dm_forward_timeout_sec = DM_FORWARD_RATELIMIT_SEC;
int sysctl_dm_expired_time = CACHE_EXPIRED_SEC;                                // expire time of node in cache
int sysctl_dm_req_waitlist_num = DM_REQ_WAITLIST_NUM;                          // time for waiting backend's reply(such as BIND)
int sysctl_dm_barely_trusted_time = DM_BARELY_TRUSTED_SEC;                     // trusted time of cache
int sysctl_dm_forward_ratelimit_qps = DM_FORWARD_RATELIMIT_QPS;                // rate limit by query QPS
int sysctl_dm_forward_ratelimit_sec = DM_FORWARD_RATELIMIT_SEC;                // the period for counting QPS
int sysctl_dm_cache_clean_interval_ms = DM_CACHE_CLEAN_INTERVAL_MS;            // the period of cleanin expired node
int sysctl_dm_cache_clean_bulk_num = DM_CACHE_CLEAN_BULK_NUM;                  // clean all cache
int sysctl_dm_ip_ratelimit_qps = DM_IP_RATELIMIT_QPS;                          // rate limit for ip by QPS
int sysctl_dm_ip_ratelimit_on = DM_IP_RATELIMIT_ON;                            // the switch of ip's rate limit
int sysctl_dm_ip_rec_ratelimit_on = DM_IP_REC_RATELIMIT_ON;                    // the switch of ip's rate limit while recusive
int sysctl_dm_ip_rec_ratelimit_qps = DM_IP_REC_RATELIMIT_QPS;                  // rate limit for ip by QPS while recusive
int sysctl_dm_update_nxdomain_on = DM_UPDATE_NXDOMAIN;
int sysctl_dm_update_servfail_on = DM_UPDATE_SERVFAIL;

struct proc_dir_entry *mega_dir;

struct dm_config proc_cfg[] = {
    {"on",                      {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_on},
    {"clear_counters",          {.write = clear_counters_write, .open = NULL, .read = NULL, .llseek = seq_lseek, .release = NULL}, NULL, NULL},
    {"max_cache_num",           {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_max_cache_num},
    {"dns_port",                {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_dns_port},
    {"barely_trusted_time",     {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_barely_trusted_time},
    {"expired_time",            {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_expired_time},
    {"max_req_waitlist_num",    {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_req_waitlist_num},
    {"forward_timeout_sec",     {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_forward_timeout_sec},
    {"forward_ratelimit_qps",   {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_forward_ratelimit_qps},
    {"forward_ratelimit_sec",   {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_forward_ratelimit_sec},
    {"cache_clean_interval_ms", {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_cache_clean_interval_ms},
    {"cache_clean_bulk_num",    {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_cache_clean_bulk_num},
    {"ip_ratelimit_qps",        {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_ip_ratelimit_qps},
    {"ip_ratelimit_on",         {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_ip_ratelimit_on},
    {"ip_rec_ratelimit_qps",    {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_ip_rec_ratelimit_qps},
    {"ip_rec_ratelimit_on",     {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_ip_rec_ratelimit_on},
    {"update_nxdomain_on",     {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_update_nxdomain_on},
    {"update_servfail_on",     {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_dm_update_servfail_on},
    {"version",                 {.write = NULL, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, version_read, NULL},
    {"counters",                {.write = NULL, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, dm_counters_show, NULL},
    {"stats",                   {.write = NULL, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, dm_estats_show,  NULL},
};

static int get_data(char *realdata, const char __user * buffer,
                    unsigned long count)
{
    int len;
    if (copy_from_user(realdata, buffer, count))
        return -EFAULT;
    realdata[count] = 0;
    len = strlen(realdata);
    while (!isdigit(realdata[len - 1]))
        realdata[len--] = 0;
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)  
{
    int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    struct dm_config *proc_cfg_entry = (struct dm_config *)PDE(inode)->data;
#else
    struct dm_config *proc_cfg_entry = (struct dm_config *)PDE_DATA(inode);
#endif
    ret = single_open(file, proc_cfg_entry->proc_show, proc_cfg_entry);
    return ret;
}

int proc_read(struct seq_file *m, void *v)
{
    //const struct cred *tcred = get_current_cred();
    struct dm_config *proc_cfg_entry = (struct dm_config *)m->private;

//#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
//    uid_t user = tcred->uid;
//#else
//    uid_t user = tcred->uid.val;
//#endif
    seq_printf(m, "%d\n", *proc_cfg_entry->value);

    /* monitor read frequently */
    //pr_info("INFO:user_id:%d read %s\n", user, proc_cfg_entry->name);
    return 0;
}

static ssize_t proc_write(struct file *file, const char __user *buffer,
                             size_t count, loff_t *f_pos)
{
    unsigned int temp;
    char realdata[MAX_PARA_LEN + 1] = {0};
    int ret;
    struct dm_config *proc_cfg_entry = (struct dm_config *)(((struct seq_file *)file->private_data)->private);

    if (count > MAX_PARA_LEN) {
        pr_err("write parameter %s length is %lu, too long, invalid\n", proc_cfg_entry->name, count);
        return -1;
    }

    ret = get_data(realdata, buffer, count);
    if (ret) {
        pr_err("write %s get_data return %d\n", proc_cfg_entry->name, ret);
        return ret;
    }

    temp = simple_strtoul(realdata, NULL, 10);
    *proc_cfg_entry->value = temp;
    pr_info("change sysctl_dm_%s to %d\n", proc_cfg_entry->name, temp);

    return count;
}

static ssize_t
clear_counters_write(struct file *file, const char __user * buffer,
                     size_t count, loff_t *f_pos)
{
    int i, j;

    pr_err("DNS Mega clear counters.\n");
    for (i = 0; i < DM_FWD_QUERIES; i++) {
        for_each_online_cpu(j) {
            per_cpu_ptr(dm_esmib, j)->mibs[i] = 0;
        }
    }
    return count;
}

static int version_read(struct seq_file *m, void *v)
{
    seq_printf(m, "v%d.%d.%d\n", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION);
    return 0;
}

static int get_opt(void)
{
    int i;
    struct proc_dir_entry *proc_entry;

    for (i = 0; i < sizeof(proc_cfg) / sizeof(proc_cfg[0]); i++) {
        proc_entry = proc_create_data(proc_cfg[i].name, 0644, mega_dir, &proc_cfg[i].proc_fops, &proc_cfg[i]);
        if (proc_entry == NULL) {
            return -1;
        }
    }
    return 0;
}

int dm_control_init(void)
{
    int ret = 0;
    mega_dir = proc_mkdir("dnsmega", NULL);
    if (mega_dir == NULL) {
        return -1;
    }

    ret = get_opt();
    if (ret != 0) {
        remove_proc_entry("dnsmega", NULL);
        return ret;
    }

    pr_info("DNS Mega control initialization successful\n");
    return ret;
}

void dm_control_exit(void)
{
    int i;
    for(i = 0; i < sizeof(proc_cfg) / sizeof(proc_cfg[0]); i ++) {
        remove_proc_entry(proc_cfg[i].name, mega_dir);
    }
    remove_proc_entry("dnsmega", NULL);
    pr_info("DNS Mega control exit successful\n");
}
