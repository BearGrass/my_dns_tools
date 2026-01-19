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
#include "config.h"
#include "edns.h"

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
int sysctl_as_on = AS_ON;
int sysctl_as_dns_port = DNS_PORT;
int sysctl_vctk_vxlan_another_dport = AS_VCTK_VXLAN_ANOTHER_DPORT;
int sysctl_as_edns_code = EDNS_OPTION_PVT;
int sysctl_as_edns_len = EDNS_OPTION_PVT_LEN;

struct proc_dir_entry *mega_dir;

struct as_config proc_cfg[] = {
    {"on",                   {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_as_on},
    {"clear_counters",       {.write = clear_counters_write, .open = NULL, .read = NULL, .llseek = seq_lseek, .release = NULL}, NULL, NULL},
    {"dns_port",             {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_as_dns_port},
    {"vxlan_another_dport",  {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_vctk_vxlan_another_dport},
    {"edns_code",            {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_as_edns_code},
    {"edns_len",             {.write = proc_write, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, proc_read, &sysctl_as_edns_len},
    {"version",              {.write = NULL, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, version_read, NULL},
    {"counters",             {.write = NULL, .open = proc_open, .read = seq_read, .llseek = seq_lseek, .release = single_release}, as_counters_show, NULL},
};

static int get_data(char *realdata, const char __user * buffer,
                    unsigned long count)
{
    int len;

    if (copy_from_user(realdata, buffer, count))
        return -EFAULT;
    realdata[count] = 0;
    len = strlen(realdata);

    while ((len > 0) && !isdigit(realdata[len - 1]))
        realdata[len--] = 0;

    if(0 == len)
        return -EINVAL;

    return 0;
}

static int proc_open(struct inode *inode, struct file *file)  
{
    int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    struct as_config *proc_cfg_entry = (struct as_config *)PDE(inode)->data;
#else
    struct as_config *proc_cfg_entry = (struct as_config *)PDE_DATA(inode);
#endif
    ret = single_open(file, proc_cfg_entry->proc_show, proc_cfg_entry);
    return ret;
}

int proc_read(struct seq_file *m, void *v)
{
    //const struct cred *tcred = get_current_cred();
    struct as_config *proc_cfg_entry = (struct as_config *)m->private;

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
    struct as_config *proc_cfg_entry = (struct as_config *)(((struct seq_file *)file->private_data)->private);

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
    pr_info("change sysctl_as_%s to %d\n", proc_cfg_entry->name, temp);

    return count;
}

static ssize_t
clear_counters_write(struct file *file, const char __user * buffer,
                     size_t count, loff_t *f_pos)
{
    pr_info("asmega clear counters.\n");

    as_estats_clear(as_esmib, AS_COUNTERS_START, AS_COUNTERS_END);

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

int as_control_init(void)
{
    int ret = 0;
    mega_dir = proc_mkdir("asmega", NULL);
    if (mega_dir == NULL) {
        return -1;
    }

    ret = get_opt();
    if (ret != 0) {
        remove_proc_entry("asmega", NULL);
        return ret;
    }

    pr_info("asmega control initialization successful\n");
    return ret;
}

void as_control_exit(void)
{
    int i;
    for(i = 0; i < sizeof(proc_cfg) / sizeof(proc_cfg[0]); i ++) {
        remove_proc_entry(proc_cfg[i].name, mega_dir);
    }
    remove_proc_entry("asmega", NULL);
    pr_info("asmega control exit successful\n");
}
