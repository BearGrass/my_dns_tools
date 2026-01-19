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


#define MAX_PARA_LEN 10

/* default sysctl option */
#define AS_OFF 0
#define AS_ON 1
#define DNS_PORT	53
#define AS_VCTK_VXLAN_ANOTHER_DPORT 250

extern int sysctl_as_on;
extern int sysctl_as_dns_port;
extern int sysctl_vctk_vxlan_another_dport;
extern int sysctl_as_edns_code;
extern int sysctl_as_edns_len;

/* register proc file */
struct as_config {
    char name[64];                       /* proc file name */
    const struct file_operations proc_fops; /* proc interface file operations */
    int (*proc_show)(struct seq_file *m, void *v);
    int *value;
};

/* mega's proc director */
extern struct proc_dir_entry *mega_dir;
/* proc file array */
extern struct as_config proc_cfg[];

extern int as_control_init(void);
extern void as_control_exit(void);

#endif                          /* __CONTROL_H__ */
