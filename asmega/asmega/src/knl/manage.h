/*
 * Copyright (C)
 * Filename: manage.h
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 */

#ifndef __MANAGE_H__
#define __MANAGE_H__

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/netfilter_ipv4.h>
#include <linux/init.h>
#include <asm/uaccess.h>

#include "dns.h"


extern int as_manage_init(void);
extern void as_manage_exit(void);

#endif                          /* __MANAGE_H__ */
