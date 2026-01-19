/*
 * Copyright (C)
 * Filename: util.h
 * Author:
 * yisong <songyi.sy@alibaba-inc.com>
 * Description:
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <linux/kernel.h>
#include <linux/types.h>

#define DNS_MAGIC 53

/* Debug */
//#define DM_KERN_DEBUG

#define PRINT_IP(addr) \
      (addr)[0]&0xff, \
  (addr)[1]&0xff, \
  (addr)[2]&0xff, \
  (addr)[3]&0xff
#define PRINT_IP_FORMAT      " %d.%d.%d.%d"

#define PRINT_MAC(addr) \
      ((uint8_t *)addr)[0], \
  ((uint8_t *)addr)[1], \
  ((uint8_t *)addr)[2], \
  ((uint8_t *)addr)[3], \
    ((uint8_t *)addr)[4], \
  ((uint8_t *)addr)[5]
#define PRINT_MAC_FORMAT        "%02x:%02x:%02x:%02x:%02x:%02x"

#ifdef DM_KERN_DEBUG
#define EnterFunction()					\
	do {						\
		printk(KERN_ERR				\
		       "Enter: %s, %s line %i\n",	\
		       __func__, __FILE__, __LINE__);	\
	} while(0)
#else
#define EnterFunction()
#endif

#ifdef DM_KERN_DEBUG
#define LeaveFunction()					\
	do {						\
		printk(KERN_ERR				\
		       "Leave: %s, %s line %i\n",	\
		       __func__, __FILE__, __LINE__);	\
	} while(0)
#else
#define LeaveFunction()
#endif
/* ~Debug */

/* conmon marco */
#define DM_HOLD 2
#define DM_NOSUPPORT 1
#define DM_SUCCESS 0
#define DM_ERROR -1

#define DM_UPDATE_NODE 1
#define DM_NEW_NODE 0


#endif                          /* __UTIL_H__ */
