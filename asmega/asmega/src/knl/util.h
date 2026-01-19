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
//#define AS_KERN_DEBUG

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

#ifdef AS_KERN_DEBUG
#define EnterFunction()					\
	do {						\
		printk(KERN_ERR				\
		       "Enter: %s, %s line %i\n",	\
		       __func__, __FILE__, __LINE__);	\
	} while(0)
#else
#define EnterFunction()
#endif

#ifdef AS_KERN_DEBUG
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
#define AS_HAS_EDNS 5
#define AS_ACCEPT 4
#define AS_STOLEN 3
#define AS_PVT_EDNS 2
#define AS_NONSUPPORT 1
#define AS_SUCCESS 0
#define AS_ERROR -1


#endif                          /* __UTIL_H__ */
