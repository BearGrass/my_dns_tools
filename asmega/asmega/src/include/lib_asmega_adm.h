/*
 * Copyright (C)
 * Filename: lib_asmega_adm.h
 * Author:
 * yingze <mayong.my@alibaba-inc.com>
 * Description:
 */

#ifndef __LIB_ASMEGA_ADM_H_
#define __LIB_ASMEGA_ADM_H_

#include <lib_asmega.h>

int lib_asmega_adm_get(am_tnl_info_t * tnl_list, uint32_t *tnl_num);
int lib_asmega_adm_set(am_tnl_info_t * tnl_list, uint32_t tnl_num);

#endif                          /* __LIB_ASMEGA_ADM_H_ */
