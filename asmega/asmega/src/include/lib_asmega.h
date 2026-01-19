/*
 * Copyright (C)
 * Filename: lib_asmega.h
 * Author:
 * yingze <mayong.my@alibaba-inc.com>
 * Description:
 */

#ifndef __LIB_ASMEGA_H__
#define __LIB_ASMEGA_H__


#define MAX_TNL_NUM (1<<24)
#define MAX_TNL_ID (MAX_TNL_NUM - 1)
#define MAX_VIEW_ID (10000)
#define MIN_VIEW_ID (1)
#define MAX_VIEW_ID_NUM (MAX_VIEW_ID - MIN_VIEW_ID + 1)

/* 512 is to prevent conflict with kernel opt number */
enum {
    SOCKET_OPS_SET_BASE = 512,
    SOCKET_OPS_SET_BATCH,
    SOCKET_OPS_SET_BIND,
    SOCKET_OPS_SET_UNBIND,
    SOCKET_OPS_SET_CLEAR,

    SOCKET_OPS_SET_MAX,
};

enum {
    SOCKET_OPS_GET_BASE = 512,
    SOCKET_OPS_GET_ALL,

    SOCKET_OPS_GET_MAX,
};

typedef struct am_tnl_info {
    uint32_t tnl_id;
    uint16_t view_id;
}am_tnl_info_t;

#endif                          /* __LIB_ASMEGA_H__ */
