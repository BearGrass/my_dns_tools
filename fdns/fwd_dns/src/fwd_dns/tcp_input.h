
/*
* Copyright (C)
* Filename: tcp_input.h
* Author:
* yisong <songyi.sy@alibaba-inc.com>
*/

#ifndef __TCP_INPUT_H__
#define __TCP_INPUT_H__

#include "arch/arch.h"
#include "core/def.h"

#ifdef __cplusplus
extern "C" {
#endif

err_t tcpdns_accept(void *arg, struct tcp_pcb *pcb, err_t err);
int tcpdns_lcore_init();

#ifdef __cplusplus
}
#endif
#endif
