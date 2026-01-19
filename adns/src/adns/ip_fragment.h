
/*
* Copyright (C)
* Filename: ip_fragment.h
* Author:
* yisong <songyi.sy@alibaba-inc.com>
* Description: IP fragment
*/


#ifndef _IP_FRAGMENT_H_
#define _IP_FRAGMENT_H_

void fragment_output(struct rte_mbuf *m, uint8_t port, uint16_t mtu_size, int is_gre);

#endif


