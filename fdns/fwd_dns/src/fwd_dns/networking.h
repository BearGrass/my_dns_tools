
#ifndef _NETWORKING_H_
#define _NETWORKING_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "ae.h"
#include "anet.h"

void acceptTcpDns(aeEventLoop *el, int fd, void *privdata, int mask);

void acceptTcpCmd(aeEventLoop *el, int fd, void *privdata, int mask);

void UdpDnsProc(aeEventLoop *el, int fd, void *privdata, int mask);


#endif

