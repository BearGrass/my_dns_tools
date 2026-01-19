
#ifndef _ARNDC_SHARE_H_
#define _ARNDC_SHARE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

enum {
	ADNS_GET_INFO = 0,

	/* rndc operation */
	RNDC_START,
	RNDC_STOP,
	RNDC_RELOAD,
	
	CMD_ADDZONE,

	CMD_MAX
};

struct cmd_msg {
	uint32_t version;
    int opcode;
    int flags;
    int seq;
	int cmd;
	int ret_val;
    int req_len;
	int rsp_len;
    char data[0];
} __attribute__((packed));

#endif

