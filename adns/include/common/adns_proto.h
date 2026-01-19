
#ifndef _ADNS_PROTO_H_
#define _ADNS_PROTO_H_

#include <stdint.h>
#include <string.h>


#define ADNS_PROTO_VERSION 0x20131125

// My car number
#define ADNS_CTL_LISTEN_PORT 8166

// request flags
#define CTL_F_CMD_WRITE 0x1
#define CTL_F_CMD_READ  0x2


struct server_info {
	uint8_t addr[16];	// ipv4/ipv6 addr
	uint16_t port;
};

enum ctl_cmd {
	CTL_GET_VERSION = 0,

	CTL_MAX
};

// request
struct ctl_req {
	uint32_t version;	// ctl protocol version
	uint16_t cmdid;
	uint16_t flags;
	int res;			// return value
	int id;				// ctl sequence number
	int datalen;
	char data[0];		// real data, assoi
};

// response
struct ctl_rsp {
	uint32_t version;	// ctl protocol version
	uint16_t cmdid;
	uint16_t flags;
	int res;			// return value
	int id;				// ctl sequence number
	int datalen;
	char data[0];		// real data, assoi
};



// init ctl request message with cmdid and proto version
static inline ctl_init_req(struct ctl_req *req, uint16_t cmdid)
{
	memset(req, 0, sizeof(struct ctl_req));
	req->version = ADNS_PROTO_VERSION;
	req->cmdid = cmdid;
}








#endif

