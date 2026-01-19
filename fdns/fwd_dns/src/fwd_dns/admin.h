
#ifndef _ADNS_ADMIN_H_
#define _ADNS_ADMIN_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
//#include <netdb.h>

#include "net.h"
#include "list.h"
#include "ae.h"
#include "fwdctl_share.h"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define EVENT_SET_SIZE 1024

extern int g_init_done;

enum {
	IO_BIND_CMD			/* Addresses bind to CMD */
};
#define IO_BINDADDR_NUM 1

struct io_bindaddr {
	int port;			/* listening port */
	char *addr;		/* Addresses bind to */
};

/* With multiplexing we need to take per-client state.
 * Clients are taken in a liked list. */
typedef struct ioClient {
	struct list_head list;

    int fd;
	int state;
	int flags;
	int reqtype;

	struct adnsCommand *cmd;

	struct list_head reply_list;
	unsigned int reply_bytes;

	/* query buffer */
	char querybuf[ADNS_IO_BUFLEN];
	int query_size;

	/* response buffer */
	int bufpos;
	int sendlen;
	int buf_size;
	char buf[ADNS_IO_BUFLEN];

	/* peer info */
	uint16_t port;
	char addr_str[46];
} ioClient;

typedef void io_cb(ioClient *c);
struct io_proc {
    io_cb *proc;
    int flags; 
};


extern void rndc_reload_cb(ioClient *c);


typedef void adnsCommandProc(ioClient *c);
struct adnsCommand {
	int opcode;
    char *desc;
    int flags;

    adnsCommandProc *proc;
};

extern struct adnsCommand *adns_lookup_cmd(int opcode);

/*
 * System IO, process dns tcp/udp sync, command setting.
 */
struct sys_admin {
    aeEventLoop *el;
    int shutdown;                   /* SHUTDOWN */
    /* Networking */
	struct io_bindaddr bindaddr[IO_BINDADDR_NUM];

    int ipfd[IO_BINDADDR_NUM]; /* TCP socket file descriptors */

	char *bind_addr;
	uint16_t bind_port;

    char neterr[256];  /* Error buffer for anet.c */

    /* Fast pointers to often looked up command */
	struct io_proc *tcp_proc;
	struct io_proc *udp_proc;
	struct io_proc *cmd_proc;

    /* Configuration */
    int maxidletime;                /* Client timeout in seconds */
    int tcpkeepalive;               /* Set SO_KEEPALIVE if non-zero. */
    size_t client_max_querybuf_len; /* Limit for client query buffer length */
    /* Limits */
    unsigned int maxclients;        /* Max number of simultaneous clients */
    /* Blocked clients */
    unsigned int bpop_blocked_clients; /* Number of clients blocked by lists */
    //list *unblocked_clients; [> list of clients to unblock before next loop <]
	ioClient *current_client;
	struct list_head clients;
    
	uint64_t stat_numconnections;  /* Number of connections received */
    uint64_t stat_rejected_conn;   /* Clients rejected because of maxclients */
};

extern struct sys_admin admin;


int admin_init(const char *addr, uint16_t port);
void admin_cleanup(void);


#endif

