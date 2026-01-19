#ifndef _NETWORKING_H_
#define _NETWORKING_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "list.h"
#include "ae.h"
#include "anet.h"


#define ADNS_IO_BUFLEN (1<<20)
#define CMD_MAX_LEN (1<<29) // TODO: shrink this size when adns_adm is totally abandoned, please.
#define EXTBUF_MAX_LEN (1<<28)
#define IO_BINDADDR_NUM 3


typedef struct ioClient {
    struct list_head list;

    int fd;
    int state;
    int flags;
    int reqtype;

    struct list_head reply_list;
    unsigned int reply_bytes;

    /* query buffer */
    char *extend_buf;
    char querybuf[CMD_MAX_LEN];
    int query_size;

    uint32_t recvd_total;
    uint32_t body_size;

    /* response buffer */
    int bufpos; // uint32_t is better, keep it for compatibility
    int buf_size; // uint32_t is better, keep it for compatibility
    char buf[ADNS_IO_BUFLEN];

    /* peer info */
    uint16_t port;
    char addr_str[46];
} ioClient;


enum {
    IO_BIND_TCP = 0,  /* Addresses bind to TCP */
    IO_BIND_UDP,      /* Addresses bind to UDP */
    IO_BIND_CMD       /* Addresses bind to CMD */
};

struct io_bindaddr {
    int port;         /* listening port */
    char *addr;       /* Addresses bind to */
};

typedef void io_cb(ioClient *c);

struct io_proc {
    io_cb *proc;
    int flags; 
};

struct sys_admin {
    aeEventLoop *el;
    int shutdown;                      /* SHUTDOWN */

    struct io_bindaddr bindaddr[IO_BINDADDR_NUM];
    int ipfd[IO_BINDADDR_NUM];         /* TCP socket file descriptors */
    char *bind_addr;
    uint16_t bind_port;

    char neterr[256];                  /* Error buffer for anet.c */
    struct io_proc *tcp_proc;
    struct io_proc *udp_proc;
    struct io_proc *cmd_proc;

    /* Configuration */
    int maxidletime;                   /* Client timeout in seconds */
    int tcpkeepalive;                  /* Set SO_KEEPALIVE if non-zero. */
    size_t client_max_querybuf_len;    /* Limit for client query buffer length */
    unsigned int maxclients;           /* Max number of simultaneous clients */
    unsigned int bpop_blocked_clients; /* Number of clients blocked by lists */

    ioClient *current_client;
    struct list_head clients;

    uint64_t stat_numconnections;      /* Number of connections received */
    uint64_t stat_rejected_conn;       /* Clients rejected because of maxclients */
};


void acceptTcpDns(aeEventLoop *el, int fd, void *privdata, int mask);
void acceptTcpCmd(aeEventLoop *el, int fd, void *privdata, int mask);
void UdpDnsProc(aeEventLoop *el, int fd, void *privdata, int mask);

extern struct sys_admin admin;

static inline void queueClient(struct ioClient *c)
{
    list_add_tail(&c->list, &admin.clients);
}

static inline void dequeueClient(struct ioClient *c)
{
    list_del(&c->list);
}

void freeClient(ioClient *c);
#endif
