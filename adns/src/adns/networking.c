
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/uio.h>
#include <math.h>
#include <errno.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_spinlock.h>

#include "networking.h"
#include "admin.h"
#include "adns_sync.h"
#include "utili_base.h"
#include "libadns.h"
#include "adns_api.h"

void freeClient(ioClient *c)
{
    /*listNode *ln;*/

    /* If this is marked as current client unset it */
    if (admin.current_client == c)
        admin.current_client = NULL;

    /* Close socket, unregister events, and remove list of replies and
     * accumulated arguments. */
    if (c->fd != -1) {
        aeDeleteFileEvent(admin.el,c->fd,AE_READABLE);
        aeDeleteFileEvent(admin.el,c->fd,AE_WRITABLE);
        close(c->fd);
    }

    /* Remove from the list of clients */
    if (c->fd != -1) {
        dequeueClient(c);
    }

    if (c->extend_buf != NULL) {
        admin_client_extbuf_put(c->extend_buf);
    }

    free(c);
}



void sendReplyToClient(aeEventLoop *el, int fd, void *privdata, int mask)
{
    ioClient *c = privdata;
    int nwritten = 0, ret = 0;

    /*uint16_t body_len = *((uint16_t *)(c->buf));*/
    while (nwritten < c->buf_size) {
        ret = write(fd, c->buf + nwritten, c->buf_size - nwritten);
        if (unlikely(ret <= 0)) {
            if (ret == -1 && errno == EAGAIN) {
                continue;
            } else {
                break;
            }
        } else {
            nwritten += ret;
        }
    }

    freeClient(c);
}

/* 
 * Set the event loop to listen for write events on the client's socket.
 * Typically gets called every time a reply is built. 
 */
int _installWriteEvent(ioClient *c)
{
    if (c->fd <= 0)
        return -1;

#if 0
    c->buf_size = 0;
    if (c->buf_size <=0 && aeCreateFileEvent(admin.el, c->fd, AE_WRITABLE,
                sendReplyToClient, c) == AE_ERR) 
#endif
        if (aeCreateFileEvent(admin.el, c->fd, AE_WRITABLE,
                    sendReplyToClient, c) == AE_ERR) 
            return -1;

    return 0;
}

void addReply(ioClient *c)
{
    if (_installWriteEvent(c) != 0)
        return;
}

void processInputBuffer(ioClient *c)
{
    /*struct cmd_msg *cmd_msg;*/
    struct adns_command_entry *ce;
    struct adnsCommand *adns_cmd;

#if 0
    if (c->query_size < sizeof(struct adns_command_entry) + 2) {
        freeClient(c);
        return;
    }
#endif

    /*ce = (struct adns_command_entry *)(c->querybuf + 2);*/
    ce = (struct adns_command_entry *)g_req_buf;
    adns_cmd = adns_lookup_cmd(ce->cmd);
    if (adns_cmd == NULL) {
        freeClient(c);
        return;
    }


    update_master(c, adns_cmd);

    // add reply event
    addReply(c);	
}

void readQueryFromClient(aeEventLoop *el, int fd, void *privdata, int mask)
{
    ioClient *c = (ioClient*) privdata;
    int nread;
    uint32_t body_len = 0, total = 0;

    admin.current_client = c;

    /* 1. read requset command header for body len */
    while (total < sizeof(body_len)) {
        nread = read(fd, (uint8_t *)&body_len + total, sizeof(body_len) - total);
        if (nread == -1) {
            if (errno == EAGAIN) {
                /*fprintf(stderr, "Eagain\n");*/
                nread = 0;
                total += nread;
                continue;
            } else {
                /*fprintf(stderr, "Reading from client: %s",strerror(errno));*/
                freeClient(c);
                return;
            }
        } else if (nread == 0) {
            /*fprintf(stderr, "Client closed connection");*/
            freeClient(c);
            return;
        }

        total += nread;
    }
    body_len = ntohl(body_len);
    /*fprintf(stderr, "received data length: %u\n", body_len);*/

    /* too small */
    if (body_len == 0) {
        admin.current_client = NULL;
        return;
    }
    /* too large */
    if (body_len > REQ_MAX_LEN) {
        freeClient(c);
        return;
    }

    /* 2. read request body, it's length is body len */
    total = 0;
    while (total < body_len) {
        nread = read(fd, g_req_buf + total, body_len - total);
        if (nread == -1) {
            if (errno == EAGAIN) {
                nread = 0;
                total += nread;
                /* sleep 1us */
                rte_delay_us(1);
                continue;
            } else {
                freeClient(c);
                return;
            }
        } else if (nread == 0) {
            /*fprintf(stderr, "Client closed connection");*/
            freeClient(c);
            return;
        }
        /* sleep 1us */
        rte_delay_us(1);
        total += nread;
    }

    /* 3. set cmd request length */
    g_req_len = body_len;
    /*printf("\nread bytes: %d\n", nread);*/

    processInputBuffer(c);
    admin.current_client = NULL;
}


ioClient *createClient(int fd)
{
    /* use malloc for better performance
     * please do remember to set all fields properly
     */
    ioClient *c = malloc(sizeof(ioClient));
    if (c == NULL)
        return NULL;

    /* passing -1 as fd it is possible to create a non connected client.
     * This is useful since all the Redis commands needs to be executed
     * in the context of a client. When commands are executed in other
     * contexts (for instance a Lua script) we need a non connected client. */
    if (fd != -1) {
        anetEnableNoSigpipe(NULL, fd);
        anetNonBlock(NULL,fd);
        anetEnableTcpNoDelay(NULL,fd);
        if (admin.tcpkeepalive) {
            anetKeepAlive(NULL, fd, admin.tcpkeepalive);
        }
        if (aeCreateFileEvent(admin.el,fd,AE_READABLE, readQueryFromClient, 
                    c) == AE_ERR) {
            close(fd);
            free(c);
            return NULL;
        }
    }

    c->fd = fd;
    c->reqtype = 0;
    c->flags = 0;

    c->extend_buf = NULL;
    c->query_size = 0;
    
    c->recvd_total = 0;
    c->body_size = 0;

    c->bufpos = 0;
    c->buf_size = 0;

    INIT_LIST_HEAD(&c->reply_list);
    c->reply_bytes = 0;
    if (fd != -1)
        queueClient(c);

    return c;
}

/* Only used for cmd msg now */
static void acceptCommonHandler(int fd, int flags)
{
    ioClient *c;

    if ((c = createClient(fd)) == NULL) {
        /*
         *printf("Error registering fd event for the new client: %s (fd=%d)",
         *    strerror(errno),fd);
         */
        close(fd); /* May be already closed, just ignore errors */
        return;
    }
}

void acceptTcpDns(aeEventLoop *el, int fd, void *privdata, int mask)
{
    int cport, cfd;
    char cip[46];

    cfd = anetTcpAccept(admin.neterr, fd, cip, sizeof(cip), &cport);
    if (cfd == AE_ERR) {
        /*printf("Accepting client connection: %s", admin.neterr);*/
        return;
    }
    /*printf("Accepted %s:%d", cip, cport);*/

    acceptAdnsApiHandler(cfd,0);
}

void acceptTcpCmd(aeEventLoop *el, int fd, void *privdata, int mask)
{
    int cport, cfd;
    char cip[46];

    cfd = anetTcpAccept(admin.neterr, fd, cip, sizeof(cip), &cport);
    if (cfd == AE_ERR) {
        /*printf("Accepting client connection: %s", admin.neterr);*/
        return;
    }
    /*printf("Accepted %s:%d", cip, cport);*/

    acceptCommonHandler(cfd,0);
}

void UdpDnsProc(aeEventLoop *el, int fd, void *privdata, int mask)
{
    sync_udp_process(fd);
}


