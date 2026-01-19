
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/uio.h>
#include <math.h>
#include <errno.h>

#include "networking.h"
#include "admin.h"

static void freeClient(ioClient * c);

void sendReplyToClient(aeEventLoop * el, int fd, void *privdata, int mask)
{
    ioClient *c = privdata;
    int nwritten = 0;

    uint16_t body_len = *((uint16_t *) (c->buf));
    nwritten = write(fd, c->buf + c->sendlen, c->buf_size);
    if (nwritten == -1) {
        if (errno == EAGAIN) {
            nwritten = 0;
        } else {
            printf("Error writing to client: %s", strerror(errno));
            freeClient(c);
            return;
        }
    }

    if (nwritten < c->buf_size) {
        c->sendlen += nwritten;
        c->buf_size -= nwritten;
        fprintf(stderr, "body len: %u, have wirtten len: %d\n", body_len,
                nwritten);
    } /*else
        fprintf(stderr, "body len: %u, wirtten len: %d\n", body_len, nwritten);*/

    if (nwritten == c->buf_size) {
        aeDeleteFileEvent(admin.el, c->fd, AE_WRITABLE);
        freeClient(c);
    }
}

/* 
 * Set the event loop to listen for write events on the client's socket.
 * Typically gets called every time a reply is built. 
 */
int _installWriteEvent(ioClient * c)
{
    if (c->fd <= 0)
        return -1;

#if 0
    c->buf_size = 0;
    if (c->buf_size <= 0 && aeCreateFileEvent(admin.el, c->fd, AE_WRITABLE,
                                              sendReplyToClient, c) == AE_ERR)
#endif
        if (aeCreateFileEvent(admin.el, c->fd, AE_WRITABLE,
                              sendReplyToClient, c) == AE_ERR)
            return -1;

    return 0;
}

void addReply(ioClient * c)
{
    if (_installWriteEvent(c) != 0)
        return;
}

static void queueClient(struct ioClient *c)
{
    list_add_tail(&c->list, &admin.clients);
}

static void dequeueClient(struct ioClient *c)
{
    list_del(&c->list);
}

static void freeClient(ioClient * c)
{
    /*listNode *ln; */

    /* If this is marked as current client unset it */
    if (admin.current_client == c)
        admin.current_client = NULL;

    /* Close socket, unregister events, and remove list of replies and
     * accumulated arguments. */
    if (c->fd != -1) {
        aeDeleteFileEvent(admin.el, c->fd, AE_READABLE);
        aeDeleteFileEvent(admin.el, c->fd, AE_WRITABLE);
        close(c->fd);
    }

    /* Remove from the list of clients */
    if (c->fd != -1) {
        dequeueClient(c);
    }

    free(c);
}

void processInputBuffer(ioClient * c)
{
    struct cmd_msg *ce;
    struct adnsCommand *adns_cmd;

    if (c->query_size < sizeof(struct cmd_msg)) {
        freeClient(c);
        return;
    }

    ce = (struct cmd_msg *)(c->querybuf);
    if (!VALID_CMD_MSG(ce)) {
        freeClient(c);
        return;
    }
    adns_cmd = adns_lookup_cmd(ce->opcode);
    if (adns_cmd == NULL) {
        freeClient(c);
        return;
    }

    adns_cmd->proc(c);

    // add reply event
    addReply(c);
}

void readQueryFromClient(aeEventLoop * el, int fd, void *privdata, int mask)
{
    ioClient *c = (ioClient *) privdata;
    c->sendlen = 0;
    int nread, readlen;

    admin.current_client = c;
    readlen = ADNS_IO_BUFLEN;
    nread = read(fd, c->querybuf, readlen);
    if (nread == -1) {
        if (errno == EAGAIN) {
            printf("Eagain\n");
            nread = 0;
        } else {
            printf("Reading from client: %s", strerror(errno));
            freeClient(c);
            return;
        }
    } else if (nread == 0) {
        printf("Client closed connection");
        freeClient(c);
        return;
    }
    c->query_size = nread;
    //printf("\nread bytes: %d\n", nread);

    if (nread == 0) {
        admin.current_client = NULL;
        return;
    }

    processInputBuffer(c);
    admin.current_client = NULL;
}

ioClient *createClient(int fd)
{
    ioClient *c = calloc(1, sizeof(ioClient));
    if (c == NULL)
        return NULL;

    /* passing -1 as fd it is possible to create a non connected client.
     * This is useful since all the Redis commands needs to be executed
     * in the context of a client. When commands are executed in other
     * contexts (for instance a Lua script) we need a non connected client. */
    if (fd != -1) {
        anetNonBlock(NULL, fd);
        anetEnableTcpNoDelay(NULL, fd);
        if (admin.tcpkeepalive) {
            anetKeepAlive(NULL, fd, admin.tcpkeepalive);
        }
        if (aeCreateFileEvent(admin.el, fd, AE_READABLE, readQueryFromClient,
                              c) == AE_ERR) {
            free(c);
            return NULL;
        }
    }

    c->fd = fd;
    c->bufpos = 0;
    c->reqtype = 0;
    c->flags = 0;
    INIT_LIST_HEAD(&c->reply_list);
    c->reply_bytes = 0;
    if (fd != -1)
        queueClient(c);

    return c;
}

/* Only used for cmd msg now */
static void acceptCommonHandler(int fd, int flags)
{
    if (createClient(fd) == NULL) {
        printf("Error registering fd event for the new client: %s (fd=%d)",
               strerror(errno), fd);
        close(fd);              /* May be already closed, just ignore errors */
        return;
    }
}

void acceptTcpDns(aeEventLoop * el, int fd, void *privdata, int mask)
{
    int cport, cfd;
    char cip[46];

    cfd = anetTcpAccept(admin.neterr, fd, cip, sizeof(cip), &cport);
    if (cfd == AE_ERR) {
        printf("Accepting client connection: %s", admin.neterr);
        return;
    }
    //printf("Accepted %s:%d", cip, cport);

    acceptCommonHandler(cfd, 0);
}

void acceptTcpCmd(aeEventLoop * el, int fd, void *privdata, int mask)
{
    int cport, cfd;
    char cip[46];

    cfd = anetTcpAccept(admin.neterr, fd, cip, sizeof(cip), &cport);
    if (cfd == AE_ERR) {
        printf("Accepting client connection: %s", admin.neterr);
        return;
    }
    //printf("Accepted %s:%d", cip, cport);

    acceptCommonHandler(cfd, 0);
}

void UdpDnsProc(aeEventLoop * el, int fd, void *privdata, int mask)
{
}
