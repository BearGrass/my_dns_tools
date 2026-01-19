#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "networking.h"
#include "admin.h"

/* cpp part */
extern int adns_api_dispatch(char * querybuf, uint32_t querysize, char * respbuf, uint32_t * p_respsize);


/* local functions declaration */
static void adns_api_write(aeEventLoop *el, int fd, void * privdata, int mask);
static void adns_api_read_hdr(aeEventLoop *el, int fd, void *privdata, int mask);


static inline uint32_t adns_api_hdr_read_body_size(char *buf)
{
    return ntohl(*(uint32_t *)buf);
}

static inline void adns_api_hdr_write_body_size(char *buf, uint32_t body_size)
{
   *(uint32_t *)buf = htonl(body_size);
   return;
}

static inline uint32_t adns_api_hdr_len()
{
    return sizeof(uint32_t);
}

static inline bool adns_api_hdr_initialized(ioClient *c)
{
    return (c->body_size == 0) ? false : true;
}

static void adns_api_write(aeEventLoop *el, int fd, void * privdata, int mask)
{
    int ret = -1;
    ioClient *c = (ioClient*) privdata;
    ret = write(fd, (void*)c->buf + c->bufpos, c->buf_size + adns_api_hdr_len());
    if (ret <= 0) {
        if (errno == EAGAIN){
        }
        else {
            perror("recv error");
            freeClient(c);
        }
    }
    else {
        c->bufpos += ret;
        if (c->bufpos == c->buf_size + adns_api_hdr_len()) {
            aeDeleteFileEvent(el, c->fd, AE_WRITABLE);
            ret = aeCreateFileEvent(el, fd,AE_READABLE, adns_api_read_hdr, c);
            if (ret == AE_ERR) {
                freeClient(c);
            }
        }
    }
    return;
}

static void adns_api_read_hdr_body(aeEventLoop *el, int fd, void *privdata, int mask)
{
    ioClient *c = (ioClient*) privdata;
    int ret = -1;
    char * resp_body = NULL; // leave a header space here
    uint32_t * p_resp_len = NULL;
    char * query_holder = c->querybuf;
    uint32_t query_holder_cap = CMD_MAX_LEN;

    admin.current_client = c;
    if (c->extend_buf != NULL) {
        query_holder = c->extend_buf;
        query_holder_cap = EXTBUF_MAX_LEN;
    }

    ret = read(fd, query_holder + c->recvd_total, query_holder_cap - c->recvd_total);
    if (ret < 0) {
        if (errno == EAGAIN)
            goto BACKTOPOLL;
        else {
            perror("recv error");
            goto CLOSE;
        }
    }
    else if (ret == 0)
        goto CLOSE;
    else {
        c->recvd_total += ret;

        if (c->recvd_total == c->body_size + adns_api_hdr_len()) {
            resp_body = c->buf + adns_api_hdr_len(); // leave a header space here
            p_resp_len = (uint32_t*)&(c->buf_size);

            ret = adns_api_dispatch(query_holder + adns_api_hdr_len(), c->body_size, resp_body, p_resp_len);
            adns_api_hdr_write_body_size(c->buf, *p_resp_len); // now write the hdr

            /* reset read after processing */
            aeDeleteFileEvent(el, c->fd, AE_READABLE);
            c->recvd_total = 0;
            c->body_size = 0; //TODO: could we delete it?
            c->bufpos = 0; //TODO: could we delete it?
            if (ret < 0) {
                goto CLOSE;
            }

            ret = aeCreateFileEvent(el, c->fd, AE_WRITABLE, adns_api_write, c);
            if (ret == AE_ERR)
                goto CLOSE;
            goto BACKTOPOLL;
        }
        // not enough for msg body, goto BACKTOPOLL
        else if (c->recvd_total < c->body_size + adns_api_hdr_len())
            goto BACKTOPOLL;
        // exceed expection
        else {
            printf("Lenght of the msg client sending exceeds server recv buf max.\n");
            goto CLOSE;
        }
    }
CLOSE:
    //TODO: tell client the reason of failure
    freeClient(c);
BACKTOPOLL:
    admin.current_client = NULL;
    return;
}

static void adns_api_read_hdr(aeEventLoop *el, int fd, void *privdata, int mask)
{
    ioClient *c = (ioClient*) privdata;
    int ret = -1;

    admin.current_client = c;

    ret = read(fd, c->querybuf, adns_api_hdr_len());
    if (ret < 0) {
        if (errno == EAGAIN)
            goto BACKTOPOLL;
        else {
            perror("recv error");
            goto CLOSE;
        }
    }
    else if (ret == 0)
        goto CLOSE;
    else {
        c->recvd_total += ret;

        if (c->recvd_total == adns_api_hdr_len()) {
            c->body_size = adns_api_hdr_read_body_size(c->querybuf);
            if (c->body_size <= 0)
                goto CLOSE;

            if (c->body_size + adns_api_hdr_len() > CMD_MAX_LEN)
                c->extend_buf = admin_client_extbuf_get();

            aeDeleteFileEvent(el, c->fd, AE_READABLE);
            ret = aeCreateFileEvent(el, c->fd, AE_READABLE, adns_api_read_hdr_body, c);
            if (ret == AE_ERR)
                goto CLOSE;
            goto BACKTOPOLL;
        }
        else if (c->recvd_total < adns_api_hdr_len()) {
            goto BACKTOPOLL;
        }
        else {
            printf("reading of msg header exceeds what we expected");
            goto CLOSE;
        }
    }
CLOSE:
    //TODO: tell client the reason of failure
    freeClient(c);
BACKTOPOLL:
    admin.current_client = NULL;
    return;
}

/*
 * Almost the same as createClient, for port 5858 5353 work in parrellel
 */
static ioClient *createAdnsApiClient(int fd)
{
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
        if (aeCreateFileEvent(admin.el,fd,AE_READABLE, adns_api_read_hdr,
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
void acceptAdnsApiHandler(int fd, int flags)
{
    ioClient *c;

    if ((c = createAdnsApiClient(fd)) == NULL) {
        /*
         *printf("Error registering fd event for the new client: %s (fd=%d)",
         *    strerror(errno),fd);
         */
        close(fd); /* May be already closed, just ignore errors */
        return;
    }
}
