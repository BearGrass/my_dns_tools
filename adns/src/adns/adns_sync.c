
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <rte_mempool.h>
#include <rte_byteorder.h>
#include <rte_string_fns.h>
#include <assert.h>

#include "consts.h"
#include "wire.h"

#include "adns_sync.h"


static struct rte_mempool *sync_mp = NULL;

/* static functions not used in this file, comment it to avoid gcc warning
   uncomment them if used or remove static modifier */
#if 0
static int tcp_send(int fd, uint8_t *msg, size_t msglen)
{
    struct iovec iov[2];
    uint16_t pktsize = htons(msglen);

    iov[0].iov_base = &pktsize;
    iov[0].iov_len = sizeof(uint16_t);
    iov[1].iov_base = msg;
    iov[1].iov_len = msglen;

    int total_len = iov[0].iov_len + iov[1].iov_len;
    int sent = writev(fd, iov, 2);
    if (sent != total_len) {
        return -1;
    }

    return msglen; /* Do not count the size prefix. */
}
#endif

int tcp_recv(int fd, uint8_t *buf, size_t len, sockaddr_t *addr)
{
    int flags = MSG_WAITALL;

    /* Receive size. */
    unsigned short pktsize = 0;
    int n = recv(fd, &pktsize, sizeof(unsigned short), flags);
    if (n < 0) {
        if (errno == EAGAIN) {
            return -EAGAIN;
        } else {
            return -1;
        }
    }

    pktsize = ntohs(pktsize);
    if (pktsize == 0) {
        return -1;
    }
    printf("tcp: incoming packet size=%hu on fd=%d\n", pktsize, fd);

    if (len < pktsize) {
        return -ENOMEM;
    }

    /* Get peer name. */
    if (addr) {
        if (getpeername(fd, (struct sockaddr *)addr, &addr->len) < 0) {
            return -1;
        }
    }

    /* Receive payload. */
    n = recv(fd, buf, pktsize, flags);
    if (n < 0) {
        if (errno == EAGAIN) {
            return -EAGAIN;
        } else {
            return -1;
        }
    }
    printf("tcp: received packet size=%d on fd=%d\n", n, fd);

    return n;
}

/* static functions not used in this file, comment it to avoid gcc warning
   uncomment them if used or remove static modifier */
#if 0
static int sync_send_tcp(int fd, sockaddr_t *addr, uint8_t *msg, size_t msglen)
{
    return tcp_send(fd, msg, msglen); 
}

static int sync_recv_tcp(int fd, sockaddr_t *addr, uint8_t *buf, size_t buflen)
{
    return tcp_recv(fd, buf, buflen, addr); 
}
#endif

int sockaddr_tostr(const sockaddr_t *addr, char *dst, size_t size)
{
    if (!addr || !dst || size == 0) {
        return -1;
    }

    size_t minlen = INET_ADDRSTRLEN;

    if (size < minlen) {
        return -1;
    }

    dst[0] = '\0';
    /* Load IPv4 if set. */
    if (addr->len == sizeof(struct sockaddr_in)) {
        inet_ntop(AF_INET, &addr->addr4.sin_addr, dst, size);
    }

    return 0;
}

/* UDP recvfrom() request struct. */
struct udp_recvfrom {
    int fd;
    sockaddr_t addr;
    struct iovec iov;
    uint8_t buf[SOCKET_MTU_SIZE];
    size_t buflen;
    struct msghdr msg;
};

static struct udp_recvfrom *udp_rq = NULL;

struct sync_packet *sync_packet_new(void)
{
    void *data;

    if (rte_mempool_get(sync_mp, &data) < 0){
        printf("Failed to alloc memory for rrset\n");
        return NULL;
    }

    return (struct sync_packet *)data;
}

void sync_packet_free(struct sync_packet *packet)
{
    rte_mempool_put(sync_mp, (void *)packet);
}

static inline void sync_error_response(uint8_t rcode, uint8_t *response_wire)
{
    adns_wire_set_qr(response_wire);
    adns_wire_set_rcode(response_wire, rcode);
}

static int sync_resp_err_wire(uint8_t *query, size_t size, uint8_t rcode)
{
    /* invalid query packet */
    if (size < 2) {
        return -1;
    }

    uint8_t flags1;

    if (size > ADNS_WIRE_OFFSET_FLAGS1) {
        flags1 = adns_wire_get_flags1(query);
    }
    sync_error_response(rcode, query);

    return 0;
}

/* Get opcode from wire packet */
static uint8_t sync_get_opcode(const uint8_t *wire)
{
    uint8_t flags = adns_wire_get_flags1(wire);
    return adns_wire_flags_get_opcode(flags);
}

static int sync_packet_is_query(const uint8_t *wire)
{
    uint8_t flags = adns_wire_get_flags1(wire);
    return adns_wire_flags_get_qr(flags) == 0;
}


struct dns_header {
    uint16_t id;
    uint8_t flags1;
    uint8_t flags2;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

struct sync_question {
    uint16_t len;	/* total len */

    uint8_t *name;
    uint8_t name_len;

    uint16_t type;
    uint16_t class;
} __attribute__((packed));

struct sync_answer {
    uint16_t len;	/* total len */

    uint8_t *name;
    uint8_t name_len;

    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t data_len;
    uint8_t *data;
} __attribute__((packed));


/*
 * Parse dns header, not do sanity check
 */
static int sync_parse_header(uint8_t *qbuf, size_t qbuflen,
        struct dns_header *dnh)
{
    if (qbuflen < ADNS_WIRE_HEADER_SIZE) {
        return -1;
    }

    dnh->id = adns_wire_get_id(qbuf);
    dnh->flags1 = adns_wire_get_flags1(qbuf);
    dnh->flags2 = adns_wire_get_flags2(qbuf);
    dnh->qdcount = adns_wire_get_qdcount(qbuf);
    dnh->ancount = adns_wire_get_ancount(qbuf);
    dnh->nscount = adns_wire_get_nscount(qbuf);
    dnh->arcount = adns_wire_get_arcount(qbuf);

    return 0;
}

/*
 * Parse dns query and answer section
 */
static int sync_parse_qa(uint8_t *qbuf, size_t qbuflen,
        struct sync_question *question, struct sync_answer *answer)
{
    uint8_t *pos;

    /* domain name must end with 0, so just search for 0 */
    unsigned int i = ADNS_WIRE_HEADER_SIZE;
    while (i < qbuflen && qbuf[i] != 0) { /* calc domain name len */
        ++i;
    }

    /* parse question */
    question->name = qbuf + ADNS_WIRE_HEADER_SIZE;
    question->name_len = i - ADNS_WIRE_HEADER_SIZE;
    question->type = adns_wire_read_u16(qbuf + i + 1);
    question->class = adns_wire_read_u16(qbuf + i + 3);
    question->len = question->name_len + 4;

    /* parse answer */
    pos = qbuf + question->len;
    if (adns_wire_is_pointer(pos)) {
        answer->name = question->name;
        answer->name_len = question->name_len;
        answer->type = adns_wire_read_u16(pos + 2);
        answer->class = adns_wire_read_u16(pos + 4);
        answer->ttl= adns_wire_read_u32(pos + 6);
        answer->data_len = adns_wire_read_u16(pos + 10);
        answer->data = pos + 12;
        answer->len = answer->data_len + 12;
    } else {
        return -1;
    }

    return 0;
}

static int sync_notify_process(uint8_t *qbuf, size_t qbuflen)
{
    int ret;
    struct dns_header dnh;
    struct sync_question question;
    struct sync_answer answer;

    /* parse dns header */
    ret = sync_parse_header(qbuf, qbuflen, &dnh);
    if (ret < 0)
        return -1;

    /* qdcount=1, ancount=1, nscount=0, arcount=1 */
    if (dnh.qdcount != 1 || dnh.ancount != 1 || dnh.nscount != 0
            || dnh.arcount != 1)
        return -1;

    /* parse question and answer section */
    ret = sync_parse_qa(qbuf, qbuflen, &question, &answer);
    if (ret < 0)
        return -1;

    /* Parse additional(tsig) rr */
    /* uint8_t *tsig_wire = qbuf + ADNS_WIRE_HEADER_SIZE + question.len
        + answer.len; */


    return 0;
}

static int udp_handle(uint8_t *qbuf, size_t qbuflen,
        size_t *resp_len, sockaddr_t* addr)
{
    int ret;
    char strfrom[46];
    memset(strfrom, 0, sizeof(strfrom));
    sockaddr_tostr(addr, strfrom, sizeof(strfrom));
    printf("udp: received %zd bytes from '%s:%d'.\n", qbuflen,
            strfrom, rte_be_to_cpu_16(addr->addr4.sin_port));

    *resp_len = SOCKET_MTU_SIZE;

    if(NULL == qbuf){
        return -1;
    }

    /* alloc memory for sync response packet */
    struct sync_packet *packet = sync_packet_new();
    if (packet == NULL) {
        printf("Failed to alloc memory for sync packet\n");
        ret = sync_resp_err_wire(qbuf, qbuflen, ADNS_RCODE_SERVFAIL);
        return ret;
    }

    /* Get opcode, check if notify packet */
    uint8_t opcode = sync_get_opcode(qbuf);
    switch (opcode) {
        case ADNS_OPCODE_NOTIFY:
            /* Adns deploy as slave, so when opcode is query, only process
             * query packet, refuse notify response.
             */
            if (sync_packet_is_query(qbuf) == 0) {
                ret = sync_resp_err_wire(qbuf, qbuflen, ADNS_RCODE_REFUSED);
                return ret;
            }

            /* parse question
             */
            ret = sync_notify_process(qbuf, qbuflen);
            if (ret < 0)
                sync_resp_err_wire(qbuf, qbuflen, ADNS_RCODE_REFUSED);
            break;
        default:
            sync_resp_err_wire(qbuf, qbuflen, ADNS_RCODE_NOTIMPL);
            break;
    }

    return 0;
}

static int udp_recvfrom_init(void)
{
    udp_rq = malloc(sizeof(struct udp_recvfrom));
    if (udp_rq == NULL)
        return -ENOMEM;
    memset(udp_rq, 0, sizeof(struct udp_recvfrom));

    udp_rq->addr.len = sizeof(struct sockaddr_in);
    udp_rq->buflen = SOCKET_MTU_SIZE;
    udp_rq->iov.iov_base = udp_rq->buf;
    udp_rq->iov.iov_len = udp_rq->buflen;
    udp_rq->msg.msg_name = &udp_rq->addr;
    udp_rq->msg.msg_namelen = udp_rq->addr.len;
    udp_rq->msg.msg_iov = &udp_rq->iov;
    udp_rq->msg.msg_iovlen = 1;
    udp_rq->msg.msg_control = NULL;
    udp_rq->msg.msg_controllen = 0;

    return 0;
}

static void udp_recvfrom_cleanup(void)
{
    if (udp_rq != NULL) {
        free(udp_rq);
        udp_rq = NULL;
    }
}

static int udp_recvfrom_recv(int fd)
{
    int ret = recvmsg(fd, &udp_rq->msg, 0);
    if (ret > 0) {
        udp_rq->fd = fd;
        udp_rq->buflen = ret;
        return 1;
    }

    /* error or no data */
    return 0;
}

static int udp_recvfrom_handle(void)
{
    /* Process received pkt. */
    udp_rq->addr.len = udp_rq->msg.msg_namelen;
    int ret = udp_handle(udp_rq->buf, udp_rq->buflen,
            &udp_rq->iov.iov_len, &udp_rq->addr);
    if (ret < 0) {
        udp_rq->iov.iov_len = 0;
    }

    return ret;
}

static int udp_recvfrom_send(void)
{
    int rc = 0;
    if (udp_rq->iov.iov_len > 0) {
        rc = sendmsg(udp_rq->fd, &udp_rq->msg, 0);
    }

    /* Reset buffer size and address len. */
    udp_rq->iov.iov_len = SOCKET_MTU_SIZE;
    udp_rq->addr.len = sizeof(struct sockaddr_in);
    udp_rq->msg.msg_namelen = udp_rq->addr.len;

    /* Return number of packets sent. */
    if (rc > 1) {
        return 1;
    }

    return 0;
}

void sync_udp_process(int fd)
{
    int rcvd = 0;

    rcvd = udp_recvfrom_recv(fd);
    if (rcvd <= 0)
        return;

    printf("Rcvd udp packet\n");
    udp_recvfrom_handle();
    udp_recvfrom_send();
}

int adns_sync_init(void)
{
    int ret;
    char name[64];

    /* Create mempool for sync dns packet */
    snprintf(name, sizeof(name), "sync_mempool");
    sync_mp = rte_mempool_create(name, SYNC_PACKET_NUM, 
            sizeof(struct sync_packet), 0, 0, NULL, NULL, NULL, NULL, 
            SOCKET_ID_ANY, 0);
    if (sync_mp == NULL) {
        printf("Create mempool for sync packet error\n");
        goto err;
    }

    ret = udp_recvfrom_init();
    if (ret < 0) {
        printf("udp init error\n");
        goto err;
    }


    return 0;
err:
    return -1;
}

void adns_sync_cleanup(void)
{
    udp_recvfrom_cleanup();
}

