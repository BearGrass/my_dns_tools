
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>

#include "rte_core.h"

#include "adns.h"
#include "msg.h"


#define MSG_W2M_RING_SIZE 8192
#define MSG_MEMPOOL_SIZE  8192  

static struct rte_ring  *msg_w2m_ring; /* worker lcore to misc lcore */
static struct rte_mempool *message_pool;

struct msg_info *msg_alloc(void)
{
    void *msg;

    if (rte_mempool_get(message_pool, &msg) < 0){
        printf("Worker to misc lcore msg alloc failed\n");
        return NULL;
    }

    return (struct msg_info *)msg;
}

void msg_free(struct msg_info *msg)
{
    rte_mempool_put(message_pool, (void *)msg);
}

int msg_w2m_send(struct rte_mbuf *m, uint8_t portid)
{
    struct msg_info *msg;

    msg = msg_alloc();
    if (msg == NULL) {
        printf("work --> misc alloc msg fail in %s()\n", __func__);
        rte_pktmbuf_free(m);
        return -1;
    }

    msg->port_id = portid;
    msg->m = m;

    if (rte_ring_enqueue(msg_w2m_ring, (void *)msg) < 0){
        printf("Input msg enqueue fail in %s()\n", __func__);
        msg_free(msg);
        rte_pktmbuf_free(m);
        return -1;
    }

    return 0;
}

struct msg_info *msg_w2m_recv(void)
{
    int ret;
    void *msg;

    ret = rte_ring_dequeue(msg_w2m_ring, &msg);
    if (ret < 0)
        return NULL;

    return (struct msg_info *)msg;
}

int msg_init(void)
{
    msg_w2m_ring = rte_ring_create("msg_w2m", MSG_W2M_RING_SIZE, SOCKET_ID_ANY, 0);
    if (msg_w2m_ring == NULL) {
        printf("Faile to create wroker to misc ring\n");
        return -1;
    }	

    message_pool = rte_mempool_create("msg_w2m", MSG_MEMPOOL_SIZE, 
            sizeof(struct msg_info), 0, 0, NULL, NULL, NULL, NULL, 
            SOCKET_ID_ANY, 0);
    if (message_pool == NULL){
        printf("Faile to create message pool\n");
        return -1;
    }

    return 0;
}

