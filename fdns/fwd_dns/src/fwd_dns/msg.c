
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>

#include "rte_core.h"

#include "ldns.h"
#include "msg.h"
#include "log.h"
#include "dns_pkt.h"

#define LCORE_MSG_RING_SIZE 8192
#define MSG_MEMPOOL_SIZE  2048


struct rte_ring *lcore_msg_ring[RTE_MAX_LCORE];
struct rte_mempool *g_lcore_msg_pool;


struct lcore_msg_info *get_cmd_msg_info(int opcode, int len, void *data)
{
    struct lcore_msg_info *m = NULL;

    if (len > LCORE_MSG_MAX_LEN) {
        /*
        ALOG(SERVER, WARN, "Fail to do %s ,data len  %d > %d", __func__, len,
             LCORE_MSG_MAX_LEN);
        */
        STATS(IPC_MSG_EXCEED);
        return NULL;
    }

    m = lcore_msg_alloc(opcode);
    if (m == NULL) {
        return NULL;
    }

    rte_atomic16_init(&m->pcmd.ref);
    //rte_atomic16_set(&m->pcmd.ref, 0);
    m->pcmd.len = len;
    if (data != NULL) {
        rte_memcpy(m->pcmd.data, data, len);
    }

    return m;
}

static inline  uint8_t *adns_dname_from_str(const char *name, uint8_t *buff)
{
    if (name == NULL) {
        return NULL;
    }
    *buff = '\0';

    /* Parse labels. */
    const uint8_t *ch = (const uint8_t *)name;
    uint8_t *label = buff;
    uint8_t *w = buff + 1;      /* Reserve 1 for label len */
    while (*ch != '\0') {
        if (*ch == '.') {
            /* Zero-length label inside a dname - invalid. */
            if (*label == 0) {
                if (ch == (const uint8_t *)name) {
                    break;
                }
                return NULL;
            }
            label = w;
            *label = '\0';
        } else {
            *w = *ch;
            *label += 1;
        }
        ++w;
        ++ch;
    }

    /* Check for non-FQDN name. */
    if (*label > 0) {
        *w++ = '\0';
    }

    return w;
}


struct lcore_msg_info *get_del_key_msg_info(char *name, int qtype, uint8_t stype)
{
    struct lcore_msg_info *m = NULL;
    uint8_t *pend;

    m = lcore_msg_alloc(MSG_DEL_KEY);
    if (m == NULL) {
        return NULL;
    }

    pend = adns_dname_from_str(name, (uint8_t *)m->pcmd.data);
    if (pend == NULL) {
        lcore_msg_free(m);
        return NULL;
    }
    *(uint16_t *)pend = (uint16_t) qtype;
    pend += 2;
	*(uint8_t*) pend = stype;
	pend += 1;
    m->pcmd.len = pend - (uint8_t *)m->pcmd.data;
    rte_atomic16_init(&m->pcmd.ref);
    //rte_atomic16_set(&m->pcmd.ref, 0);

    return m;
}

void get_cmd_msg(struct lcore_msg_info *msg)
{
    rte_atomic16_inc(&msg->pcmd.ref);
}

void put_cmd_msg(struct lcore_msg_info *msg)
{
    if (rte_atomic16_dec_and_test(&msg->pcmd.ref)) {
        rte_mempool_put(g_lcore_msg_pool, (void *)msg);
    }
}

int send_cmd_msg(struct lcore_msg_info *msg, int lcore_id)
{
    if (msg == NULL)
        return -1;
    get_cmd_msg(msg);

    if (rte_ring_mp_enqueue(lcore_msg_ring[lcore_id], (void *)msg) < 0) {
        STATS(MSG_ENQUEUE_FAIL);
        put_cmd_msg(msg);
        return -1;
    }
    return 0;
}

int lcore_msg_init(void)
{
    int lcore_id = 0;
    int ring_num = 0;
    char tmp[30];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if ((app.lcore_params[lcore_id].type == e_LCORE_DISABLED)) {
            continue;
        }

        sprintf(tmp, "lcore_msg_ring_%d", lcore_id);
        lcore_msg_ring[lcore_id] = rte_ring_create(tmp, LCORE_MSG_RING_SIZE,
                SOCKET_ID_ANY, RING_F_SC_DEQ);

        if (lcore_msg_ring[lcore_id] == NULL) {
            RTE_LOG(ERR, LDNS, "Fail to crate %s", tmp);
            return -1;
        }
        ring_num++;
    }
    g_lcore_msg_pool = rte_mempool_create("g_lcore_msg_pool",
            LCORE_MSG_RING_SIZE * ring_num, sizeof(struct lcore_msg_info), 32, 0,
            NULL, NULL,
            NULL, NULL, SOCKET_ID_ANY, 0);

    return 0;
}
