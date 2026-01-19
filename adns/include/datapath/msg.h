
#ifndef _ADNS_MSG_H_
#define _ADNS_MSG_H_

#include <stdint.h>


struct msg_info {
	struct rte_mbuf *m;
	uint8_t port_id;
};

struct msg_info *msg_w2m_recv(void);
int msg_w2m_send(struct rte_mbuf *m, uint8_t portid);

int msg_init(void);


#endif

