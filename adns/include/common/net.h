
#ifndef _ADNS_NET_H_
#define _ADNS_NET_H_

#include <sys/socket.h>
//#include <arpa/inet.h>

#include "event.h"


#define DRM_F_WRITE 0x01
#define DRM_F_READ  0x02


struct drm_req {
	uint32_t version;
	int opcode;
	int flags;
	int seq;
	int data_len;
};

struct drm_rsp {
	uint32_t version;
	int opcode;

	int ret_val;
	int flags;
	int seq;
	int data_len;
};

enum conn_state {
	C_IO_HEADER = 0,
	C_IO_DATA_INIT,
	C_IO_DATA,
	C_IO_END,
	C_IO_CLOSED,
};

struct connection {
	int fd;
	unsigned int events;

	uint16_t port;
	//char ipstr[INET6_ADDRSTRLEN];
	char ipstr[46];

	enum conn_state c_rx_state;
	int rx_length;
	void *rx_buf;
	struct drm_req rx_hdr;

	enum conn_state c_tx_state;
	int tx_length;
	void *tx_buf;
	struct drm_rsp tx_hdr;

	struct list_head blocking_siblings;
};

char *addr_to_str(char *str, int size, uint8_t *addr, uint16_t port);
uint8_t *str_to_addr(int af, const char *ipstr, uint8_t *addr);

int set_nonblocking(int fd);
int set_nodelay(int fd);
int set_keepalive(int fd);
int set_timeout(int fd);
int set_cork(int fd, int val);

static inline int set_cork_on(int fd)
{
	return set_cork(fd, 1);
}

static inline int set_cork_off(int fd)
{
	return set_cork(fd, 0);
}

int conn_tx_off(struct connection *conn);
int conn_tx_on(struct connection *conn);
int conn_rx_off(struct connection *conn);
int conn_rx_on(struct connection *conn);
int is_conn_dead(struct connection *conn);

int do_read(int sockfd, void *buf, int len);
int drm_read(struct connection *conn, enum conn_state next_state);
int drm_write(struct connection *conn, enum conn_state next_state, int flags);
int connect_to(const char *name, int port);
int send_req(int sockfd, struct drm_req *hdr, void *data, unsigned int *wlen);
int exec_req(int sockfd, struct drm_req *hdr, void *data,
	     unsigned int *wlen, unsigned int *rlen);

int get_local_addr(uint8_t *bytes);
int create_listen_ports(int port, int (*callback)(int fd, void *), void *data);

#endif

