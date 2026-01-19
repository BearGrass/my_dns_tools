
/*
 * fwdctl - adns name server control utility
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "common.h"
#include "fwdctl_share.h"


char *server_ip = NULL;
int server_port = 0;

static int sock_fd = -1;
static struct cmd_msg *cmd_msg = NULL;

static int fwdctl_connect(char *ip, int port)
{
    int ret;
    struct sockaddr_in serv_addr;

    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
        return -1;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = inet_addr(ip);

    ret =
        connect(sock_fd, (struct sockaddr *)&serv_addr,
                sizeof(struct sockaddr));
    if (ret < 0) {
        LOG("ret = %d, connect to %s:%d fail", ret, ip, port);
        close(sock_fd);
        return -1;
    }

    //LOG("connect to %s:%d ok", ip, port);
    return 0;
}

static void fwdctl_cleanup(void)
{
    if (sock_fd > -1) {
        close(sock_fd);
        sock_fd = -1;
    }
}

static int set_cork(int fd, int val)
{
    int opt = val;
    return setsockopt(fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
}

static int set_cork_on(int fd)
{
    return set_cork(fd, 1);
}

static int set_cork_off(int fd)
{
    return set_cork(fd, 0);
}

#define RETRY_MAX_NUMS 5
static int tcp_process(char *sendBuf, char *recvBuf, int send_len, int recv_len)
{
    int len, retries = 0;;
    int flags = MSG_WAITALL;
    struct cmd_msg *msg = (struct cmd_msg *)sendBuf;
    //LOG("Send msg appending data:%s", msg->data);

    set_cork_on(sock_fd);
    len = send(sock_fd, sendBuf, send_len, 0);
    if (len != send_len) {
        return -1;
    }
    set_cork_off(sock_fd);

retry:
    len = recv(sock_fd, recvBuf, recv_len, flags);
    if (len == -1) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            retries++;
            if (retries > RETRY_MAX_NUMS)
			{
                return -1;
			}
            goto retry;
        }
        return -1;
    } else if (len == 0) {
        retries++;
        if (retries > RETRY_MAX_NUMS) {
            LOG("%s : no data recv", __func__);
            return -1;
        }
        goto retry;
    }
    LOG("%s: received packet size=%d on fd=%d", __func__, len, sock_fd);
    return len;
}

int nf_msg_linux_process_new(int cmdid, void * data, int * plen)
{
	int ret = -1, req_len, rsp_len;
	int rlen = *plen;
	socklen_t len;

	int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
	struct cmd_msg *msg = malloc(mlen);
	memset(msg,0,mlen);
	char buf[ADNS_IO_BUFLEN];
	memset(buf,0,sizeof(buf));
	/* init cmd message */
	msg->magic = CMD_MSG_MAGIC;
	msg->version = FWD_VERSION;
	msg->opcode = ALISS_CMD;
	msg->flags = 0;
	msg->cmd = 0;
	msg->seq = 0;
	msg->req_len = 0;
	msg->rsp_len = 0;

	if(fwdctl_connect(server_ip,server_port) < 0)	
	{
		ret = -1;
		goto exit;	
	}

	/* send cmd to remote and wait response */
	memcpy(msg->data, data, *plen);
	int dlen = *plen;

	req_len = sizeof(struct cmd_msg) + dlen;
	
	ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
	if (ret <= 0)
	{
		goto exit;
	}
	struct cmd_msg *reply = (struct cmd_msg *)buf;
	
	/* check ret value */
	if(!VALID_CMD_MSG(reply)){
		LOG("Forward DNS reply unknow data,magic error!");
		goto exit;
	}
	ret = reply->ret_val;
	if (msg->opcode != reply->opcode) {
		LOG("Forward DNS reply error,opcode not match!");
		goto exit;
	}
	if(ret < 0){
		LOG("Forward DNS reply error,infomation below\n%s\n",reply->data);
		goto exit;
	}
	
	//LOG("Forward DNS reply done !\n");
	#if 0
	memcpy(data, reply->data, reply->rsp_len);
	*plen = reply->rsp_len;
	#else
	memcpy(data, reply->data, rlen);
	*plen = rlen;
	#endif

exit:
	fwdctl_cleanup();
	free(msg);


	return ret;
}

int main(int argc, char **argv)
{
    int ret = 0;

    if (!server_ip)
		server_ip = "127.0.0.1";
	if (!server_port)
		server_port = 6666;

	ret = main_aliss(argc, argv);

    return ret;
}
