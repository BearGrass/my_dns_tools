
/*
 * fwdctl - adns name server control utility
 */

#include <errno.h>
#include <limits.h>
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
#include <unistd.h>
#include "common.h"
#include "fwdctl_share.h"
#include "log_def.h"
#include "fwd_type.h"

#ifdef _MAX_LCORE
#define MAX_LCORE _MAX_LCORE
#else
#define MAX_LCORE 80
#endif

#define CAL(x,y) ((x > y) ? x - y : 0)

struct cpu_util {
    int lcore_id;
    uint64_t send;
    uint64_t recv;
    uint64_t hc_send;
    uint64_t hc_tw;
    uint64_t retry;
    uint64_t ttl_ck;
    uint64_t msg;
    uint64_t all;
};

char *server_ip = NULL;
int server_port = 0;

/* should read config file or specified by command option */
static int sock_fd = -1;

typedef int (*adns_cmdf_t) (int argc, char *argv[]);

typedef struct adns_cmd {
    adns_cmdf_t cb;
    int need_conf;
    const char *name;
    const char *params;
    const char *desc;
} adns_cmd_t;

static int __parse_cpu_util(struct cpu_util *cpu, char *line);
static int _cal_cpu_util(struct cpu_util *pre, struct cpu_util *cur, int count);
static int _cpu_stats(struct cpu_util *cpu_util);

static int parse_cpu_util(struct cpu_util *cpu, char *msg);

static uint8_t *dname_str_to_wire(char *name, size_t len, int *res_len)
{
    uint8_t *wire, *label, *w;
    int wire_size;
    char *ch, *np;

    if (name == NULL || len == 0 || len > 255) {
        return NULL;
    }

    wire_size = len + 1;
    if (name[0] == '.' && len == 1) {
        wire_size = 1;
        len = 0;
    } else if (name[len - 1] != '.') {
        ++wire_size;
    }

    *res_len = wire_size;

    wire = malloc(wire_size * sizeof(uint8_t));
    if (wire == NULL) {
        return NULL;
    }
    *wire = '\0';

    ch = name;
    np = ch + len;
    label = wire;
    w = wire + 1;

    while (ch != np) {
        if (*ch == '.') {
            if (*label == 0) {
                free(wire);
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

    if (*label > 0) {
        *w = '\0';
    }

    return wire;
}

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
        LOG("connect to %s:%d fail", ip, port);
        close(sock_fd);
        return -1;
    }

    LOG("connect to %s:%d ok", ip, port);
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
    LOG("Send msg appending data:%s", msg->data);

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
                return -1;
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

static int valid_log_type(char *t)
{
    if (t == NULL)
        return -1;
    int i;
    for (i = 0; i < LOG_FILE_NUM; i++) {
        if (strcasecmp(t, log_type_str[i]) == 0)
            return i;
    }
    return -1;
}

static int valid_log_level(char *level)
{
    if (level == NULL)
        return -1;
    int i;
    for (i = 0; i < LOG_LEVEL_NUM; i++) {
        if (strcasecmp(level, log_level_str[i]) == 0)
            return i;
    }
    return -1;
}

static int __cmd_set_status(int type, int argc, char *argv[])
{

    int ret = -1, req_len;
    if (argv[0] == NULL) {
        LOG("need status arg");
        return -1;
    }
    int status = -1;
    if (strcasecmp(argv[0], "ON") == 0)
        status = STATUS_ON;
    if (strcasecmp(argv[0], "OFF") == 0)
        status = STATUS_OFF;
    if (status == -1) {
        LOG("Unknow status,must be on or off");
        return -1;
    }

    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = type;
    msg.flags = status;
    msg.cmd = 0;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;

    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    return ret;
}

static int cmd_set_oversea_status(int argc, char *argv[])
{
    return __cmd_set_status(FWD_SET_OVERSEA_STATUS, argc, argv);
}

static int cmd_set_blacklist_status(int argc, char *argv[])
{
    return __cmd_set_status(FWD_SET_BLACK_STATUS, argc, argv);
}

static int cmd_set_whitelist_status(int argc, char *argv[])
{
    return __cmd_set_status(FWD_SET_WHITE_STATUS, argc, argv);
}
static int cmd_set_man_whitelist_status(int argc, char *argv[])
{
    return __cmd_set_status(FWD_SET_MAN_WHITE_STATUS, argc, argv);
}
static int cmd_set_man_blacklist_status(int argc, char *argv[])
{
    return __cmd_set_status(FWD_SET_MAN_BLACK_STATUS, argc, argv);
}
static int cmd_set_lcoreshare_status(int argc,char *argv[])
{
    return __cmd_set_status(FWD_SET_SHARE_STATUS,argc,argv);
}

static int cmd_get_wild_attack_status(int argc,char *argv[])
{
    int ret = -1, req_len;

    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = FWD_GET_WILD_ATTACK_STATUS;
    msg.flags = 0;
    msg.cmd = 0;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;

    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    return ret;
}

static int cmd_view_nodes_ttlfetch_threshold(int argc, char *argv[])
{
    int ret = -1, req_len;
    if (argv[0] == NULL) {
        LOG("Invalid view_nodes_ttlfetch_threshold,type must be >= 0 and <= %d",
            MVNODES);
        return -1;
    }
    int count = atoi(argv[0]);
    if (count < 0 || count > MVNODES) {
        LOG("Invalid view_nodes_ttlfetch_threshold %d,type must be >= 0 and <= %d", count, MVNODES);
        return -1;

    }
    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = FWD_SET_VIEW_NODES_TTL_THRESHOLD;
    msg.flags = count;
    msg.cmd = 0;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;

    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    return ret;
}

static int cmd_set_log(int argc, char *argv[])
{
    int ret = -1, req_len;
    int i;
    int type = valid_log_type(argv[0]);
    int level = valid_log_level(argv[1]);
    if (type < 0) {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (i = 0; i < LOG_FILE_NUM; i++) {
            strcat(buf, log_type_str[i]);
            strcat(buf, ",");
        }
        LOG("Invalid log type '%s',type must be %s", argv[0], buf);
        return -1;
    }

    if (level < 0) {

        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (i = 0; i < LOG_LEVEL_NUM; i++) {
            strcat(buf, log_level_str[i]);
            strcat(buf, ",");
        }
        LOG("Invalid log level '%s',level must be %s", argv[0], buf);
        return -1;
    }
    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = FWD_SET_LOG;
    msg.flags = level;
    msg.cmd = type;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;

    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    return ret;
}

static int cmd_set_view_backup(int argc, char *argv[])
{
    int ret = -1, req_len;

    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    memset(msg, 0, mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->opcode = FWD_SET_BACKUP;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;

    /* send cmd to remote and wait response */
    strcat(msg->data, argv[0]);
    strcat(msg->data, FWD_VIEW_BACKUP_SPLIT);
    strcat(msg->data, argv[1]);
    int dlen = strlen(msg->data) + 1;

    req_len = sizeof(struct cmd_msg) + dlen;

    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode) {
        LOG("Forward DNS reply error,opcode not match!");
        goto exit;
    }
    if (ret < 0) {
        LOG("Forward DNS reply error,infomation below\n%s\n", reply->data);
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    free(msg);
    return ret;
}

static int cmd_cpu_stats(int argc, char *argv[])
{

    struct cpu_util cpu_util[2][MAX_LCORE];
    struct cpu_util *pre = NULL, *cur = NULL;
    int pre_count, cur_count, used, using;

    pre = cpu_util[0];
    pre_count = _cpu_stats(pre);
    if (pre_count < 0)
        goto error;
    used = 0;

    while (1) {
        fwdctl_cleanup();
        sleep(1);
        if (fwdctl_connect(server_ip, server_port) < 0)
            goto error;
        using = (used + 1) % 2;
        cur = cpu_util[using];
        cur_count = _cpu_stats(cur);
        if (cur_count < 0 || pre_count != cur_count)
            goto error;
        if (_cal_cpu_util(pre, cur, pre_count) < 0)
            goto error;
        pre = cur;
        used = using;
        if (argv[0] == NULL) {
            return 0;
        }
        if (!strcasecmp(argv[0], "live")) {
            continue;
        } else {
            return 0;
        }
    }

error:
    LOG("CPU STATS ERROR!");
    return -1;

}

static int _cal_cpu_util(struct cpu_util *pre, struct cpu_util *cur, int count)
{
    int i;
    LOG("CPU |%-15s|%-15s|%-15s|%-15s|%-15s|%-15s|%-15s", "send", "recv",
        "hc_send", "hc_tw", "retry", "ttl_ck", "msg");
    struct cpu_util cd;
    double a_send = 0, a_recv = 0, a_hc_send = 0, a_hc_tw = 0, a_retry =
        0, a_ttl_ck = 0, a_msg = 0;
    for (i = 0; i < count; i++) {
        if (pre[i].lcore_id != cur[i].lcore_id)
            return -1;
        cd.send = CAL(cur[i].send, pre[i].send);
        cd.recv = CAL(cur[i].recv, pre[i].recv);
        cd.hc_send = CAL(cur[i].hc_send, pre[i].hc_send);
        cd.hc_tw = CAL(cur[i].hc_tw, pre[i].hc_tw);
        cd.retry = CAL(cur[i].retry, pre[i].retry);
        cd.ttl_ck = CAL(cur[i].ttl_ck, pre[i].ttl_ck);
        cd.msg = CAL(cur[i].msg, pre[i].msg);
        cd.all = CAL(cur[i].all, pre[i].all);

        double send = (cd.send * 1.0 / cd.all * 100);
        a_send += send;

        double recv = (cd.recv * 1.0 / cd.all * 100);
        a_recv += recv;

        double hc_send = (cd.hc_send * 1.0 / cd.all * 100);
        a_hc_send += hc_send;

        double hc_tw = (cd.hc_tw * 1.0 / cd.all * 100);
        a_hc_tw += hc_tw;

        double retry = (cd.retry * 1.0 / cd.all * 100);
        a_retry += retry;

        double ttl_ck = (cd.ttl_ck * 1.0 / cd.all * 100);
        a_ttl_ck += ttl_ck;

        double msg = (cd.msg * 1.0 / cd.all * 100);
        a_msg += msg;

        LOG("%-4d|%-15.2lf|%-15.2lf|%-15.2lf|%-15.2lf|%-15.2lf|%-15.2lf|%-15.2lf", pre[i].lcore_id, send, recv, hc_send, hc_tw, retry, ttl_ck, msg);
    }
    LOG("AVG |%-15.2lf|%-15.2lf|%-15.2lf|%-15.2lf|%-15.2lf|%-15.2lf|%-15.2lf", a_send / count, a_recv / count, a_hc_send / count, a_hc_tw / count, a_retry / count, a_ttl_ck / count, a_msg / count);
    return 0;
}

static int _cpu_stats(struct cpu_util *cpu_util)
{
    int ret = -1, req_len;

    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = FWD_CPU_UTIL;
    msg.flags = 0;
    msg.cmd = 0;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;

    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    int count = parse_cpu_util(cpu_util, reply->data);
    if (count <= 0) {
        LOG("Parse cpu util error!");
        goto exit;
    }

    return count;
//  LOG("Forward DNS reply done ! \n%s\n-------OVER\n",reply->data);

exit:
    return ret;
}

static int __parse_cpu_util(struct cpu_util *cpu, char *line)
{
    int lcore_id;
    uint64_t send;
    uint64_t recv;
    uint64_t hc_send;
    uint64_t hc_tw;
    uint64_t retry;
    uint64_t ttl_ck;
    uint64_t msg;
    uint64_t all;
    int ret =
        sscanf(line, "%d |%lu |%lu |%lu |%lu |%lu |%lu |%lu |%lu",
               &lcore_id, &send, &recv, &hc_send, &hc_tw, &retry, &ttl_ck, &msg,
               &all);
    if (ret != 9)              /* this should be the number of cpu points */
        return -1;
    cpu->lcore_id = lcore_id;
    cpu->send = send;
    cpu->recv = recv;
    cpu->hc_send = hc_send;
    cpu->hc_tw = hc_tw;
    cpu->retry = retry;
    cpu->ttl_ck = ttl_ck;
    cpu->msg = msg;
    cpu->all = all;
    return 0;

}

static int parse_cpu_util(struct cpu_util *cpu, char *msg)
{
    char *end;
    int count = 0;
    const int M = 1024;
    while ((end = strstr(msg, "\r\n")) != NULL) {
        char line[M];
        int len = end - msg;
        if (len >= M)
            return -1;
        memcpy(line, msg, len);
        line[len] = '\0';
        if (__parse_cpu_util(cpu + count, line) < 0)
            return -1;
        count++;
        msg = (end + 2);
        if (count >= MAX_LCORE - 10)
            return -1;
    }
    return count;
}

static int cmd_version(int argc, char *argv[])
{
    int ret = -1, req_len;

    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = FWD_GET_VERSION;
    msg.flags = 0;
    msg.cmd = 0;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;

    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    LOG("fwdctl version [%s]", FWD_VERSION_STR);
    LOG("fwd_dns_dpdk version [%s]", reply->data);
    if (strcmp(reply->data, FWD_VERSION_STR) == 0) {
        LOG("ALIDNS fwdctl&fwd_dns_dpdk Version Match");
    } else
        LOG("ALIDNS fwdctl&fwd_dns_dpdk Version NotMatch");

exit:
    return ret;
}

static int cmd_statsreset(int argc, char *argv[])
{
    int ret = -1, req_len;

    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = FWD_STATSRESET;
    msg.flags = 0;
    msg.cmd = 0;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;

    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    return ret;
}

static int _stats(int argc, char *argv[], int opcode)
{

    int ret = -1, req_len;

    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = opcode;
    msg.flags = 0;
    msg.cmd = 0;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;

    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    return ret;
}

static int cmd_stats(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_STATS);
}

static int cmd_cache_state(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_CACHE_STATE);
}

static int cmd_req_stats(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_REQ_STATS);
}

static int cmd_view_stats(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_VIEW_STATS);
}

static int cmd_drop_stats(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_DROP_STATS);
}

static int cmd_prefetch_stats(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_PREFETCH_STATS);
}

static int cmd_nodes_stats(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_VIEW_NODES);
}

static int cmd_view_state(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_VIEW_STATE);
}

static int cmd_dns_state(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_DNS_STATE);
}

static int cmd_dns_cnts(int argc, char *argv[])
{
    return _stats(argc, argv, FWD_DNS_CNTS);
}

static int cmd_protect_stop(int argc, char *argv[])
{
    int ret = -1, req_len;

    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    memset(msg, 0, mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->opcode = FWD_DENY_DNS_STOP;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;

    /* send cmd to remote and wait response */

    req_len = sizeof(struct cmd_msg);

    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode) {
        LOG("Forward DNS reply error,opcode not match!");
        goto exit;
    }
    if (ret < 0) {
        LOG("Forward DNS reply error,infomation below\n%s\n", reply->data);
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    free(msg);
    return ret;
}

static int cmd_protect_start(int argc, char *argv[])
{
    int ret = -1, req_len;

    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    memset(msg, 0, mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->opcode = FWD_DENY_DNS_START;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;

    /* send cmd to remote and wait response */
    strcat(msg->data, argv[0]);

    int dlen = strlen(msg->data) + 1;

    req_len = sizeof(struct cmd_msg) + dlen;

    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode) {
        LOG("Forward DNS reply error,opcode not match!");
        goto exit;
    }
    if (ret < 0) {
        LOG("Forward DNS reply error,infomation below\n%s\n", reply->data);
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    free(msg);
    return ret;
}

static int cmd_delreg(int argc, char *argv[])
{
    int ret = -1, req_len;

    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    memset(msg, 0, mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->opcode = FWD_DEL_REG;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;

    /* send cmd to remote and wait response */
    strcat(msg->data, argv[0]);

    int dlen = strlen(msg->data) + 1;

    req_len = sizeof(struct cmd_msg) + dlen;

    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode) {
        LOG("Forward DNS reply error,opcode not match!");
        goto exit;
    }
    if (ret < 0) {
        LOG("Forward DNS reply error,infomation below\n%s\n", reply->data);
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    free(msg);
    return ret;
}

static int cmd_del(int argc, char *argv[])
{
    int ret = -1, req_len;

    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    memset(msg, 0, mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->opcode = FWD_DEL;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;

    if (msg == NULL) {
        LOG("malloc msg failed");
        goto exit;
    }
    if (argc < 1) {
        LOG("Invalid number of argv(%d)", argc);
        goto exit;
    }
	if (!strcmp("batch", argv[0])) {
		if (argv[1] && argv[2]) {
			snprintf(msg->data, ADNS_IO_BUFLEN, "batch%c%s %s",
					FWD_DEL_STYPE_SPLIT, argv[1], argv[2]);
		} else {
			LOG("Invalid number of argv(%d)", argc);
			goto exit;
		}
	} else if (!strcmp("all", argv[0])) {
		strcat(msg->data, argv[0]);
	} else {
		if (argv[1] && argv[2]) {
			snprintf(msg->data, ADNS_IO_BUFLEN, "%c%s %s%s%s",
					FWD_DEL_STYPE_SPLIT, argv[0], argv[1], FWD_DEL_SPLIT,
					argv[2]);
		} else {
			LOG("Invalid number of argv(%d)", argc);
			goto exit;
		}
	}
    /* send cmd to remote and wait response */
    int dlen = strlen(msg->data) + 1;

    req_len = sizeof(struct cmd_msg) + dlen;

    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode) {
        LOG("Forward DNS reply error,opcode not match!");
        goto exit;
    }
    if (ret < 0) {
        LOG("Forward DNS reply error,infomation below\n%s\n", reply->data);
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    free(msg);
    return ret;
}

static inline double byte_to_gigabyte(const uint64_t byte_num) {
    return byte_num * 1.0 / 1024 / 1024 / 1024;
}

static int show_memory_info(struct mem_info_t *mem_info)
{
    int i = 0, sok_id;
    printf("-----------------------------------------------------------------MEMORY INFO-------------------------------------------------------\n");

    for (sok_id = 0; sok_id < RTE_MAX_NUMA_NODES; sok_id++) {
        if (mem_info->heap_stats[sok_id].heap_totalsz_bytes == 0) {
            continue;
        }

        printf("---------DPDK HEAP MEMORY, SOCKET[%d]:---------\n"
                "Heap_size:%zu\n"
                "Free_size:%zu\n"
                "Alloc_size:%zu\n"
                "Greatest_free_size:%zu\n"
                "Alloc_count:%u\n"
                "Free_count:%u\n", sok_id,
                mem_info->heap_stats[sok_id].heap_totalsz_bytes,
                mem_info->heap_stats[sok_id].heap_freesz_bytes,
                mem_info->heap_stats[sok_id].heap_allocsz_bytes,
                mem_info->heap_stats[sok_id].greatest_free_size,
                mem_info->heap_stats[sok_id].alloc_count,
                mem_info->heap_stats[sok_id].free_count);
    }

    printf("---------DPDK MEMORY ZONE USAGE:---------\n"
            "ZONE COUNT:     %16lu \n" "TOTAL USED:    %16lfG%16lf%%\n",
            mem_info->count, byte_to_gigabyte(mem_info->used),
            mem_info->used * 100.0 / mem_info->total);
    for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
        if (mem_info->used_per_socket[i] != 0) {
            printf("SOCKET%d USED:  %16lfG%16lf%%\n",
                    i, byte_to_gigabyte(mem_info->used_per_socket[i]),
                    mem_info->used_per_socket[i] * 100.0 /
                    mem_info->total_per_socket[i]);
        }
    }
    printf
        ("\nZONE_NAME                       [ ZONE_LENGTH   =  COMMON_BASE +      OBJ_COUNT *        OBJ_SIZE ]"
         "    OBJ_PAY_LOAD      AVAIL_COUNT         AVAIL_PER\n");
    for (i = 0; i < RTE_MAX_MEMZONE; i++) {
        if (mem_info->zone_info_list[i].name[0] != 0) {
            printf("%-32s%16lfG",
                    mem_info->zone_info_list[i].name,
                    byte_to_gigabyte(mem_info->zone_info_list[i].len));
            if (mem_info->zone_info_list[i].is_pool == 0) {
                printf("\n");
            } else if (mem_info->zone_info_list[i].is_pool == 1) {
                printf("%16luB %16lu %16lfB %16luB %16lu %16lf%%\n",
                        mem_info->zone_info_list[i].pool_detail.base_size,
                        mem_info->zone_info_list[i].pool_detail.elt_count,
                        mem_info->zone_info_list[i].pool_detail.elt_size,
                        mem_info->zone_info_list[i].pool_detail.elt_net_size,
                        mem_info->zone_info_list[i].pool_detail.avail_count,
                        100.0 *
                        mem_info->zone_info_list[i].pool_detail.avail_count /
                        mem_info->zone_info_list[i].pool_detail.elt_count);
            }
        }
    }
    return 0;
}

static int cmd_memory_info(int argc, char *argv[])
{
    int ret = -1, req_len;

    struct cmd_msg msg;
    char buf[ADNS_IO_BUFLEN];
    memset(&msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg.magic = CMD_MSG_MAGIC;
    msg.version = FWD_VERSION;
    msg.opcode = FWD_MEMORY_INFO;
    msg.flags = 0;
    msg.cmd = 0;
    msg.seq = 0;
    msg.req_len = 0;
    msg.rsp_len = 0;
    /* send cmd to remote and wait response */
    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)&msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;
    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg.opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }

    ret = show_memory_info((struct mem_info_t *)reply->data);
    return 0;

exit:
    LOG("MEMORY INFO ERROR!");
    return ret;
}

static int cmd_reload_ip_lib(int argc, char *argv[]) {
    int ret = -1, req_len;

    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    memset(msg, 0, mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->opcode = FWD_SET_IPLIB;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;

    req_len = sizeof(struct cmd_msg);
    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode) {
        LOG("Forward DNS reply error,opcode not match!");
        goto exit;
    }
    if (ret < 0) {
        LOG("Forward DNS reply error,infomation below\n%s\n", reply->data);
        goto exit;
    }

    LOG("Reload ip lib done!\n%s\n", reply->data);

exit:
    free(msg);
    return ret;
}

static int cmd_kni_qpslimit(int argc, char *argv[]) {
    int ret = -1, req_len;

    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    memset(msg, 0, mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(buf, 0, sizeof(buf));
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->opcode = FWD_SET_KNI_QPS_LIMIT_NUM;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;

    /* send cmd to remote and wait response */
    strcat(msg->data, argv[0]);
    if (argv[1]) {
        strcat(msg->data, FWD_DEL_SPLIT);
        strcat(msg->data, argv[1]);
    }
    int dlen = strlen(msg->data) + 1;

    req_len = sizeof(struct cmd_msg) + dlen;

    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode) {
        LOG("Forward DNS reply error,opcode not match!");
        goto exit;
    }
    if (ret < 0) {
        LOG("Forward DNS reply error,infomation below\n%s\n", reply->data);
        goto exit;
    }

    LOG("Forward DNS reply done ! \n%s\n", reply->data);

exit:
    free(msg);
    return ret;
}

static int cmd_reload(int argc, char *argv[])
{
    LOG("exec stats");
    return 0;
}

static int valid_dnscache_op(char *t)
{
    if (t == NULL)
        return -1;
    int i;
    for (i = 0; i < DC_OP_NUM; i++) {
        if (strcasecmp(t, dnscache_op_str[i]) == 0)
            return i;
    }
    return -1;
}

static int read_uint32_t(char *str, uint32_t *val) {
    char *endptr;
    int base = 10;
    errno = 0; /* To distinguish success/failure after call */
    uint32_t max_tll = strtoul(str, &endptr, base);
    /* Check for various possible errors */
    if ((errno == ERANGE && (max_tll == ULONG_MAX))
            || (errno != 0 && max_tll == 0)) {
        return -1;
    }

    *val = max_tll;

    return 0;
}

static int parse_dnscache_data(int argc, char *argv[], uint8_t *buf)
{
    if ( argc < 10 ) {
        return -1;
    }

    int i;
    uint8_t *cur_p = buf;

    /* total */
    uint32_t *total = (uint32_t *)cur_p;
    *total = 1; // only support one zone once
    cur_p += 4;

    /* domain name length */
    uint8_t *domain_len = cur_p++;

    /* domain name */
    int res_len =0;
    uint8_t *dname = dname_str_to_wire(argv[1], strlen(argv[1]), &res_len);
    if (dname == NULL) {
        return -1;
    }
    *domain_len = (uint8_t) res_len;
    memcpy(cur_p, dname, *domain_len);
    free(dname);
    cur_p += *domain_len;

    /* zone id */
    if (read_uint32_t(argv[2], (uint32_t *) cur_p) < 0) {
        return -1;
    }
    cur_p += sizeof(uint32_t);

    /* max ttl */
    if(read_uint32_t(argv[3], (uint32_t *)cur_p) < 0) {
        return -1;
    }
    cur_p += sizeof(uint32_t);

    /* min ttl */
    if(read_uint32_t(argv[4], (uint32_t *)cur_p) < 0) {
        return -1;
    }
    cur_p += sizeof(uint32_t);

    /* queue offset */
    if(read_uint32_t(argv[5], (uint32_t *)cur_p) < 0) {
        return -1;
    }
    cur_p += sizeof(uint32_t);

    /* is support ECS */
    *cur_p = (uint8_t) atoi(argv[6]);
    cur_p++;

    /* status */
    *cur_p = (uint8_t) atoi(argv[7]);
    cur_p++;

    /* source dns ip list lenght */
    *cur_p = (uint8_t) atoi(argv[8]);
    uint8_t ip_len = *cur_p;
    cur_p++;

    /* source dns ip list */
    if( argc < (2 * ip_len + 8)) {
        return -1;
    }

    for (i = 0; i < ip_len; i ++) {
        uint32_t tmp_ip;
        /* ip addr */
        if (inet_pton(AF_INET, argv[9 + 2 *i], (void *)&tmp_ip) != 1) {
            return -1;
        }
        *(uint32_t *)cur_p = ntohl(tmp_ip);
        cur_p += 4;

        /* ip port */
        if (read_uint32_t(argv[9 + 2 *i + 1], (uint32_t *)cur_p) < 0) {
            return -1;
        }
        cur_p += sizeof(uint32_t);
    }

    return cur_p - buf;
}

static int cmd_dnscache(int argc, char *argv[]) {
    int i;

    if (argc <= 0) {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (i = 0; i < DC_OP_NUM; i++) {
            strcat(buf, dnscache_op_str[i]);
            strcat(buf, ",");
        }
        LOG("No operation specified, could be %s", buf);
        return -1;
    }
    int ret = 0, req_len;
    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    int op = valid_dnscache_op(argv[0]);

    if (op < 0) {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (i = 0; i < DC_OP_NUM; i++) {
            strcat(buf, dnscache_op_str[i]);
            strcat(buf, ",");
        }
        LOG("Invalid dnscache operation '%s', operation must be %s", argv[0], buf);
        return -1;
    }

    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;

    printf("op=%d\n", op);
    switch (op) {
    case DC_LIST:
        if (argc > 1 && argv[1] != NULL && !strcasecmp(argv[1], "detail")) {
            msg->opcode = FWD_LIST_DNSCACHE_DETAIL;
        } else {
            msg->opcode = FWD_LIST_DNSCACHE_DOMAIN;
        }
        break;
    case DC_SET:
        msg->opcode = FWD_BATCH_DNSCACHE_SET;
        ret = parse_dnscache_data(argc, argv, (uint8_t *)msg->data);
        if (ret <= 0) {
            LOG("No enough parameters: dnscache set dname zone_id max_tll min_tll queue_offset ECS status iplist_len ip1 port1 ip2 port2 ...");
            goto exit;
        }
        break;
    case DC_UPDATE:
        msg->opcode = FWD_BATCH_DNSCACHE_UPDATE;
        ret = parse_dnscache_data(argc, argv, (uint8_t *)msg->data);
        if (ret <= 0) {
            LOG("No enough parameters: dnscache update zone_id dname max_tll min_tll queue_offset ECS status iplist_len ip1 port1 ip2 port2 ...");
            goto exit;
        }
        break;
    default:
        LOG("Here is impossible!");
        goto exit;
    }

    req_len = sizeof(struct cmd_msg) + ret;
    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }
    if (msg->opcode == FWD_LIST_DNSCACHE_DETAIL) {
        LOG("DNSCACHE DOMAIN LIST DETAIL:");
        printf("%-30s | %-5s | %-5s | %-5s | %-5s | %-5s | %s\n", "domain",
                "zoneid", "maxttl", "minttl", "edns", "serials", "nslist");
        printf("%s", (char*) reply->data);
    } else if (msg->opcode == FWD_LIST_DNSCACHE_DOMAIN) {
        LOG("DNSCACHE DOMAINLIST:");
        printf("%s\n", (char*)reply->data);
    }

exit:
    free(msg);
    return ret;
}

static int valid_snapshot_op(char *t)
{
    if (t == NULL)
        return -1;
    int i;
    for (i = 0; i < DC_OP_NUM; i++) {
        if (strcasecmp(t, snapshot_op_str[i]) == 0)
            return i;
    }
    return -1;
}

static int cmd_snapshot(int argc, char *argv[]) {
    int i;
    if (argc <= 0) {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (i = 0; i < SS_OP_NUM; i++) {
            strcat(buf, snapshot_op_str[i]);
            strcat(buf, ",");
        }
        LOG("No operation specified, could be %s", buf);
        return -1;
    }
    int ret = 0, req_len;
    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    int op = valid_snapshot_op(argv[0]);
    if (op < 0) {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (i = 0; i < SS_OP_NUM; i++) {
            strcat(buf, snapshot_op_str[i]);
            strcat(buf, ",");
        }
        LOG("Invalid snapshot operation '%s', operation must be %s", argv[0], buf);
        return -1;
    }
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;
    switch (op) {
    case SS_EXPORT:
        msg->opcode = FWD_EXPORT_SNAPSHOT;
        break;
    case SS_IMPORT:
        msg->opcode = FWD_IMPORT_SNAPSHOT;
        if (argc != 2) {
            LOG("import error, miss file path");
            return -1;
        }
        strcat(msg->data, argv[1]);
        ret = strlen(msg->data) + 1;
        break;

    }
    req_len = sizeof(struct cmd_msg) + ret;
    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;

    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }
    if(msg->opcode == FWD_EXPORT_SNAPSHOT) {
        // TODO : print dstination file path
        LOG("EXPORT SUCCESS\n");
    } else if(msg->opcode == FWD_IMPORT_SNAPSHOT) {
        // TODO: try to run list
        LOG("IMPORT SUCCESS\n");
    }
exit:
    free(msg);
    return ret;
}


static int valid_queue_offset_op(char *str) {
    if (str == NULL) {
        return -1;
    }
    int i;
    for (i = 0; i < KAFKA_OP_NUM; i++) {
        if (strcasecmp(str, queue_op_str[i]) == 0)
            return i;
    }
    return -1;
}

static int cmd_dnscache_queue_offset(int argc, char *argv[]) {
    int ret = 0, req_len;
    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    char buf[ADNS_IO_BUFLEN];

    if (argc == 1 || argc == 2) {
        memset(msg, 0, sizeof(struct cmd_msg));
        memset(buf, 0, sizeof(buf));
        int op = valid_queue_offset_op(argv[0]);
        if (op < 0) {
            LOG("Operation error, use set [int] or get");
            return -1;
        }
        /* init cmd message */
        msg->magic = CMD_MSG_MAGIC;
        msg->version = FWD_VERSION;
        msg->flags = 0;
        msg->cmd = 0;
        msg->seq = 0;
        msg->req_len = 0;
        msg->rsp_len = 0;
        switch (op) {
            case GET_OFFSET:
                msg->opcode = FWD_GET_DNSCACHE_KAFKA_OFFSET;
                break;
            case SET_OFFSET:
                msg->opcode = FWD_SET_DNSCACHE_KAFKA_OFFSET;
                if (argc != 2) {
                    LOG("KAFKA OP error, miss set number");
                    return -1;
                }
                strcat(msg->data, argv[1]);
                break;
            default:
                LOG("msg queue op error");
                break;
        }
        int dlen = strlen(msg->data) + 1;
        req_len = sizeof(struct cmd_msg) + dlen;
        ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
        if (ret <= 0)
            goto exit;
        struct cmd_msg *reply = (struct cmd_msg *)buf;
        ret = reply->ret_val;
        if (ret < 0) {
            LOG("MSG QUEUE OP ERROR");
        }
        if (msg->opcode == FWD_GET_DNSCACHE_KAFKA_OFFSET) {
            printf("msg queue offset is %u\n", *(unsigned int*)reply->data);
        } else if (msg->opcode == FWD_SET_DNSCACHE_KAFKA_OFFSET) {
            printf("msg queue offset is set to %u\n", *(unsigned int*)reply->data);
        }
    } else {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        LOG("Operation error, use set [int] or get");
        return -1;
    }
exit:
    free(msg);
    return ret;
}

static int valid_user_op(char *t)
{
    if (t == NULL)
        return -1;
    int i;
    for (i = 0; i < USER_OP_NUM; i++) {
        if (strcasecmp(t, user_op_str[i]) == 0)
            return i;
    }
    return -1;
}

static int parse_user_cmd(int argc, char *argv[], uint8_t *buf, int op) {
    int i;
    char ip[100];
    uint8_t *cur_p = buf;
    /* total */
    uint32_t *total = (uint32_t *)cur_p;
    *total = 1; // only support one zone once
    cur_p += 4;

    /* action */
    *cur_p = op;
    cur_p ++;

    /* user id */
    if (read_uint32_t(argv[1], (uint32_t *) cur_p) < 0) {
        return -1;
    }
    cur_p += sizeof(uint32_t);

    /* queue offset */
    if (read_uint32_t(argv[2], (uint32_t *) cur_p) < 0) {
        return -1;
    }
    cur_p += sizeof(uint32_t);

    uint16_t range_num;
    switch (op) {
        case ADD_USER:
			if (argc <= 3) {
				LOG("No enough argument for %s", argv[0]);
				return -1;
			}
            /* status */
            *cur_p = (uint8_t) atoi(argv[3]);
            cur_p++;
            break;
        case DEL_USER:
            break;
        case CHG_USER:
            break;
        case CHG_USER_STATUS:
			if (argc <= 3) {
				LOG("No enough argument for %s", argv[0]);
				return -1;
			}
            /* status */
            if (!strcmp(argv[3], "suspend")) {
                *cur_p = 1;
                cur_p++;
            } else if (!strcmp(argv[3], "serving")) {
                *cur_p = 0;
                cur_p++;
            }
            break;
        case ADD_USER_IP_RANGE:
        case DEL_USER_IP_RANGE:
        case CHG_USER_IP_RANGE:
			if (argc <= 4) {
				LOG("No enough argument for %s", argv[0]);
				return -1;
			}
            /* ip range num */
            range_num = (uint16_t) atoi(argv[3]);
            *cur_p = range_num;
            cur_p += 2;
			if (argc <= (4 + range_num)) {
				LOG("No enough argument for %s", argv[0]);
				return -1;
			}
            for (i = 0; i < range_num; i ++) {
                int family_pos = 4;
                int ip_pos = 5 + i;
                if (!strcmp(argv[family_pos], "ipv4")) {
                    int pos = strcspn(argv[ip_pos], "/");
                    char *mask_ptr;
                    uint8_t mask;
                    uint32_t temp_ip;
                    strcpy(ip, argv[ip_pos]);
                    ip[pos] = 0;
                    mask_ptr = argv[ip_pos] + pos + 1;
                    mask = atoi(mask_ptr);
                    if (inet_pton(AF_INET,ip, (void *)&temp_ip) != 1) {
                        return -1;
                    }
                    /* family */
                    *cur_p = 1;
                    cur_p ++;
                    /* mask */
                    *cur_p = mask;
                    cur_p ++;
                    /* padding1 & padding2 */
                    cur_p += 6;
                    /* ipv4 */
                    int j;
                    *(uint32_t*)cur_p = ntohl(temp_ip);
                    cur_p += 4;
                    for (j = 0; j < 12; j ++) {
                        *cur_p = 0;
                        cur_p ++;
                    }
                } else if (!strcmp(argv[family_pos], "ipv6")) {
                    int pos = strcspn(argv[ip_pos], "/");
                    char *mask_ptr;
                    uint8_t mask;
                    uint8_t temp_ip[16];
                    uint8_t *ip_ptr = temp_ip;
                    strcpy(ip, argv[ip_pos]);
                    ip[pos] = 0;
                    mask_ptr = argv[ip_pos] + pos + 1;
                    mask = atoi(mask_ptr);
                    if (inet_pton(AF_INET6,ip, (void *)ip_ptr) != 1) {
                        return -1;
                    }
                    /* family */
                    *cur_p = 2;
                    cur_p ++;
                    /* mask */
                    *cur_p = mask;
                    cur_p ++;
			    	/* padding1 & padding2 */
				    cur_p += 6;
                    /* ipv6 */
                    int j;
                    for (j = 0; j < 16; j ++) {
                        *cur_p = temp_ip[16-1-j];
                        cur_p ++;
                    }

                } else {
                    return -1;
                }
            }
            break;
        default:
            LOG("Here is impossible!");
            return -1;
    }
    return cur_p - buf;;
}

static int cmd_user_set(int argc, char *argv[]) {
    int i;
    if (argc <= 0) {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (i = 0; i < USER_OP_NUM; i ++) {
            strcat(buf, user_op_str[i]);
            strcat(buf, ",");
        }
        LOG("No operation specified, could be %s", buf);
        return -1;
    }
    int ret = 0, req_len;
    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    char buf[ADNS_IO_BUFLEN];
    memset(msg, 0, sizeof(struct cmd_msg));
    memset(buf, 0, sizeof(buf));
    int op = valid_user_op(argv[0]);
    if (op < 0) {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (i = 0; i < USER_OP_NUM; i++) {
            strcat(buf, user_op_str[i]);
            strcat(buf, ",");
        }
        LOG("Invalid dnscache operation '%s', operation must be %s", argv[0], buf);
        return -1;
    }
    /* init cmd message */
    msg->magic = CMD_MSG_MAGIC;
    msg->version = FWD_VERSION;
    msg->flags = 0;
    msg->cmd = 0;
    msg->seq = 0;
    msg->req_len = 0;
    msg->rsp_len = 0;
    if (op == LIST_USER) {
        msg->opcode = FWD_USER_LIST;
    } else {
        msg->opcode = FWD_USER_BATCH_SET;

		if (argc <= 2) {
			LOG("No enough argument for %s", argv[0]);
			return -1;
		}
        ret = parse_user_cmd(argc, argv, (uint8_t *)msg->data, op);
        if (ret < 0) {
            goto exit;
        }
    }
    req_len = sizeof(struct cmd_msg) + ret;
    ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
    if (ret <= 0)
        goto exit;
    struct cmd_msg *reply = (struct cmd_msg *)buf;
    /* check ret value */
    if (!VALID_CMD_MSG(reply)) {
        LOG("Forward DNS reply unknow data,magic error!");
        goto exit;
    }
    ret = reply->ret_val;
    if (msg->opcode != reply->opcode || ret < 0) {
        LOG("Forward DNS reply error!");
        goto exit;
    }
    if (msg->opcode == FWD_USER_LIST) {
        LOG("USER LIST:");
        printf("%-10s | %-10s | %s\n",
                "user_id", "status", "ip_list");
        printf("%s", (char*) reply->data);
    }
exit:
    free(msg);
    return ret;
}

static int cmd_user_queue_offset(int argc, char *argv[]) {
    int ret = 0, req_len;
    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    char buf[ADNS_IO_BUFLEN];

    if (argc == 1 || argc == 2) {
        memset(msg, 0, sizeof(struct cmd_msg));
        memset(buf, 0, sizeof(buf));
        int op = valid_queue_offset_op(argv[0]);
        if (op < 0) {
            LOG("Operation error, use set [int] or get");
            return -1;
        }
        /* init cmd message */
        msg->magic = CMD_MSG_MAGIC;
        msg->version = FWD_VERSION;
        msg->flags = 0;
        msg->cmd = 0;
        msg->seq = 0;
        msg->req_len = 0;
        msg->rsp_len = 0;
        switch (op) {
            case GET_OFFSET:
                msg->opcode = FWD_GET_USER_QUEUE_OFFSET;
                break;
            case SET_OFFSET:
                msg->opcode = FWD_SET_USER_QUEUE_OFFSET;
                if (argc != 2) {
                    LOG("KAFKA OP error, miss set number");
                    return -1;
                }
                strcat(msg->data, argv[1]);
                break;
            default:
                LOG("msg queue op error");
                break;
        }
        int dlen = strlen(msg->data) + 1;
        req_len = sizeof(struct cmd_msg) + dlen;
        ret = tcp_process((char *)msg, buf, req_len, sizeof(buf));
        if (ret <= 0)
            goto exit;
        struct cmd_msg *reply = (struct cmd_msg *)buf;
        ret = reply->ret_val;
        if (ret < 0) {
            LOG("MSG QUEUE OP ERROR");
        }
        if (msg->opcode == FWD_GET_USER_QUEUE_OFFSET) {
            printf("msg queue offset is %u\n", *(unsigned int*)reply->data);
        } else if (msg->opcode == FWD_SET_USER_QUEUE_OFFSET) {
            printf("msg queue offset is set to %u\n", *(unsigned int*)reply->data);
        }
    } else {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        LOG("Operation error, use set [int] or get");
        return -1;
    }
exit:
    free(msg);
    return ret;
}

static int valid_init_op(char *str) {
    if (str == NULL) {
        return -1;
    }
    int i;
    for (i = 0; i < INIT_OP_NUM; i++) {
        if (strcasecmp(str, init_op_str[i]) == 0)
            return i;
    }
    return -1;
}

static int cmd_init(int argc, char *argv[]) {
    int ret = 0, req_len;
    int mlen = sizeof(struct cmd_msg) + ADNS_IO_BUFLEN;
    struct cmd_msg *msg = malloc(mlen);
    char buf[ADNS_IO_BUFLEN];

    if (argc == 1 || argc == 2) {
        memset(msg, 0, sizeof(struct cmd_msg));
        memset(buf, 0, sizeof(buf));
        int op = valid_init_op(argv[0]);
        if (op < 0) {
            LOG("Operation error, use load <filepath> or show");
            return -1;
        }
        /* init cmd message */
        msg->magic = CMD_MSG_MAGIC;
        msg->version = FWD_VERSION;
        msg->flags = 0;
        msg->cmd = 0;
        msg->seq = 0;
        msg->req_len = 0;
        msg->rsp_len = 0;
        switch (op) {
        case LOAD_DATA:
            msg->opcode = FWD_INIT_LOAD_DATA;
            if (argc != 2) {
                LOG("INIT OP ERROR, miss file path");
                return -1;
            }
            strcat(msg->data, argv[1]);
            break;
        case SHOW_STATUS:
            msg->opcode = FWD_INIT_SHOW_STATUS;
            break;
        default:
            LOG("INIT OP ERROR");
            break;
        }
        int dlen = strlen(msg->data) + 1;
        req_len = sizeof(struct cmd_msg) + dlen;
        ret = tcp_process((char *) msg, buf, req_len, sizeof(buf));
        if (ret <= 0)
            goto exit;
        struct cmd_msg *reply = (struct cmd_msg *) buf;
        ret = reply->ret_val;
        if (ret < 0) {
            LOG("INIT OP ERROR");
        }
        if (msg->opcode == FWD_INIT_SHOW_STATUS) {
            if (*(int*) reply->data) {
                fprintf(stdout, "FWD init done\n");
            } else {
                fprintf(stdout, "FWD init loading\n");
            }
        } else if (msg->opcode == FWD_INIT_LOAD_DATA) {
            if (*(int*)reply->data) {
                fprintf(stdout, "FWD has been initialized\n");
            } else {
                fprintf(stdout, "FWD init loading\n");
            }
        }
    } else {
        char buf[100];
        memset(buf, 0, sizeof(buf));
        LOG("Operation error, use load <filepath> or show");
        return -1;
    }
    exit: free(msg);
    return ret;
}

static void fwdctl_usage(void)
{
    LOG("VERSION:[%s]", FWD_VERSION_STR);
    LOG("================fwdctl usage===================");
    LOG("\t===Show Stats===");
    LOG("\tUsage:fwdctl -s ipaddr -p port stats | cstats | vstats | dstats | pstats | nstats | vstate | dstate | cnts | cpu | version");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 stats (see forward statistics)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 cstats (see cache statistics)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 vstats (see view statistics)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 dstats (see drop statistics)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 pstats (see prefetch statistics)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 nstats (see view nodes statistics)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 vstate (see view health state)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 dstate (see dns health state)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 cnts (see fdns raw counters)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 cpu [live] (see cpu utilization)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 memory (see memory utilization)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 version");
    LOG("\n");

    LOG("\t===Reset Stats===");
    LOG("\tUsage:fwdctl -s ipaddr -p port statsreset");
    LOG("\tDescription:reset all stats counter to initialization");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 statsreset");
    LOG("\n");

    LOG("\t===Set Log Level===");
    LOG("\tUsage:fwdctl -s ipaddr -p port log [type] [level]");
    LOG("\tDescription:type can be:query, answer, server, secure");
    LOG("\tDescription:level can be:info , warn , error , none");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 log query info");
    LOG("\tDescription:This will set query log to info level");
    LOG("\n");

    LOG("\t===Set View's Backup===");
    LOG("\tUsage:fwdctl -s ipaddr -p port backup [view] [backup]");
    LOG("\tDescription:'view' is view's name,'backup' is backup view's name");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 backup chinanet unicom");
    LOG("\tDescription:This will set view chinanet's backup to view unicom");
    LOG("\n");

    LOG("\t===Set View's nodes ttl fetch threshold===");
    LOG("\tUsage:fwdctl -s ipaddr -p port nthreshold count");
    LOG("\tDescription:'view' is view's name,count is to set,default count = 10000");
    LOG("\ttDescription:when lcore nodes < count,all nodes on the lcore will do ttl fetch like topn nodes");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 nthreshold 50000");
    LOG("\tDescription:when the lcore nodes < 50000,all nodes on the lcore will do ttl fetch");
    LOG("\n");

    LOG("\t===Delete keys in batches===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 del batch@stype name1@type1,name2@type2,name3@type3");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 del batch@recu www.alibaba.com@1,www.baidu.com@1,www.qq.com@1 ");
    LOG("\tDescription:This will delete the A record of www.alibaba.com, www.baidu.com and www.qq.com in recursive caches");
    LOG("\tDescription:1 means A in RFC 1035,Lookup RFC for more dns query type");
    LOG("\n");

    LOG("\t===Delete One Key Or All Keys===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 del [stype name type]|[all]");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 del auth www.alibaba.com 1 ");
    LOG("\tDescription:This will delete the A record of www.alibaba.com in authoritative caches");
    LOG("\tDescription:1 means A in RFC,Lookup RFC for more dns query type");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 del all");
    LOG("\tDescription:This will del all keys and all types");
    LOG("\n");

    LOG("\t===Delete keys which match regex===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 delreg viewname:regex");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 delreg default:(.*\\.|^)weibo.com./*");
    LOG("\tDescription:This will delete all keys end with '.weibo.com' (include 'weibo.com./ns') in default view ");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 delreg *:(.*\\.|^)weibo.com./*");
    LOG("\tDescription:This will del all  keys end with '.weibo.com' (include 'weibo.com./ns') in all views");
    LOG("\n");

    LOG("\t===Protect keys which match regex===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 protect_start viewname:regex");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 protect_start default:(.*\\.|^)weibo.com./*");
    LOG("\tDescription:This will make all keys end with '.weibo.com' (include 'weibo.com./ns') in default view get new data from redis only");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 protect_stop");
    LOG("\tDescription:This will make logic return to normal");
    LOG("\n");

    LOG("\t===set kni qps limit===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 kni_qpslimit [other | dot | doh | dohs | ip | fwd] number(must be equal or greater than 0)");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 kni_qpslimit dot 100");
    LOG("\tDescription:This will make set kni qps to 100 for dot packets");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 kni_qpslimit dot 0");
    LOG("\tDescription:This will make cancel the dot kni qps limit controler");
    LOG("\n");

    LOG("\t===get kni qps limit===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 kni_qpslimit show");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 kni_qpslimit show");
    LOG("\tDescription:This will show the kni qps for each type of flow");
    LOG("\n");

    LOG("\t===Set Features status===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 oversea_list on");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 oversea_list off");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 black_list on");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 black_list off");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 white_list on");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 white_list off");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 man_white_list on");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 man_white_list off");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 man_black_list on");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 man_black_list off");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 lcore_share_data on");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 lcore_share_data off");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 reload_iplib");
    LOG("\n");

    LOG("\t===Get Wild Attack status===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 wild_attack");
    LOG("\n");

    LOG("\t===Manage DNS cache data===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 dnscache <set|update> domain_name zone_id max_ttl min_ttl queue_offset support_edns status number IP port...");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 dnscache set alb1.ali-gslb.com 123456 3600 10 1 1 1 2 106.11.30.113 53 140.205.1.2 53");
    LOG("\tDescription:This will refresh the dns cache node configuration");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 dnscache update tmall.com 987654 3600 10 2 0 1 2 140.205.122.34 53 106.11.35.25 53");
    LOG("\tDescription:This will add this dns cache node configuration, update it if it is existing");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 dnscache update tmall.com 456789 3600 10 3 0 0 2 140.205.122.34 53 106.11.35.25 53");
    LOG("\tDescription:This will delete the specified dns cache node configuration");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 dnscache list [detail]");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 list detail");
    LOG("\tDescription:This will show the detail information for each dns cache node");
    LOG("\n");

    LOG("\t===Set/Get message queue offset===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 queue_offset <set|get> [offset]");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 queue_offset get");
    LOG("\tDescription: get message queue offset");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 queue_offset set 1024");
    LOG("\tDescription: set message queue offset to 1024");
    LOG("\n");

    LOG("\t===Manage user information===");
    LOG("\tUsage: fwdctl -s 127.0.0.1 -p 6666 user action user_id offset [status] [range_num ip_ranges]");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 user add_user 10001 1 serving");
    LOG("\tDescription:This will add one user which uid is 10001 and server status is  serving");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 user change_user_status 10001 1 suspend/serving");
    LOG("\tDescription:This will change the server status of 10001 user to suspend");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 user del_user 10001 1");
    LOG("\tDescription:This will delete the 10001 user");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 user add_user_ip_range 10001 1 2 ipv4 1.1.1.0/24 2.2.2.2/32");
    LOG("\tDescription:This will add 2 ip ranges for 10001 user which is 1.1.1.0/24 and 2.2.2.2/32");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 user change_user_ip_range 10001 1 1 ipv4 1.1.1.1/32");
    LOG("\tDescription:This will change the ip range of 10001 user to 1.1.1.1/32");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 user list");
    LOG("\tDescription:This will list all user's information");
    LOG("\n");

    LOG("\t===Set/Get security message queue offset===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 user_queue_offset <set|get> [offset]");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 user_queue_offset get");
    LOG("\tDescription: get message queue offset");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 user_queue_offset set 1024");
    LOG("\tDescription: set message queue offset to 1024");
    LOG("\n");

    LOG("\t===Import/Export snapshot===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 snapshot <import|export>");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 snapshot export");
    LOG("\tDescription: export snapshot to /work/dpdk_fwrd/data/snapshot.data");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 snapshot import /work/dpdk_fwrd/data/snapshot.data");
    LOG("\tDescription: import snapshot from /work/dpdk_fwrd/data/snapshot.data");

    LOG("\t===Operation on initializing stage===");
    LOG("\tUsage:fwdctl -s 127.0.0.1 -p 6666 init <load|show> [filepath]");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 init load /work/dpdk_fwrd/dump/snapshoot.fwd");
    LOG("\tDescription: load data from file");
    LOG("\tE.g fwdctl -s 127.0.0.1 -p 6666 init show");
    LOG("\tDescription: show server init status");

    LOG("\n");
}

adns_cmd_t adns_cmd_tbl[] = {
    {&cmd_stats, 0, "stats", "", "\t\tForward stats."},
	{&cmd_cache_state, 0, "cstats", "", "\t\tCache stats."},
    {&cmd_req_stats, 0, "rstats", "", "\t\tForward request stats."},
    {&cmd_view_stats, 0, "vstats", "", "\t\tForward view stats."},
    {&cmd_drop_stats, 0, "dstats", "", "\t\tForward drop stats."},
    {&cmd_prefetch_stats, 0, "pstats", "", "\t\tForward ttl fetch stats."},
    {&cmd_nodes_stats, 0, "nstats", "", "\t\tForward view nodes stats."},
    {&cmd_view_state, 0, "vstate", "", "\t\tForward view health state."},
    {&cmd_dns_state, 0, "dstate", "", "\t\tForward DNS health state."},
    {&cmd_dns_cnts, 0, "cnts", "", "\t\tForward DNS raw counters."},
    {&cmd_cpu_stats, 0, "cpu", "", "\t\tForward DNS CPU util."},
    {&cmd_memory_info, 0, "memory", "", "\t\tForward DNS memory infomation."},
    {&cmd_view_nodes_ttlfetch_threshold, 0, "nthreshold", "",
     "\t\tForward node fetch view threshold."},
    {&cmd_statsreset, 0, "statsreset", "", "\t\tForward stats reset."},
    {&cmd_set_log, 0, "log", "", "\t\tForward set log level."},
    {&cmd_reload, 0, "reload", "",
     "\t\tReload configuration and changed zones."},
    {&cmd_set_view_backup, 0, "backup", "", "\t\tSet view's backup."},
    {&cmd_del, 0, "del", "", "\t\tDel one key or all keys"},
    {&cmd_delreg, 0, "delreg", "", "\t\tDel one key or all keys match reg"},
    {&cmd_protect_start, 0, "protect_start", "", "\t\tProtect keys match reg"},
    {&cmd_protect_stop, 0, "protect_stop", "",
     "\t\tStop Protect keys match reg"},
    {&cmd_version, 0, "version", "", "\t\tget fdns version"},
    {&cmd_set_oversea_status, 0, "oversea_list", "",
     "\t\tset oversealist status"},
    {&cmd_set_blacklist_status, 0, "black_list", "",
     "\t\tset blacklist status"},
    {&cmd_set_whitelist_status, 0, "white_list", "",
     "\t\tset whitelist status"},
    {&cmd_set_man_whitelist_status, 0, "man_white_list", "",
     "\t\tset man_whitelist status"},
    {&cmd_set_man_blacklist_status, 0, "man_black_list", "",
     "\t\tset man_blacklist status"},
    {&cmd_set_lcoreshare_status,0,"lcore_share_data","","\t\tset lcore data share status"},
    {&cmd_get_wild_attack_status,0,"wild_attack","","\t\tget wild attack status"},
    {&cmd_reload_ip_lib,0,"reload_iplib","","\t\treload ip lib"},
    {&cmd_kni_qpslimit,0,"kni_qpslimit","","\t\tset kni qps limit number"},
    {&cmd_dnscache,0,"dnscache","","\t\tadd，del,list dnscache domain or detail"},
    {&cmd_dnscache_queue_offset,0,"queue_offset","","\t\tset，get,msg queue offset of dnscache"},
    {&cmd_user_set, 0, "user", "", "\t\tset,get user some information"},
    {&cmd_user_queue_offset,0,"user_queue_offset","","\t\tset，get,user queue offset of security"},
    {&cmd_snapshot, 0, "snapshot", "", "\t\timport,export snapshot of fwd's data"},
    {&cmd_init,0,"init","","\t\tOperation on initializing stage"},
    {NULL, 0, NULL, NULL, NULL},
};

int main(int argc, char **argv)
{
    int ret = 0;
    int c, opt_index;

    struct option long_opts[] = {
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {"server", required_argument, 0, 's'},
        {"port", required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "vhs:p:", long_opts, &opt_index)) != -1) {

        switch (c) {
            case 'v':
                LOG("%s, version %s", "ALIDNS", FWD_VERSION_STR);
                goto cleanup;
            case 's':
                server_ip = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'h':
            default:
                fwdctl_usage();
                goto cleanup;
        }
    }

    if (!server_ip || !server_port || argc - optind < 1) {
        fwdctl_usage();
        goto cleanup;
    }

    /* Find requested command. */
    adns_cmd_t *cmd = adns_cmd_tbl;
    while (cmd->name) {
        if (strcmp(cmd->name, argv[optind]) == 0) {
            break;
        }
        ++cmd;
    }

    /* Command not found. */
    if (!cmd->name) {
        LOG("Invalid command: '%s'", argv[optind]);
        ret = -1;
        goto cleanup;
    }

    ret = fwdctl_connect(server_ip, server_port);
    if (ret < 0) {
        return -1;
    }
    /* Execute command. */
    ret = cmd->cb(argc - optind - 1, argv + optind + 1);

cleanup:
    fwdctl_cleanup();

    return ret;
}
