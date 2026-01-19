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
#include <sys/uio.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <rte_config.h>

#include "descriptor.h"
#include "common_value.h"
#include "adns_stats.h"
#include "errcode.h"
#include "view_maps.h"
#include "utili_base.h"
#include "libadns.h"
#include "consts.h"
#include "adns_utili.h"
#include "adns_counter.h"
#include "mem_info.h"
#include "ns_info.h"

static int g_adm_sock_fd = -1;
static const char *g_adm_server_addr = "127.0.0.1";
static const int g_adm_server_port = 5353;
static char g_adm_recv_buf[RECV_BUFSIZE];


char *g_rcode_counter_string[] = {
    [RCODE_NOERROR] = "RCODE_NOERROR:",
    [RCODE_FORMERR] = "RCODE_FORMERR:",
    [RCODE_SERVFAIL] = "RCODE_SERVFAIL:",
    [RCODE_NXDOMAIN] = "RCODE_NXDOMAIN:",
    [RCODE_NOTIMPL] = "RCODE_NOTIMPL:",
    [RCODE_REFUSED] = "RCODE_REFUSED:",
    [RCODE_NOTAUTH] = "RCODE_NOTAUTH:",
    [ADNS_RCODE_COUNTER_MAX] = NULL,
};


char *g_adns_counter_string[] = {
    [IPV4_HEADER_INVALID] = "ipv4 header invalid:",
    [IPV6_HEADER_INVALID] = "ip6 header invalid:",
    [IPV6_EXTHEADER_INVALID] = "ipv6 extra header invalid:",
    [ERROR_PORT] = "package error port:",
    [PACKAGE_BAD_LENGTH] = "package bad length:",
    [PACKAGE_IS_RESPONSE] = "package is response:",
    [PARSE_DNS_WIRE_NULL_FAILED] = "parse dns wire is null failed:",
    [UNSUPPORT_OPCODE] = "unsupport opcode:",
    [PACKAGE_DNS_HEAD_COUNT_FAILED] = "parse dns head count failed:",
    [PACKAGE_EDNS_FORMAT_FAILED] = "parse edns fomat failed:",
    [FILL_DONE_PROCESS_FAILED] = "fill done process failed:",
    [DEFAULT_VIEW_IS_NOT_EXISTED] = "default view is not existed:",
    [VIEW_NAME_IS_NOT_EXISTED] = "view name is not existed:",
    [VIEW_EXCEED_MAX_NUMBER] = "view exceed max number:",
    [ANSWER_WITH_DEFAULT_FAILED] = "answer with default failed:",
    [ANSWER_WITH_NORMAL_FAILED] = "answer with normal failed:",
    [DNSSEC_OVER_QUOTA] = "dnssec query over quota:",
};


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


int socket_init()
{
    int ret;
    struct sockaddr_in addr;
    
    if (g_adm_sock_fd != -1) {
        return ADNS_ADM_SOCKET_BUSY;      
    }

    g_adm_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_adm_sock_fd < 0) {
        return ADNS_ADM_SOCKET_ERROR;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_adm_server_port);
    addr.sin_addr.s_addr = inet_addr(g_adm_server_addr);

    ret = connect(g_adm_sock_fd, (struct sockaddr *) &addr, sizeof(struct sockaddr));
    if (ret < 0) {
        close(g_adm_sock_fd);
        return ADNS_ADM_SOCKET_ERROR;
    }

    return ADNS_ADM_OK;
}


void socket_cleanup()
{
    if (g_adm_sock_fd > -1) {
        close(g_adm_sock_fd);
        g_adm_sock_fd = -1;
    }
}


static int net_send(uint8_t *buf, size_t buf_len)
{
    struct iovec iov[2];

    if (buf == NULL || buf_len == 0) {
        return -1;
    }

    uint32_t pktsize = htonl(buf_len);

    iov[0].iov_base = &pktsize;
    iov[0].iov_len = sizeof(pktsize);
    iov[1].iov_base = (uint8_t *)buf;
    iov[1].iov_len = buf_len;

    ssize_t total = iov[0].iov_len + iov[1].iov_len;

    set_cork_on(g_adm_sock_fd);
    if (writev(g_adm_sock_fd, iov, 2) != total) {
        set_cork_off(g_adm_sock_fd);
        fprintf(stderr, "[%s]: Cannot send query data to remote server\n", __FUNCTION__);
        return -1;
    }
    set_cork_off(g_adm_sock_fd);

    return 0;
}


static int net_receive(char *buf, size_t buf_len)
{
    int ret;
    ssize_t nread;
    struct timeval tv;
    fd_set read_fds;
    uint16_t msg_len = 0;
    uint32_t total = 0;

    if (buf == NULL) {
        return -1;
    }

    tv.tv_sec = 90;
    tv.tv_usec = 0;

    while (total < sizeof(msg_len)) {
        FD_ZERO(&read_fds);
        FD_SET(g_adm_sock_fd, &read_fds);
        
        ret = select(g_adm_sock_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            fprintf(stderr, "[%s]: Received error\n", __FUNCTION__);
            return -1;
        }

        if (!FD_ISSET(g_adm_sock_fd, &read_fds)) {
            fprintf(stderr, "[%s]: Read response timeout\n", __FUNCTION__);
            return -1;
        }

        nread = recv(g_adm_sock_fd, (uint8_t *)&msg_len + total, 
                sizeof(msg_len) - total, 0);
        if (nread <= 0) {
            fprintf(stderr, "[%s]: Cannot receive reply on socket %d\n", __FUNCTION__, g_adm_sock_fd);
            return -1;
        }

        total += nread;
    }

    msg_len = ntohs(msg_len);
    if (msg_len > buf_len) {
        fprintf(stderr, "[%s]: Cannot receive reply: mesg lenth = %d larger than buf_len = %zu\n", __FUNCTION__, msg_len, buf_len);
        return -1;
    }
    total = 0;

    while (total < msg_len) {
        FD_ZERO(&read_fds);
        FD_SET(g_adm_sock_fd, &read_fds);
        
        ret = select(g_adm_sock_fd+1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            fprintf(stderr, "[%s]: Received error\n", __FUNCTION__);
            return -1;
        }

        if (!FD_ISSET(g_adm_sock_fd, &read_fds)) {
            fprintf(stderr, "[%s]: Read response timeout\n", __FUNCTION__);
            return -1;
        }

        nread = recv(g_adm_sock_fd, buf + total, msg_len - total, 0);
        if (nread <= 0) {
            fprintf(stderr, "[%s]: Cannot receive reply on socket %d\n", __FUNCTION__, g_adm_sock_fd);
            return -1;
        }

        total += nread;
    }

    return total;
}


static int net_process(uint8_t *send_buf, size_t send_len, char *g_adm_recv_buf, size_t recv_len)
{
    int n = 0;
    int tries = 3;

    for (; tries > 0; --tries) {
        n = net_send(send_buf, send_len);
        if (n < 0) {
            continue;
        }
        
        n = net_receive(g_adm_recv_buf, recv_len);
        if (n > 0) {
            break;
        }
    }

    if (n <= 0) {
        fprintf(stderr, "[%s]: Failed to process command\n", __FUNCTION__);
        return -1;
    }

    return n;
}


int adns_add_zone(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to add zone, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_del_zone(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to del zone, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_set_cname_cascade(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to set cname cascade, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_set_wildcard_fallback(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to set wildcard fallback, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_set_dnssec(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to set dnssec, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_add_key(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to add key, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_del_zsk(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to del ZSK, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_add_dnskey_rrsig(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to add dnskey rrsig, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_dnssec_quota(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to set DNSSEC quota, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    fprintf(stdout, "%s", cmd_resp->err_msg);
    return 0;
}

int adns_dnssec_cache(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to operate DNSSEC cache, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    fprintf(stdout, "%s", cmd_resp->err_msg);
    return 0;
}


int adns_edit_zone(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to edit zone, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_list_zone(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;
    char *zone_str;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s], Failed to list zone, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    zone_str = (char *)(cmd_resp + 1);
    fprintf(stderr, "%s\n", zone_str);

    return 0;
}


int adns_add_rr(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;
    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to add rr, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_edit_rr(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;
    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to edit rr, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_del_rr(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to del rr, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_del_domain(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to del domain, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_list_dname(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;
    char *str;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to list dname, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    /* parse list domain rrset */
    str = g_adm_recv_buf + sizeof(struct cmd_resp);
    fprintf(stdout, "%s\n", str);

    return 0;
}


int adns_list_schedule(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;
    char *str;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to list dname, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    /* parse list domain rrset */
    str = g_adm_recv_buf + sizeof(struct cmd_resp);
    fprintf(stdout, "%s\n", str);

    return 0;
}


int adns_schedule_mode(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    /* check schedule mode value */
    if (ce->rclass > SCHEDULE_MODE_UNKNOWN) {
        fprintf(stderr, "[%s]: Failed to set schedule mode, invalid schedule mode %u\n", __FUNCTION__, ce->rclass);
        return ADNS_ADM_ERROR;
    }

    /* check rrset type */
    if (ce->type != ADNS_RRTYPE_A && ce->type != ADNS_RRTYPE_AAAA) {
        fprintf(stderr, "[%s]: Failed to set schedule mode, only A or AAAA is allowed to set schedule mode\n", __FUNCTION__);
        return ADNS_ADM_ERROR;
    }

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to set schedule mode, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_list_qps(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;
    char *str;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to list qps, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    /* parse list domain rrset */
    str = g_adm_recv_buf + sizeof(struct cmd_resp);
    fprintf(stdout, "%s\n", str);

    return 0;
}

int adns_init_load(uint8_t *batch_cmd_buff, int buff_len)
{
    int ret;
    struct cmd_resp *cmd_resp = NULL;
    char * error_collected = NULL;

    ret = net_process(batch_cmd_buff, buff_len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0){
        return ret;
     }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        error_collected = (char *)(cmd_resp + 1);
        fprintf(stdout, "[%s]: error collected: \n%s\n", __FUNCTION__, error_collected);
        return ret;
    }


    int done = cmd_resp->init_done;
    if (done) {
        //fprintf(stderr, "Adns has inited done\n");
    } else {
        fprintf(stdout, "Adns init loading\n");
    }
    fflush(stdout);

    return 0;
}


int adns_batch_process(uint8_t *batch_cmd_buff, int buff_len)
{
    int ret;
    struct cmd_resp *cmd_resp;

    ret = net_process(batch_cmd_buff, buff_len, g_adm_recv_buf, RECV_BUFSIZE);

    if (ret < 0){
        return ret;
    }
    
    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to batch process, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_dump(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to dump, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_clear(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to clear, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_info_get(struct adns_command_entry *ce, struct adns_info **info)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to adns_info_get, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    *info = (struct adns_info *)(cmd_resp + 1);

    return 0;
}


int adns_show(struct adns_command_entry *ce)
{
    int ret;
    struct adns_info *info;

    ret = adns_info_get(ce, &info);    
    if (ret < 0) {
        fprintf(stderr, "[%s]: Cannot get adns statistics\n", __FUNCTION__);
        return ret;
    }

    fprintf(stdout, "Adns info:              number          cordon(Percentage)\n");
    fprintf(stdout, 
      "    zone:                    %-18d%lf\n"
      "    private_route_zone:      %-18d%lf\n"
      "    dnssec_zone:             %-18d%lf\n"
      "    dnssec_cache:            %-18d%lf\n"
      "    domain:                  %-18d%lf\n"
      "    rr:                      %-18d%lf\n"
      "        -A:                  %-18d%lf\n"
      "        -AAAA:               %-18d%lf\n"
      "        -NS:                 %-18d%lf\n"
      "        -CNAME:              %-18d%lf\n"
      "        -MX:                 %-18d%lf\n"
      "        -PTR:                %-18d%lf\n"
      "        -TXT:                %-18d%lf\n"
      "        -SRV:                %-18d%lf\n"
      "        -CAA:                %-18d%lf\n"
      "        -RRSIG:              %-18d%lf\n"

      "    rdata_ctl_num:           %-18d%lf\n"
      "    private_rdata_ctl_num:   %-18d%lf\n"
      "    rrset_memory_num:        %-18d%lf\n"
      "    zone_name_32:            %-18d%lf\n"
      "    zone_name_64:            %-18d%lf\n"
      "    zone_name_128:           %-18d%lf\n"
      "    zone_name_256:           %-18d%lf\n"
      "    domain_name_32:          %-18d%lf\n"
      "    domain_name_64:          %-18d%lf\n"
      "    domain_name_128:         %-18d%lf\n"
      "    domain_name_256:         %-18d%lf\n",
            info->zone_num, (info->zone_max_num) ? (double)info->zone_num * 100.0/(double)info->zone_max_num : 0,
            info->private_route_zone_num, (info->private_route_zone_max_num) ? (double)info->private_route_zone_num * 100.0/(double)info->private_route_zone_max_num : 0,
            info->dnssec_zone_num, (info->dnssec_zone_max_num) ? (double)info->dnssec_zone_num * 100.0/(double)info->dnssec_zone_max_num : 0,
            info->dnssec_cache_num, (info->dnssec_cache_max_num) ? (double)info->dnssec_cache_num * 100.0/(double)info->dnssec_cache_max_num : 0,
            info->domain_num, (info->domain_max_num) ? (double)info->domain_num * 100.0/(double)info->domain_max_num : 0,
            info->rr_num, (info->rr_max_num) ? (double)info->rr_num * 100.0/(double)info->rr_max_num : 0,

            info->rr_detail_num.A_num, (info->rr_num) ? (double)info->rr_detail_num.A_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.AAAA_num, (info->rr_num) ? (double)info->rr_detail_num.AAAA_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.NS_num, (info->rr_num) ? (double)info->rr_detail_num.NS_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.CNAME_num, (info->rr_num) ? (double)info->rr_detail_num.CNAME_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.MX_num, (info->rr_num) ? (double)info->rr_detail_num.MX_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.PTR_num, (info->rr_num) ? (double)info->rr_detail_num.PTR_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.TXT_num, (info->rr_num) ? (double)info->rr_detail_num.TXT_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.SRV_num, (info->rr_num) ? (double)info->rr_detail_num.SRV_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.CAA_num, (info->rr_num) ? (double)info->rr_detail_num.CAA_num * 100.0/(double)info->rr_max_num : 0,
            info->rr_detail_num.RRSIG_num, (info->rr_num) ? (double)info->rr_detail_num.RRSIG_num * 100.0/(double)info->rr_max_num : 0,

            info->rdata_ctl_num, (info->rdata_ctl_max_num) ? (double)info->rdata_ctl_num * 100.0/(double)info->rdata_ctl_max_num : 0,
            info->private_rdata_ctl_num, (info->private_rdata_ctl_max_num) ? (double)info->private_rdata_ctl_num * 100.0/(double)info->private_rdata_ctl_max_num : 0,
            info->rrset_memory_num, (info->rrset_memory_max_num) ? (double)info->rrset_memory_num * 100.0/(double)info->rrset_memory_max_num : 0,
            info->zone_name_used_num[0], (info->zone_name_max_num[0]) ? (double)info->zone_name_used_num[0] * 100.0/(double)info->zone_name_max_num[0] : 0,
            info->zone_name_used_num[1], (info->zone_name_max_num[1]) ? (double)info->zone_name_used_num[1] * 100.0/(double)info->zone_name_max_num[1] : 0,
            info->zone_name_used_num[2], (info->zone_name_max_num[2]) ? (double)info->zone_name_used_num[2] * 100.0/(double)info->zone_name_max_num[2] : 0,
            info->zone_name_used_num[3], (info->zone_name_max_num[3]) ? (double)info->zone_name_used_num[3] * 100.0/(double)info->zone_name_max_num[3] : 0,
            info->domain_name_used_num[0], (info->domain_name_max_num[0]) ? (double)info->domain_name_used_num[0] * 100.0/(double)info->domain_name_max_num[0] : 0,
            info->domain_name_used_num[1], (info->domain_name_max_num[1]) ? (double)info->domain_name_used_num[1] * 100.0/(double)info->domain_name_max_num[1] : 0,
            info->domain_name_used_num[2], (info->domain_name_max_num[2]) ? (double)info->domain_name_used_num[2] * 100.0/(double)info->domain_name_max_num[2] : 0,
            info->domain_name_used_num[3], (info->domain_name_max_num[3]) ? (double)info->domain_name_used_num[3] * 100.0/(double)info->domain_name_max_num[3] : 0
            );
    return 0;
}

int adns_dpdk_heap_get(struct adns_command_entry *ce, struct adns_malloc_socket_stats **stats)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to get adns status, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    *stats = (struct adns_malloc_socket_stats *)(cmd_resp + 1);

    return 0;
}

int adns_show_dpdk_heap(struct adns_command_entry *ce)
{
    int ret, socket;
    struct adns_malloc_socket_stats *stats;

    ret = adns_dpdk_heap_get(ce, &stats);
    if(ret < 0){
        fprintf(stderr, "[%s]: adns_show_dpdk_heap failed\n", __FUNCTION__);
        return ret;
    }

    for(socket = 0; socket < 2; socket++){
        if (stats[socket].heap_totalsz_bytes == 0) {
            continue;
        }

        fprintf(stdout, "---------DPDK HEAP MEMORY, SOCKET[%d]:---------\n", socket);
        fprintf(stdout, 
        "Heap_size:%zu\n"
        "Free_size:%zu\n"
		"Alloc_size:%zu\n"
		"Greatest_free_size:%zu\n"
		"Alloc_count:%u\n"
		"Free_count:%u\n", stats[socket].heap_totalsz_bytes, stats[socket].heap_freesz_bytes, stats[socket].heap_allocsz_bytes, stats[socket].greatest_free_size, stats[socket].alloc_count, stats[socket].free_count);
    }

    return 0;
}

int adns_status(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to get adns status, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    int done = cmd_resp->init_done;
    if (done) {
        fprintf(stdout, "Adns init done\n");
    } else {
        fprintf(stdout, "Adns init loading\n");
    }
    fflush(stderr);

    return 0;
}


int adns_stats(struct adns_command_entry *ce, struct adns_stats **st)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to adns_stats, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    *st = (struct adns_stats *)(cmd_resp + 1);

    return 0;
}


int adns_list_stats(struct adns_command_entry *ce)
{
    int ret;
    struct adns_stats *st;

    ret = adns_stats(ce, &st);
    if (ret < 0) {
        fprintf(stderr, "[%s]: Cannot get adns statistics\n", __FUNCTION__);
        return ret;
    }

    fprintf(stdout, "Adns statistics:\n");
    fprintf(stdout, 
      "    qps:              %lu\n"
      "    query:            %lu\n"    /* UDP destination port is 53 */
      "    answer:           %lu\n"
      "    edns:             %lu\n"
      "    badvers:          %lu\n"    /* query with EDNS BADVERSION */
      "    unknown-opt:      %lu\n"    /* query with EDNS unknown option */
      "    dnssec:           %lu\n"    /* DNSSEC query */
      "    dnssec_ans:       %lu\n"    /* DMSSEC response */
      "    dnssec_rps:       %lu\n"    /* DNSSEC RPS */
      "    dnssec_cache:     %lu\n"    /* DNSSEC cache hit total count */
      "    dnssec_cache_qps: %lu\n"    /* DNSSEC cache hit qps */
      "    ecs:              %lu\n"
      "    cookie:           %lu\n"    /* query with cookie statitics */
      "    kni:              %lu\n"
      "    drop:             %lu\n"
      "    ipv4:             %lu\n"    /* Should be the sum of answer + all drop counters + kni */
      "    ipv6:             %lu\n"    /* Should be the sum of answer + all drop counters + kni */
      "    fragment_out:     %lu\n"
      "    tcp_in:           %lu\n"
      "    tcp_in_53:        %lu\n"
      "    tcp_in_53_drop:   %lu\n"
      "    write_server_log_fail: %lu\n"
      "    write_query_log_fail: %lu\n"
      "    write_answer_log_fail: %lu\n"
      "    write_query_statis_log_fail: %lu\n"
      "    rcu_qps: %lu\n"
      "    dnssec_cache_new_err: %lu\n"
      "    dnssec_cache_expire: %lu\n"
      "    dnssec_cache_msg_send_err: %lu\n",
      st->qps, st->query, st->answer, st->edns, st->edns_badvers, st->edns_unknown_opt, st->dnssec, st->dnssec_ans, 
      st->dnssec_qps, st->dnssec_cache_hit, st->dnssec_cache_qps, st->ecs, st->cookie, st->kni, st->drop, st->ipv4, st->ipv6,
      st->fragment_out, st->tcp_in, st->tcp_in_53, st->tcp_in_53_drop, 
      st->log_server_fail, st->log_query_fail,
      st->log_answer_fail, st->log_query_statis_fail,
      st->rcu_qps, st->dnssec_cache_new_err, st->dnssec_cache_expire, st->dnssec_cache_msg_send_err);
      
    return 0;
}


int adns_counter_info(struct adns_command_entry *ce, uint64_t **value)               
{   
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        return ret;
    }

    *value = (uint64_t *)(cmd_resp + 1);

    return 0;
}


char *rcode_counter_id_to_name(int id)
{
    if (id >= ADNS_RCODE_COUNTER_MAX) {
        return "This counter id is not support by adns\n";
    }

    return g_rcode_counter_string[id];
}


int adns_rcode_stats(struct adns_command_entry *ce)
{
    int ret, i;
    uint64_t *counter;

    ret = adns_counter_info(ce, &counter);
    if (ret < 0) {
        fprintf(stderr, "[%s]: Cannot get the adns rcode counter\n", __FUNCTION__);
        return ret;
    }

    for(i = 0; i < ADNS_RCODE_COUNTER_MAX; i++){
        if (rcode_counter_id_to_name(i) == NULL) {
            continue;
        }

        fprintf(stdout, "%-26s  %lu\n", rcode_counter_id_to_name(i), counter[i]);
    }

    return 0;
}


int adns_dpdk_port_info(struct adns_command_entry *ce, adns_dpdk_port_stats_t **value)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        return ret;
    }

    *value = (adns_dpdk_port_stats_t *)(cmd_resp + 1);
    return 0;
}


/* TODO: adns_adm can't obtain ADNS runtime variables like port_nums */
int adns_dpdk_port_stats(struct adns_command_entry *ce)
{
    int ret, i, j;
    adns_dpdk_port_stats_t *stats;
    
    ret = adns_dpdk_port_info(ce, &stats);
    if(ret < 0){
        fprintf(stderr, "[%s]: adns_dpdk_port_info get failed\n", __FUNCTION__);
        return ret;
    }

    for(i = 0; i < 2;  i++){
        fprintf(stdout, "---------DPDK PORT STATISTICS, PORT[%d]:---------\n", i);
        fprintf(stdout,
                "RX-packets:  %lu\n"
                "RX-errors:   %lu\n"
                "RX-imcasts:  %lu\n"
                "RX-bytes:    %lu\n"
                "RX-nombuf:   %lu\n"
                "TX-packets:  %lu, TX-errors: %lu, TX-bytes: %lu\n\n",
                stats[i].ipackets, stats[i].ierrors, stats[i].imcasts, stats[i].ibytes,
                stats[i].rx_nombuf, stats[i].opackets, stats[i].oerrors, stats[i].obytes);
    }

    for(i = 0; i < 2; i++){
        fprintf(stdout, "------------PACKAGE QUEUE RECEIVE STATISTICS, PORT[%d]------------\n", i);
        for(j = 0; j < RTE_ETHDEV_QUEUE_STAT_CNTRS; j++){
            fprintf(stdout, "RX-receive-queue[%2d]: %lu  ", j, stats[i].q_ipackets[j]);
            
            if ((j+1) % 4 == 0){
                fprintf(stdout, "\n");
            }
        }
    } 
    fprintf(stdout, "\n"); 

    for(i = 0; i < 2; i++){
        fprintf(stdout, "------------PACKAGE QUEUE DROP STATISTICS, PORT[%d]------------\n", i);
        for(j = 0; j < RTE_ETHDEV_QUEUE_STAT_CNTRS; j++){
            fprintf(stdout, "RX-drop-queue[%2d]: %lu  ", j, stats[i].q_errors[j]);
            
            if ((j+1) % 4 == 0){
                fprintf(stdout, "\n");
            }
        }
    }  
    fprintf(stdout, "\n");

    for(i = 0; i < 2; i++){
        fprintf(stdout, "------------PACKAGE QUEUE SEND STATISTICS, PORT[%d]------------\n", i);
        for(j = 0; j < RTE_ETHDEV_QUEUE_STAT_CNTRS; j++){
            fprintf(stdout, "TX-send-queue[%2d]: %lu  ", j, stats[i].q_opackets[j]);
            
            if ((j+1) % 4 == 0){
                fprintf(stdout, "\n");
            }
        }
    }

    return 0;
}


char *counter_id_to_name(int id)
{
    if (id >= ADNS_PKT_DROP_COUNTER_MAX) {
        return "this counter id is not support by adns\n";
    }   
    return g_adns_counter_string[id];
}


int adns_counter(struct adns_command_entry *ce)
{
    int ret, i;
    uint64_t *counter;

    ret = adns_counter_info(ce, &counter);
    if (ret < 0) {
        fprintf(stderr, "[%s]: Cannot get the adns counter\n", __FUNCTION__);
        return ret;
    }

    for (i = 0; i < ADNS_PKT_DROP_COUNTER_MAX; i++){
        fprintf(stdout, "%-30s  %lu\n", counter_id_to_name(i), counter[i]);
    }

    return 0;
}


int adns_utili(struct adns_command_entry *ce, struct adns_utili **ut)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to adns_utili, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    *ut = (struct adns_utili *)(cmd_resp + 1);

    return 0;
}


int adns_list_utili(struct adns_command_entry *ce)
{
    int i, ret;
    struct adns_utili *ut;

    ret = adns_utili(ce, &ut);
    if (ret < 0) {
        fprintf(stderr, "[%s]: Cannot get adns utilization\n", __FUNCTION__);
        return ret;
    }

    fprintf(stdout, "Adns CPU utilizations:\n");
    for (i = 0; i < ut->cpu_num; i++) {
        fprintf(stdout, "    cpu[%d]: %.2f\n", ut->cpu[i].lcore, ut->cpu[i].usage);
    }
    
    return 0;
}


int adns_reload_iplib(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to reload iplib, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_reload_vm(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to reload view map, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_reload_nslist(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret) {
        fprintf(stderr, "[%s]: Failed to reload common NS list, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}


int adns_ip2view(struct adns_command_entry *ce, int adm_view_nums, struct adns_view_map *adm_view_maps)
{
    int i, ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stdout, "adns_adm not support the cmd\n");
        return ret;
    }

    for (i = 0; i < adm_view_nums; ++i) {
        if (adm_view_maps[i].id == cmd_resp->init_done) {
            fprintf(stdout, "the ip at the view of : %s\n\n", adm_view_maps[i].name);
            return 0;
        }
    }
    
    fprintf(stdout, "[%s]: the ip fail to find view \n\n", __FUNCTION__);
    return 0;
}

int adns_lookup(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to lookup, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    fprintf(stdout, "%s\n", cmd_resp->err_msg);

    return 0;
}

int adns_quota(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to config quota, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    fprintf(stdout, "%s\n", cmd_resp->err_msg);

    return 0;
}



int adns_log(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to adns_log, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    fprintf(stdout, "%s\n", cmd_resp->err_msg);
    return 0;
}

int adns_53(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to adns_53, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    fprintf(stdout, "%s\n", cmd_resp->err_msg);
    return 0;
}

int adns_syslog(struct adns_command_entry *ce)
{
    int ret, len, i;
    struct cmd_resp *cmd_resp;
    struct adns_utili *sta_nodes;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to config syslog, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    switch (ce->rclass) {
        case ADNS_SYSLOG_IP:
            break;
        case ADNS_SYSLOG_SHOW:
            sta_nodes = (struct adns_utili *)(cmd_resp + 1);
            fprintf(stdout, "Query Sta Nodes on IO Cores:\n");
            for (i = 0; i < sta_nodes->cpu_num; i++) {
                fprintf(stdout, "    cpu[%d]: %.0f\n", sta_nodes->cpu[i].lcore,
                        sta_nodes->cpu[i].usage);
            }
            break;
        default:
            break;
    }
    fprintf(stdout, "%s\n", cmd_resp->err_msg);
    return 0;
}

static inline double byte_to_gigabyte(const uint64_t byte_num) {

    return byte_num * 1.0 / 1024 / 1024 / 1024;
}

int show_memory_info(struct mem_info_t *mem_info) {
    printf("-----------------------------------------------------------------MEMORY INFO------------------------------------------------------------------\n" \
           "ZONE COUNT:     %16lu \n" \
           "TOTAL USED:    %16lfG%16lf%%\n", \
           mem_info->count,
           byte_to_gigabyte(mem_info->used), mem_info->used * 100.0 / mem_info->total);
    int i = 0 ;
    for(i = 0; i < RTE_MAX_NUMA_NODES; i++) {
        if(mem_info->used_per_socket[i] != 0) {
            printf("SOCKET%d USED:  %16lfG%16lf%%\n",
                    i, byte_to_gigabyte(mem_info->used_per_socket[i]), \
                    mem_info->used_per_socket[i] * 100.0 / mem_info->total_per_socket[i]
                  );
        }
    }
    printf("\nZONE_NAME                           [ ZONE_LENGTH   =  COMMON_BASE +      OBJ_COUNT *        OBJ_SIZE ]"\
            "    OBJ_PAY_LOAD      AVAIL_COUNT         AVAIL_PER\n");
    for (i = 0; i < RTE_MAX_MEMZONE; i++) {
        if(mem_info->zone_info_list[i].name[0] != 0) {
            printf("%-32s%16lfG", \
                    mem_info->zone_info_list[i].name, \
                    byte_to_gigabyte(mem_info->zone_info_list[i].len) );
            if(mem_info->zone_info_list[i].is_pool == 0){
                printf("\n");
            }
            else if(mem_info->zone_info_list[i].is_pool == 1) {
                printf("%16luB %16lu %16lfB %16luB %16lu %16lf%%\n", \
                        mem_info->zone_info_list[i].pool_detail.base_size, \
                        mem_info->zone_info_list[i].pool_detail.elt_count, \
                        mem_info->zone_info_list[i].pool_detail.elt_size, \
                        mem_info->zone_info_list[i].pool_detail.elt_net_size, \
                        mem_info->zone_info_list[i].pool_detail.avail_count, \
                        100.0 * mem_info->zone_info_list[i].pool_detail.avail_count / mem_info->zone_info_list[i].pool_detail.elt_count
                      );
            }
        }
    }
   return 0;
}
int adns_memory_info(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;
    struct mem_info_t *p_mem_info;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to config syslog, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }

    p_mem_info = (struct mem_info_t *)(cmd_resp + 1);

    show_memory_info(p_mem_info);

    return 0;
}

void show_nslist_info(struct adns_ns_group_info *p_ns_group_info, uint32_t ns_group_num)
{
    uint32_t i, j;
    printf("\nNS_GROUP_ID    REF_COUNT       NS_NAME\n");

    for (i = 0; i < ns_group_num; i ++) {
        for (j = 0; j < p_ns_group_info[i].ns_count; j ++) {
            if (j == 0) {
                printf("%-16u%-16u%s", p_ns_group_info[i].group_id, p_ns_group_info[i].ref_count, (char *)(p_ns_group_info[i].ns[j]));
            } else {
                printf(" %s", (char *)(p_ns_group_info[i].ns[j]));
            }

            if (j == p_ns_group_info[i].ns_count - 1) {
                printf("\n");
            }
        }
    }

}

int adns_nslist_info(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;
    struct adns_ns_group_info *p_ns_group_info;
    uint32_t *p_ns_group_count;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to show default NS list info, err_msg %s\n", __FUNCTION__, cmd_resp->err_msg);
        return ret;
    }


    p_ns_group_count = (uint32_t *)(cmd_resp + 1);
    p_ns_group_info = (struct adns_ns_group_info *)(p_ns_group_count + 1);

    show_nslist_info(p_ns_group_info, *p_ns_group_count);

    return 0;
}


int adns_add_reload_route(uint8_t *route_cmd_buff, int buff_len)
{
    int ret;
    struct cmd_resp *cmd_resp;
    struct adns_command_entry *ce;

    ce = (struct adns_command_entry *)route_cmd_buff;

    ret = net_process(route_cmd_buff, buff_len, g_adm_recv_buf, RECV_BUFSIZE);

    if (ret < 0){
        return ret;
    }
    
    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to %s route for zone '%s', err_msg: %s",
                         __FUNCTION__, 
                         ce->cmd == CMD_ADDROUTE? "add" : "reload",
                         ce->zone, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_del_route(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    cmd_resp = (struct cmd_resp *)(g_adm_recv_buf);
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Fail to delete private route for zone '%s', err_msg %s\n", __FUNCTION__, ce->zone, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_dump_route(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to dump private route for zone '%s', err_msg %s\n", __FUNCTION__, ce->zone, cmd_resp->err_msg);
        return ret;
    }

    return 0;
}

int adns_exit_app(struct adns_command_entry *ce)
{
    int ret, len;
    struct cmd_resp *cmd_resp;

    len = CMD_ENTRY_LEN(ce);
    ret = net_process((uint8_t *)ce, len, g_adm_recv_buf, RECV_BUFSIZE);
    if (ret < 0) {
        return ret;
    }

    /* check return value */
    cmd_resp = (struct cmd_resp *)g_adm_recv_buf;
    ret = cmd_resp->ret_val;
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to quit the running ADNS\n", __FUNCTION__);
        return ret;
    }

    fprintf(stdout, "Quit the running ADNS\n");
    return 0;
}
