/*
 * Copyright (C)
 * Filename: manage.c
 * Author:
 * mogu <mogu.lwp@alibaba-inc.com>
 * Description:
 */

#include <linux/ctype.h>

#include "manage.h"
#include "util.h"
#include "dns.h"
#include "cache.h"
#include "lock.h"
#include "qpslimit.h"

static struct cache_info cinfo;
static int info_len;
static uint32_t limitip_len = 0;
static char limitip[100];

static int is_pointer(int in)
{
    return ((in & 0xc0) == 0xc0);
}

/* get domain name in DNS packets
 * @dnshdr: DNS header pointer
 * @p: the start pointer of query or answer in DNS header
 * @out: the domain name from p
 * @len: the lenth of domain name
 */
void get_domain_name(struct dm_dnshdr *dnshdr, int maxlen, char **p, char *out, int *len)
{
    /*
     * domain in cache will like this:
     * www.alipay.com:3www5alipay3com0
     */
    int number, flag, steps;
    int i;
    char *pos = out, *pnext;
    *len = 0;
    flag = 0;
    steps = 0;
    pnext = NULL;
    while (1) {
        steps ++;
        number = (*p)[0];
        if (steps > maxlen || number + *len > 255) {
            /* if number is invalid,just set out string NULL */
            *len = 0;
            memset(out, 0, sizeof(out));
            return;
        }
        if (number == 0) {
            memcpy(pos, "\0", 1);
            (*p) ++;
            break;
        }
        if (is_pointer(number)) {
            if (flag == 0) pnext = (*p) + 2;
            *p = (char *)dnshdr + ((*p)[1] & 0xff) + ((number & 0x3f) << 8);
            flag = 1;
        } else {
            (*p)++;
            memcpy(pos, (*p), number);
            for (i = 0; i < number; i ++) {
                pos[i] = *(*p+i);
            }
            pos += number;
            (*p) += number;
            *len += number + 1;
            *pos = '.';
            pos += 1;
        }
    }
    if (flag) *p = pnext;
}

static void info_init(void)
{
    cinfo.rr_num = 0;
    cinfo.ctime = 0;
    cinfo.protect = 0;
}

/*
 * show all node_t infomations
 */
static void get_cache_info(const struct node_t *n)
{
    struct dm_dnshdr *dnshdr;
    struct dm_dnsans *dnsans;
    int ansnum, dns_len, i;
    char ip[20];
    info_init();
    dnshdr = (struct dm_dnshdr *)n->val->buf;
    dns_len = n->val->len;
    dnsans = (struct dm_dnsans*)kmalloc(sizeof(struct dm_dnsans)*25, GFP_ATOMIC);
    if (dnsans == NULL) {
        cinfo.ctime = (jiffies - n->ctime) / HZ;
        cinfo.mtime = (jiffies - n->cached_jiffies) / HZ;
        cinfo.protect = n->protect;
        info_len = sizeof(struct cache_info);
        return;
    }
    parse_dns_message(dnshdr, dns_len, NULL, dnsans, &ansnum);
    cinfo.rr_num= ansnum;
    for (i = 0; i < ansnum; i ++) {
        cinfo.rr[i].ttl = dnsans[i].ttl;
        strcpy(cinfo.rr[i].query, dnsans[i].query);
        if (dnsans[i].type == RR_TYPE_ANAME) {
            memcpy(ip, dnsans[i].data.ip, 4);
            sprintf(cinfo.rr[i].answer, "%u.%u.%u.%u", ip[0] & 0xff,
                    ip[1] & 0xff, ip[2] & 0xff, ip[3] & 0xff);
            strcpy(cinfo.rr[i].type, "A");
        } else if (dnsans[i].type == RR_TYPE_CNAME) {
            memset(cinfo.rr[i].answer, 0, sizeof(cinfo.rr[i].answer));
            strcpy(cinfo.rr[i].answer, dnsans[i].data.name);
            strcpy(cinfo.rr[i].type, "CNAME");
        } else {
            //TODO: other type
        }
    }
    kfree(dnsans);
    cinfo.ctime = (jiffies - n->ctime) / HZ;
    cinfo.mtime = (jiffies - n->cached_jiffies) / HZ;
    cinfo.protect = n->protect;
    info_len = sizeof(struct cache_info);
}

static int find_cache_node(const char key[], int len, struct node_t **p)
{
    struct dm_cache_hash *hash_bucket;
    int hash_index;
    struct node_t *n = NULL;

    hash_index = hash_val(key, len);
    hash_bucket = &g_domain_cache_hash[hash_index];
    read_trylock_bh(&hash_bucket->l);
    list_for_each_entry(n, &hash_bucket->list, node_list) {
        if (match_node(n, key, len) == DM_SUCCESS) {
            if (n->val) {
                *p = n;
                goto matched;
            }
        }
    }
    read_unlock_bh(&hash_bucket->l);
    return DM_ERROR;

matched:
    read_unlock_bh(&hash_bucket->l);
    return DM_SUCCESS;
}

static int dm_search_domain(struct node_t *n, const char key[], int len)
{
    int ret;
    ret = find_cache_node(key, len, &n);
    if (ret < 0) {
        pr_info("domain is not in cache!\n");
        return DM_ERROR;
    }
    get_cache_info(n);
    return 0;
}

static int dm_clear_domain(struct node_t *n, const char key[], int len)
{
    int ret;
    ret = find_cache_node(key, len, &n);
    if (ret < 0) {
        pr_info("domain is not in cache!\n");
        return -1;
    }
    put_node(n);
    n = NULL;
    return 0;
}
unsigned int ip_s2i(char *ip) {
    unsigned int tmp[4], result = 0;
    sscanf(ip, "%u.%u.%u.%u", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);
    result = tmp[0] + (tmp[1]*(1<<8)) + (tmp[2]*(1<<16)) + (tmp[3]*(1<<24));
    return result;
}

static void dm_show_qpslimit_ip(struct rb_root *root, struct ip_limit_list_t ip_list, rwlock_t *lock) {
    int i;
    char temp[4];
    struct rb_root new_root;
    struct rb_node *i_node, *tmp_node;
    ip_pool *iplist_node;

    new_root = RB_ROOT;
    new_root = *root;
    write_trylock_bh(lock);
    *root = RB_ROOT;
    write_unlock_bh(lock);
    /* judge rb_tree whether empty or not*/
    for (i_node = rb_first(&new_root); i_node;) {
        tmp_node = rb_next(i_node);
        iplist_node = rb_entry(i_node, ip_pool, node);
        ip_list.list[ip_list.len++] = iplist_node->ip;
        rb_erase(i_node, &new_root);
        kfree(iplist_node);
        i_node = tmp_node;
    }

    limitip_len = 0;
    if (ip_list.len == 0) {
        limitip[0] = 0;
        return;
    }
    memset(limitip, 0, sizeof(limitip));
    for (i = 0; i < ip_list.len; i ++) {
        if (i == 0 && lock == &g_ip_rec_pool_l) {
            sprintf(limitip, "rec_ip_limit: ");
        }
        memcpy(temp, &ip_list.list[i], 4);
        sprintf(limitip + strlen(limitip), "%d.%d.%d.%d ", PRINT_IP(temp));
    }
    limitip_len = strlen(limitip);
    ip_list.len = 0;
}

static int recv_conf(struct sock *sk, int cmd, void __user * user,
                     unsigned int len)
{
    struct node_t *n = (struct node_t *)vmalloc(sizeof(struct node_t));
    char command[DOMAIN_LEN_MAX];
    if (n == NULL) {
        return DM_ERROR;
    }
    info_len = 0;
    if (copy_from_user(command, user, len)) {
        goto err;
    }
    switch (cmd) {
        case SOCKET_OPS_SET_SEARCH:
            if (dm_search_domain(n, command, len) == DM_ERROR)
                goto err;
            break;
        case SOCKET_OPS_SET_CLEAR:
            if (dm_clear_domain(n, command, len) == DM_ERROR)
                goto err;
            break;
        case SOCKET_OPS_SET_WHITE:
            /* DOIT: Reserve for white list */
            break;
        case SOCKET_OPS_SET_BLACK:
            /* DOIT: Reserve for black list */
            break;
        case SOCKET_OPS_SET_LIMITIP:
            dm_show_qpslimit_ip(&g_ip_limit_root, ip_limit_list, &g_ip_pool_l);
            dm_show_qpslimit_ip(&g_ip_rec_limit_root, ip_rec_limit_list, &g_ip_rec_pool_l);
            break;
        default:
            goto err;
    }
    vfree(n);
    return DM_SUCCESS;
err:
    vfree(n);
    return DM_ERROR;
}

static int send_conf(struct sock *sk, int cmd, void __user * user, int *len)
{
    int ret = 0;
    if (info_len < 0) {
        return DM_ERROR;
    }

    if (cmd == SOCKET_OPS_GET_SEARCH) {
        ret = copy_to_user(user, &cinfo, sizeof(struct cache_info));
        *len = info_len;
        memset(&cinfo, 0, sizeof(struct cache_info));
    } else if (cmd == SOCKET_OPS_GET_LIMITIP) {
        ret = copy_to_user(user, limitip, sizeof(limitip));
        *len = limitip_len;
    }
    return ret;
}

static struct nf_sockopt_ops conf_sockops __read_mostly = {
    .pf = PF_INET,
    .set_optmin = SOCKET_OPS_SET_BASE,
    .set_optmax = SOCKET_OPS_SET_MAX,
    .set = recv_conf,
    .get_optmin = SOCKET_OPS_GET_BASE,
    .get_optmax = SOCKET_OPS_GET_MAX,
    .get = send_conf,
    .owner = THIS_MODULE,
};

int dm_manage_init(void)
{
    int ret;
    ret = nf_register_sockopt(&conf_sockops);
    if (ret == DM_SUCCESS) {
        pr_info("DNS Mega manage initialization successful\n");
    }
    return ret;
}

void dm_manage_exit(void)
{
    nf_unregister_sockopt(&conf_sockops);
}
