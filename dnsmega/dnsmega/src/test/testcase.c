#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "test.h"

#define MEGATEST

MODULE_DESCRIPTION("Test Module");
MODULE_LICENSE("GPL");

/* an example:the pacage of dns query for ilike.simba.taobao.com */
const uint8_t query_message[] = {
    0x00 ,0x22 ,0xbd ,0xf1 ,0x54 ,0x00 ,0x5c ,0xe0 ,0xc5 ,0x7d ,0xfc ,0xb2 ,0x08 ,0x00 ,0x45 ,0x00,
    0x00 ,0x44 ,0x77 ,0x91 ,0x00 ,0x00 ,0x80 ,0x11 ,0x55 ,0x77 ,0x1e ,0x06 ,0x44 ,0x59 ,0x0a ,0x41,
    0x01 ,0x01 ,0xdc ,0x8a ,0x00 ,0x35 ,0x00 ,0x30 ,0x9f ,0xee ,0x5c ,0x0a ,0x01 ,0x00 ,0x00 ,0x01,
    0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x05 ,0x69 ,0x6c ,0x69 ,0x6b ,0x65 ,0x05 ,0x73 ,0x69 ,0x6d,
    0x62 ,0x61 ,0x06 ,0x74 ,0x61 ,0x6f ,0x62 ,0x61 ,0x6f ,0x03 ,0x63 ,0x6f ,0x6d ,0x00 ,0x00 ,0x01,
    0x00 ,0x01
};
const uint16_t query_len = 92;
const uint16_t query_head_l7 = 42;
const uint8_t answer_message[] = {
    0x5c ,0xe0 ,0xc5 ,0x7d ,0xfc ,0xb2 ,0x00 ,0x22 ,0xbd ,0xf1 ,0x54 ,0x00 ,0x08 ,0x00 ,0x45 ,0x00,
    0x00 ,0x81 ,0x0e ,0x29 ,0x40 ,0x00 ,0x7c ,0x11 ,0x82 ,0xa2 ,0x0a ,0x41 ,0x01 ,0x01 ,0x1e ,0x06,
    0x44 ,0x59 ,0x00 ,0x35 ,0xdc ,0x8a ,0x00 ,0x6d ,0x7a ,0x00 ,0x5c ,0x0a ,0x81 ,0x80 ,0x00 ,0x01,
    0x00 ,0x02 ,0x00 ,0x00 ,0x00 ,0x00 ,0x05 ,0x69 ,0x6c ,0x69 ,0x6b ,0x65 ,0x05 ,0x73 ,0x69 ,0x6d,
    0x62 ,0x61 ,0x06 ,0x74 ,0x61 ,0x6f ,0x62 ,0x61 ,0x6f ,0x03 ,0x63 ,0x6f ,0x6d ,0x00 ,0x00 ,0x01,
    0x00 ,0x01 ,0xc0 ,0x0c ,0x00 ,0x05 ,0x00 ,0x01 ,0x00 ,0x00 ,0x06 ,0x8f ,0x00 ,0x13 ,0x05 ,0x63,
    0x6d ,0x77 ,0x65 ,0x62 ,0x05 ,0x69 ,0x6c ,0x69 ,0x6b ,0x65 ,0x04 ,0x31 ,0x36 ,0x38 ,0x38 ,0xc0,
    0x1f ,0xc0 ,0x34 ,0x00 ,0x05 ,0x00 ,0x01 ,0x00 ,0x00 ,0x00 ,0xba ,0x00 ,0x12 ,0x05 ,0x63 ,0x6d,
    0x77 ,0x65 ,0x62 ,0x05 ,0x69 ,0x6c ,0x69 ,0x6b ,0x65 ,0x03 ,0x67 ,0x64 ,0x73 ,0xc0 ,0x40
};
const uint16_t answer_len = 143;
const uint16_t answer_head_l7 = 42;
struct dm_dnsans dnsans[MAX_ANSWER_NUM];

/* unit test for parse_dns_message function */
static void test_parse_dns(void) {
    /* function's parameter */
    struct dm_dnshdr *dnshdr = (struct dm_dnshdr*)(query_message + query_head_l7);
    uint16_t dns_len = query_len - query_head_l7;
    struct dm_dnsques *dnsques;
    int ansnum;

    int ret;
    int success = DM_SUCCESS, nosupport = DM_NOSUPPORT, error = DM_ERROR;
    t_result result;

    ret =  parse_dns_message(dnshdr, dns_len, dnsques, NULL, NULL);
    result = t_judge("parse_dns_message(query)", (void*)&ret, (void*)&success, 0, TA_INT, EQUALL);

    dnshdr = (struct dm_dnshdr*)(answer_message + answer_head_l7);
    ret = parse_dns_message(dnshdr, dns_len, NULL, dnsans, &ansnum);
    result = t_judge("parse_dns_message(answer)", (void*)&ret, (void*)&success, 0, TA_INT, EQUALL);

    return;
}

/* unit test for get_node and put_node function */
static void test_node(void) {
    const uint8_t *qkey[] = {
        "1","2"
    };
    char *ans;
    int klen[] = {
        1,1
    };
    int ret;
    t_result result;
    struct node_t *n = NULL;
    n = get_node(qkey[0], klen[0]);
    result = t_judge("get_node", (void*)n, NULL, 0, TA_POINT, NEQUALL);

    ret = update_node(n, qkey[1], klen[1], NULL, 0);
    ans = (char*)vmalloc(sizeof(char));
    strcpy(ans, "2");
    result = t_judge("update_node", (void*)n, NULL, 0, TA_POINT, NEQUALL);
    result = t_judge("update_node", (void*)n->val->buf, (void*)ans, klen[1], TA_STRING, EQUALL);
    vfree(ans);

    put_node(n);
    n = NULL;
    result = t_judge("put_node", (void*)n, NULL, 0, TA_POINT, EQUALL);
}

/* unit test for request */
static void test_req(void) {
    const uint8_t *qkey = "1";
    int klen = 1, ret, num = 0, ans = 1;
    struct node_t *n;
    struct request_t *r = NULL;
    struct sk_buff *skb, *skbs[36];
    t_result result;

    skb = NULL;
    n = get_node(qkey, klen);
    r = get_request(skb);
    put_request_to_node(n, r);
    pop_req_from_wait_list(n, skbs, &num);
    result = t_judge("pop_req_from_wait_list", (void*)&num, (void*)&ans, 0, TA_INT, EQUALL);
    ans = 0;
    result = t_judge("pop_req_from_wait_list", (void*)&(n->wait_size), (void*)&ans, 0, TA_INT, EQUALL);
    kfree(skbs);
    put_node(n);
    n = NULL;
}

/* uint test for cache_insert */
static void test_cache_insert(void) {
    struct sk_buff *skb = NULL;
    const uint8_t *qkey = "1";
    int klen = 1;
    int hash_index;
    int ans, ret;
    t_result result;
    struct dm_cache_hash *hash_bucket;
    struct node_t *n;

    hash_index = hash_val(qkey, klen);
    hash_bucket = &g_domain_cache_hash[hash_index];
    ans = DM_ERROR;
    ret = cache_insert(skb, qkey, klen, &n, hash_bucket);
    result = t_judge("cache_insert", (void*)&ret, (void*)&ans, 0, TA_INT, EQUALL);
}

/* unit test for cache insert,find and clear */
static void test_cache_find(void) {
    struct sk_buff *skb = NULL;
    const uint8_t *qkey[] = {
        "1","2"
    };
    int klen[] = {
        1,1
    };
    int hash_index;
    int ret, ans;
    int temp;
    t_result result;
    struct dm_cache_hash *hash_bucket;
    struct node_t *n;

    hash_index = hash_val(qkey[0], klen[0]);
    hash_bucket = &g_domain_cache_hash[hash_index];

    /* insert*/
    ret = cache_find(qkey[0], klen[0], skb, &n, hash_bucket);
    ans = CACHE_INSERT;
    result = t_judge("cache_find(INSERT)", (void*)&ret, (void*)&ans, 0, TA_INT, EQUALL);

    /* found */
    skb = alloc_skb(0, GFP_KERNEL);
    ret = cache_insert(skb, qkey[0], klen[0], &n, hash_bucket);
    n->val = (struct value_t*)skb;
    ret = cache_find(qkey[0], klen[0], skb, &n, hash_bucket);
    ans = CACHE_FIND;
    result = t_judge("cache_find(FIND)", (void*)&ret, (void*)&ans, 0, TA_INT, EQUALL);

    /* update */
    temp = sysctl_dm_barely_trusted_time;
    sysctl_dm_barely_trusted_time = 0;
    ret = cache_find(qkey[0], klen[0], skb, &n, hash_bucket);
    ans = CACHE_UPDATE;
    result = t_judge("cache_find(UPDATE)", (void*)&ret, (void*)&ans, 0, TA_INT, EQUALL);
    sysctl_dm_barely_trusted_time = temp;
    kfree_skb(skb);
    skb = NULL;
    n->val = NULL;

    /* drop */
    skb = alloc_skb(0, GFP_KERNEL);
    hash_index = hash_val(qkey[0], klen[0]);
    hash_bucket = &g_domain_cache_hash[hash_index];
    ret = cache_insert(skb, qkey[0], klen[0], &n, hash_bucket);
    kfree_skb(skb);
    skb = NULL;
    temp = sysctl_dm_req_waitlist_num;
    sysctl_dm_req_waitlist_num = 0;
    ret = cache_find(qkey[0], klen[0], skb, &n, hash_bucket);
    ans = CACHE_DROP;
    result = t_judge("cache_find(DROP)", (void*)&ret, (void*)&ans, 0, TA_INT, EQUALL);
    sysctl_dm_req_waitlist_num = temp;

    ret = cache_find(qkey[0], klen[0], skb, &n, hash_bucket);
    ans = CACHE_HOLD;
    result = t_judge("cache_find(HOLD)", (void*)&ret, (void*)&ans, 0, TA_INT, EQUALL);
}

static int __init test_start(void) {
    int ret;
    ret = dm_cache_init();
    ret = dm_timer_init();
    test_node();
    test_req();
    test_cache_insert();
    test_cache_find();
    test_parse_dns();
    show_test_result();
    return ret;
}

static void __exit test_exit(void) {
    pr_info("Test End");
    dm_timer_exit();
    dm_cache_exit();
}

module_init(test_start);
module_exit(test_exit);
