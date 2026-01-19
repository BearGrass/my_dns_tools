#include "request.h"
#include "whitelist.h"
#include "log.h"
#include<assert.h>
#ifndef JHASH_INITVAL
#define JHASH_INITVAL 0X2314
#endif
#define WHITELISTN_HASH_SIZE 1048576    //(1<<20)  //1048576,100W
#define WHITELISTN_FILE ".whitelist_active"
#define DATA_OK_FLAG "-----whitelistNdataok-----"

#define M1 10
#define M2 20
#define M3 30
#define M4 40
#define MB 60

typedef struct _white_node {
    char *key;
    uint16_t len;
    struct list_head list;
} white_node;

static hash_table *white_htb[2], *heap[2];
static hash_table *cur_htb = NULL;
//static int cur_htb_pending, white_htb_first;

static uint32_t hash_val(const uint8_t * p, uint16_t size);
static hash_table *create_tb(char *name);
static void fix_line(char *line);
static void free_htable(int id);
static void free_white_node(white_node * n);
static white_node *malloc_white_node(char *line);
static int match_whitelist_key(const white_node * n, const uint8_t * key,
                               uint8_t klen);
static int match_whitelist_node(white_node * n1, white_node * n2);
static void add_htable(white_node * n, hash_table * tb);
static int load_whitelist(int id);

static uint32_t hash_val(const uint8_t * p, uint16_t size)
{
/*
	uint8_t p2[size];
        uint8_t i;
        for(i = 0 ; i < size - 2; i ++){
                if(p[i] >= 'A' && p[i] <= 'Z')
                        p2[i] = p[i] + 32;
                else
                        p2[i] = p[i];
        }
        p2[i] = p[i];
        i++;
        p2[i] = p[i];
*/
    return (rte_jhash(p, size, JHASH_INITVAL)) & (WHITELISTN_HASH_SIZE - 1);
}

static hash_table *create_tb(char *name)
{
    hash_table *tb =
        rte_zmalloc_socket(name, WHITELISTN_HASH_SIZE * sizeof(hash_table), 0,
                           rte_socket_id());
    if (tb == NULL) {
        ALOG(SERVER, ERROR, "Fail to create %s", name);
        return NULL;
    }

    int i;
    for (i = 0; i < WHITELISTN_HASH_SIZE; i++) {
        hash_table *t = tb + i;
        INIT_LIST_HEAD((&t->list));
        t->size = 0;
        assert(list_empty(&t->list));
    }
    return tb;
}

static void fix_line(char *line)
{
    int len, i;

    while (1) {
        if (line == NULL)
            break;
        len = strlen(line);
        for (i = 0; i < len; i++) {
            if (line[i] == ' ') {
                while (i < len) {
                    line[i] = '\0';
                    i++;
                }
                break;
            }
        }
        len = strlen(line);
        if (line[len - 1] == '\r' || line[len - 1] == '\n'
            || line[len - 1] == ' ' || line[len - 1] == '\t') {
            line[len - 1] = '\0';
            continue;
        }
        break;

    }
}

static void free_htable(int id)
{

    if (white_htb[id] == NULL) {
        return;
    }

    int i;
    for (i = 0; i < WHITELISTN_HASH_SIZE; i++) {
        hash_table *ht = white_htb[id] + i;
        while (!(list_empty(&ht->list))) {
            assert(ht->size != 0);
            white_node *n = list_first_entry(&ht->list, white_node, list);
            free_white_node(n);
            ht->size--;

        }
        assert(ht->size == 0);
    }
    white_htb[id] = NULL;
}

static void free_white_node(white_node * n)
{
    if (!list_empty(&n->list))
        list_del(&n->list);
    if (n->key)
        rte_free(n->key);
    rte_free(n);
}

static white_node *malloc_white_node(char *line)
{
    if (strlen(line) > 200)
        return NULL;
    char *p = strstr(line, "/");
    if (p == NULL)
        return NULL;
    if (strlen(p) < 1)
        return NULL;
    white_node *n =
        rte_zmalloc_socket(NULL, sizeof(white_node), 0, rte_socket_id());
    if (n == NULL) {
        ALOG(SERVER, ERROR, "Fail to zmalloc whitelist n node in %s", __func__);
        return NULL;
    }

    uint8_t tkey[256];

    uint16_t type = (uint16_t) atoi(p + 1);

    p[0] = '\0';
    int idx = 0;
    while ((p = strstr(line, ".")) != NULL) {
        uint8_t len = p - line;
        if (len == 0 && line[0] == '.') {
            line++;
            continue;
        }
        tkey[idx++] = len;
        rte_memcpy(tkey + idx, line, len);
        idx += len;
        line = p;
    }
    tkey[idx++] = '\0';
    assert(idx < 256);
    uint8_t *key = rte_zmalloc_socket(NULL, idx + 2, 0, rte_socket_id());
    if (key == NULL) {
        rte_free(n);
        return NULL;
    }
    uint16_t *ttype = (uint16_t *) (tkey + idx);
    *ttype = type;
    rte_memcpy(key, tkey, idx + 2);
    n->key = (char *)key;
    n->len = idx + 2;
    INIT_LIST_HEAD(&n->list);
    return n;
}

static int match_whitelist_key(const white_node * n, const uint8_t * key,
                               uint8_t klen)
{
    if (n->len != klen || klen <= 2)
        return 0;
    int pass = klen - 2;
    if (strncasecmp(n->key, (const char *)key, pass) != 0)
        return 0;
    if (memcmp(n->key + pass, key + pass, 2) != 0)
        return 0;
    return 1;

}

static int match_whitelist_node(white_node * n1, white_node * n2)
{
    assert(n1 != NULL && n2 != NULL);
    if (n1->len != n2->len)
        return 0;
    int pass = n1->len - 2;
    if (strncasecmp(n1->key, n2->key, pass) != 0)
        return 0;
    if (memcmp(n1->key + pass, n2->key + pass, 2) != 0)
        return 0;
    return 1;
}

static void add_htable(white_node * n, hash_table * tb)
{
    if (n == NULL)
        return;
    assert(tb != NULL);
    uint32_t idx = hash_val((const uint8_t *)n->key, n->len);
    hash_table *ht = tb + idx;
    white_node *tn;
    list_for_each_entry(tn, &ht->list, list) {
        if (match_whitelist_node(tn, n)) {
            free_white_node(n);
            return;
        }
    }
    list_add_tail(&n->list, &ht->list);
    ht->size++;
}

static int load_whitelist(int id)
{
    hash_table *ptb = NULL;
    assert(white_htb[id] == NULL);
    if (cur_htb == heap[1])
        ptb = heap[0];
    else
        ptb = heap[1];
/*    ALOG(SERVER, WARN, "Now begin load whitelist n to heap[%d] from file %s",
         id, WHITELISTN_FILE);*/
    FILE *fp = fopen(WHITELISTN_FILE, "r");
    if (!fp) {
        ALOG(SERVER, ERROR, "Open whitelist file %s fail", WHITELISTN_FILE);
        return -1;
    }
    //ALOG(SERVER, WARN, "Open whitelist N file %s ok", WHITELISTN_FILE);
    char *line = NULL;
    size_t len = 0;
    int header = 0;
    while (getline(&line, &len, fp) != -1) {
        if (header && (strstr(line, "/") == NULL))
            continue;
        fix_line(line);
        if (line == NULL)
            continue;
        if (!header) {
            if (strcmp(DATA_OK_FLAG, line) == 0) {
                header = 1;
                ALOG(SERVER, WARN,
                     "header ok,now refresh whitelist N data from file %s",
                     WHITELISTN_FILE);
            }
            continue;
        }

        white_node *n = malloc_white_node(line);
        if (n == NULL)
            continue;

        add_htable(n, ptb);
    }

    fclose(fp);
    white_htb[id] = ptb;

    //ALOG(SERVER, WARN, "load whitelist N data done");

    return 0;
}

int init_whitelist()
{
    heap[0] = create_tb("whitelist_hash_table_0");
    if (heap[0] == NULL)
        return -1;
    heap[1] = create_tb("whitelist_hash_table_1");
    if (heap[1] == NULL)
        return -1;
    white_htb[0] = white_htb[1] = NULL;
    load_whitelist(0);
    if (white_htb[0] == NULL)
        white_htb[0] = heap[0];
    cur_htb = white_htb[0];
    rte_wmb();
    return 0;
}

int is_whitelist(node * n)
{
    return whitelist_judge(n->key->data, n->key->len);
}

int whitelist_judge(const uint8_t * key, uint16_t size)
{
    if (cur_htb == NULL)
        return 0;
    //find cur_htb
    uint32_t idx = hash_val(key, size);
    hash_table *ht = cur_htb + idx;
    white_node *n;
    list_for_each_entry(n, &ht->list, list) {
        if (match_whitelist_key(n, key, size))
            return 1;
    }
    return 0;
}

void charge_whitelist_state()   //only called at misc core
{

    assert(white_htb[0] != NULL || white_htb[1] != NULL);
    if (cur_htb == white_htb[0]) {
        free_htable(1);
        if (load_whitelist(1) == 0) {
            cur_htb = white_htb[1];
            rte_wmb();
        }
    } else {
        free_htable(0);
        if (load_whitelist(0) == 0) {
            cur_htb = white_htb[0];
            rte_wmb();
        }
    }
}
