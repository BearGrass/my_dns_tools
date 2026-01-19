#include "request.h"
#include "man_whitelist.h"
#include "log.h"
#include<assert.h>
#ifndef JHASH_INITVAL
#define JHASH_INITVAL 0X2314
#endif
#define MAN_WHITELISTN_HASH_SIZE 1024    //(1<<20)  //1048576,100W
#define MAN_WHITELISTN_FILE ".man_whitelist_active"
#define DATA_OK_FLAG "-----man_whitelistNdataok-----"

#define M1 10
#define M2 20
#define M3 30
#define M4 40
#define MB 60

int g_whitelist_label_max;

typedef struct _man_white_node {
    char *key;
    uint16_t len;
    struct list_head list;
} man_white_node;

static hash_table *man_white_htb[2], *heap[2];
static hash_table *cur_htb = NULL;
//static int cur_htb_pending, man_white_htb_first;

static uint32_t hash_val(const uint8_t * p, uint16_t size);
static hash_table *create_tb(char *name);
static void fix_line(char *line);
static void free_htable(int id);
static void free_man_white_node(man_white_node * n);
static man_white_node *malloc_man_white_node(char *line, int *temp);
static int match_man_whitelist_key(const man_white_node * n, const uint8_t * key,
                               uint8_t klen);
static int match_man_whitelist_node(man_white_node * n1, man_white_node * n2);
static void add_htable(man_white_node * n, hash_table * tb);
static int load_man_whitelist(int id);

static inline uint32_t hash_val(const uint8_t * p, uint16_t size)
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
    return (rte_jhash(p, size, JHASH_INITVAL)) & (MAN_WHITELISTN_HASH_SIZE - 1);
}

static hash_table *create_tb(char *name)
{
    hash_table *tb =
        rte_zmalloc_socket(name, MAN_WHITELISTN_HASH_SIZE * sizeof(hash_table), 0,
                           rte_socket_id());
    if (tb == NULL) {
        ALOG(SERVER, ERROR, "Fail to create %s", name);
        return NULL;
    }

    int i;
    for (i = 0; i < MAN_WHITELISTN_HASH_SIZE; i++) {
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

    if (man_white_htb[id] == NULL) {
        return;
    }

    int i;
    for (i = 0; i < MAN_WHITELISTN_HASH_SIZE; i++) {
        hash_table *ht = man_white_htb[id] + i;
        while (!(list_empty(&ht->list))) {
            assert(ht->size != 0);
            man_white_node *n = list_first_entry(&ht->list, man_white_node, list);
            free_man_white_node(n);
            ht->size--;

        }
        assert(ht->size == 0);
    }
    man_white_htb[id] = NULL;
}

static void free_man_white_node(man_white_node * n)
{
    if (!list_empty(&n->list))
        list_del(&n->list);
    if (n->key)
        rte_free(n->key);
    rte_free(n);
}

static man_white_node *malloc_man_white_node(char *line, int *temp)
{
    int L =strlen(line);
    if (L > 200 || L == 0)
        return NULL;
    man_white_node *n =
        rte_zmalloc_socket(NULL, sizeof(man_white_node), 0, rte_socket_id());
    if (n == NULL) {
        ALOG(SERVER, ERROR, "Fail to zmalloc man_whitelist n node in %s", __func__);
        return NULL;
    }

    uint8_t tkey[256];

    int temp_label_number = 0;
    int idx = 0;
    char *p = NULL;
    if ( line[L - 1] != '.') {
        temp_label_number = 1;
    }
    while ((p = strstr(line, ".")) != NULL) {
        uint8_t len = p - line;
        if (len == 0 && line[0] == '.') {
            if (L == 1) {
                return NULL;
            }
            line++;
            continue;
        }
        tkey[idx++] = len;
        rte_memcpy(tkey + idx, line, len);
        idx += len;
        line = p;
        temp_label_number ++;
    }
    if (*temp < temp_label_number)
        *temp = temp_label_number;
    tkey[idx] = '\0';
    assert(idx < 256);
    uint8_t *key = rte_zmalloc_socket(NULL, idx, 0, rte_socket_id());
    if (key == NULL) {
        rte_free(n);
        return NULL;
    }
    rte_memcpy(key, tkey, idx);
    n->key = (char *)key;
    n->len = idx;
    INIT_LIST_HEAD(&n->list);
    return n;
}

static int match_man_whitelist_key(const man_white_node * n, const uint8_t * key,
                               uint8_t klen)
{
    if (n->len != klen)
        return 0;
    if (memcmp(n->key, (const char *)key, klen) != 0)
        return 0;
    return 1;
}

static int match_man_whitelist_node(man_white_node * n1, man_white_node * n2)
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

static void add_htable(man_white_node * n, hash_table * tb)
{
    if (n == NULL)
        return;
    assert(tb != NULL);
    uint32_t idx = hash_val((const uint8_t *)n->key, n->len);
    hash_table *ht = tb + idx;
    man_white_node *tn;
    list_for_each_entry(tn, &ht->list, list) {
        if (match_man_whitelist_node(tn, n)) {
            free_man_white_node(n);
            return;
        }
    }
    list_add_tail(&n->list, &ht->list);
    ht->size++;
}

static int load_man_whitelist(int id)
{
    int temp = 0;
    hash_table *ptb = NULL;
    assert(man_white_htb[id] == NULL);
    if (cur_htb == heap[1])
        ptb = heap[0];
    else
        ptb = heap[1];
    /*ALOG(SERVER, WARN, "Now begin load man_whitelist n to heap[%d] from file %s",
         id, MAN_WHITELISTN_FILE);
         */
    FILE *fp = fopen(MAN_WHITELISTN_FILE, "r");
    if (!fp) {
        ALOG(SERVER, ERROR, "Open man_whitelist file %s fail", MAN_WHITELISTN_FILE);
        return -1;
    }
    //ALOG(SERVER, WARN, "Open man_whitelist N file %s ok", MAN_WHITELISTN_FILE);
    char *line = NULL;
    size_t len = 0;
    int header = 0;
    while (getline(&line, &len, fp) != -1) {
        fix_line(line);
        if (line == NULL)
            continue;
        if (!header) {
            if (strcmp(DATA_OK_FLAG, line) == 0) {
                header = 1;
                /*
                ALOG(SERVER, WARN,
                     "header ok,now refresh man_whitelist N data from file %s",
                     MAN_WHITELISTN_FILE);
                     */
            }
            continue;
        }

        man_white_node *n = malloc_man_white_node(line, &temp);
        if (n == NULL)
            continue;

        add_htable(n, ptb);
    }
    free(line);
    g_whitelist_label_max = temp;

    fclose(fp);
    man_white_htb[id] = ptb;

    //ALOG(SERVER, INFO, "load man_whitelist N data done, the g_whitelist_label_max is %d", g_whitelist_label_max);

    return 0;
}

int init_man_whitelist()
{
    g_whitelist_label_max = 0;
    heap[0] = create_tb("man_whitelist_hash_table_0");
    if (heap[0] == NULL)
        return -1;
    heap[1] = create_tb("man_whitelist_hash_table_1");
    if (heap[1] == NULL)
        return -1;
    man_white_htb[0] = man_white_htb[1] = NULL;
    load_man_whitelist(0);
    if (man_white_htb[0] == NULL)
        man_white_htb[0] = heap[0];
    cur_htb = man_white_htb[0];
    rte_wmb();
    return 0;
}

int is_man_whitelist(node * n)
{
    return man_whitelist_judge(n->key->data, n->key->len);
}

int man_whitelist_judge(const uint8_t * key, uint16_t size)
{
    if (cur_htb == NULL)
        return 0;
    //find cur_htb
    uint32_t idx = hash_val(key, size);
    hash_table *ht = cur_htb + idx;
    man_white_node *n;
    list_for_each_entry(n, &ht->list, list) {
        if (match_man_whitelist_key(n, key, size))
            return 1;
    }
    return 0;
}

void charge_man_whitelist_state()   //only called at misc core
{
    assert(man_white_htb[0] != NULL || man_white_htb[1] != NULL);
    if (cur_htb == man_white_htb[0]) {
        free_htable(1);
        if (load_man_whitelist(1) == 0) {
            cur_htb = man_white_htb[1];
            rte_wmb();
        }
    } else {
        free_htable(0);
        if (load_man_whitelist(0) == 0) {
            cur_htb = man_white_htb[0];
            rte_wmb();
        }
    }

}
