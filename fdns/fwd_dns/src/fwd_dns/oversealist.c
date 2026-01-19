#include<assert.h>

#include "ldns.h"
#include "request.h"
#include "oversealist.h"
#include "log.h"

#ifndef JHASH_INITVAL
#define JHASH_INITVAL 0X2314
#endif
#define OVERSEALISTN_HASH_SIZE 1048576  //(1<<20)  //1048576,100W
#define OVERSEALISTN_FILE ".oversealist_active"
#define DATA_OK_FLAG "-----oversealistNdataok-----"

#define M1 10
#define M2 20
#define M3 30
#define M4 40
#define MB 60

typedef struct _oversea_node {
    char *key;
    uint16_t len;
    struct list_head list;
} oversea_node;

static hash_table *oversea_htb[2], *heap[2];
static hash_table *cur_htb = NULL;

static uint32_t hash_val(const uint8_t * p, uint16_t size);
static hash_table *create_tb(char *name);
static void fix_line(char *line);
static void free_htable(int id);
static void free_oversea_node(oversea_node * n);
static oversea_node *malloc_oversea_node(char *line);
static int match_oversealist_key(oversea_node * n, uint8_t * key, uint8_t klen);
static int match_oversealist_node(oversea_node * n1, oversea_node * n2);
static void add_htable(oversea_node * n, hash_table * tb);
static int load_oversealist(int id);

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
    return (rte_jhash(p, size, JHASH_INITVAL)) & (OVERSEALISTN_HASH_SIZE - 1);
}

static hash_table *create_tb(char *name)
{
    hash_table *tb =
        rte_zmalloc_socket(name, OVERSEALISTN_HASH_SIZE * sizeof(hash_table), 0,
                           rte_socket_id());
    if (tb == NULL) {
        ALOG(SERVER, ERROR, "Fail to create %s", name);
        return NULL;
    }

    int i;
    for (i = 0; i < OVERSEALISTN_HASH_SIZE; i++) {
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

    assert(oversea_htb[id] != NULL);

    int i;
    for (i = 0; i < OVERSEALISTN_HASH_SIZE; i++) {
        hash_table *ht = oversea_htb[id] + i;
        while (!(list_empty(&ht->list))) {
            assert(ht->size != 0);
            oversea_node *n = list_first_entry(&ht->list, oversea_node, list);
            free_oversea_node(n);
            ht->size--;

        }
        assert(ht->size == 0);
    }
    oversea_htb[id] = NULL;
}

static void free_oversea_node(oversea_node * n)
{
    if (!list_empty(&n->list))
        list_del(&n->list);
    if (n->key)
        rte_free(n->key);
    rte_free(n);
}

static oversea_node *malloc_oversea_node(char *line)
{
    if (strlen(line) > 200)
        return NULL;
    char *p = strstr(line, "/");
    if (p == NULL)
        return NULL;
    if (strlen(p) < 1)
        return NULL;
    oversea_node *n =
        rte_zmalloc_socket(NULL, sizeof(oversea_node), 0, rte_socket_id());
    if (n == NULL) {
        ALOG(SERVER, ERROR, "Fail to zmalloc oversealist n node in %s",
             __func__);
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

static int match_oversealist_key(oversea_node * n, uint8_t * key, uint8_t klen)
{
    if (n->len != klen || klen <= QKEY_TAIL_LEN)
        return 0;
    int pass = klen - QKEY_TAIL_LEN;
    if (strncasecmp(n->key, (const char *) key, pass) != 0)
        return 0;
    if (*(uint16_t *) (n->key + pass) != *(uint16_t *) (key + pass))
        return 0;
    if (*(uint8_t *) (n->key + pass + QUERY_TYPE_LEN)
            != *(key + pass + QUERY_TYPE_LEN))
        return 0;
    return 1;
}

static int match_oversealist_node(oversea_node * n1, oversea_node * n2)
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

static void add_htable(oversea_node * n, hash_table * tb)
{
    if (n == NULL)
        return;
    assert(tb != NULL);
    uint32_t idx = hash_val((const uint8_t *)n->key, n->len);
    hash_table *ht = tb + idx;
    oversea_node *tn;
    list_for_each_entry(tn, &ht->list, list) {
        if (match_oversealist_node(tn, n)) {
            free_oversea_node(n);
            return;
        }
    }
    list_add_tail(&n->list, &ht->list);
    ht->size++;
}

static int load_oversealist(int id)
{

    hash_table *ptb = NULL;
    assert(oversea_htb[id] == NULL);
    if (cur_htb == heap[1])
        ptb = heap[0];
    else
        ptb = heap[1];
/*    ALOG(SERVER, WARN, "Now begin load oversealist n to heap[%d] from file %s",
         id, OVERSEALISTN_FILE);*/
    FILE *fp = fopen(OVERSEALISTN_FILE, "r");
    if (!fp) {
        ALOG(SERVER, ERROR, "Open oversealist file %s fail", OVERSEALISTN_FILE);
        return -1;
    }
    //ALOG(SERVER, WARN, "Open oversealist N file %s ok", OVERSEALISTN_FILE);
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
/*                ALOG(SERVER, WARN,
                     "header ok,now refresh oversealist N data from file %s",
                     OVERSEALISTN_FILE);*/
            }
            continue;
        }

        oversea_node *n = malloc_oversea_node(line);
        if (n == NULL)
            continue;

        add_htable(n, ptb);
    }

    fclose(fp);
    oversea_htb[id] = ptb;

    //ALOG(SERVER, WARN, "load oversealist N data done");

    return 0;

}

int init_oversealist()
{
    heap[0] = create_tb("oversealist_hash_table_0");
    if (heap[0] == NULL)
        return -1;
    heap[1] = create_tb("oversealist_hash_table_1");
    if (heap[1] == NULL)
        return -1;
    oversea_htb[0] = oversea_htb[1] = NULL;
    load_oversealist(0);
    if (oversea_htb[0] == NULL)
        oversea_htb[0] = heap[0];
    cur_htb = oversea_htb[0];
    rte_wmb();
    return 0;
}

int oversealist_judge(uint8_t * key, uint16_t size)
{
    if (cur_htb == NULL)
        return 0;
    //find cur_htb
    uint32_t idx = hash_val(key, size);
    hash_table *ht = cur_htb + idx;
    oversea_node *n;
    list_for_each_entry(n, &ht->list, list) {
        if (match_oversealist_key(n, key, size))
            return 1;
    }
    return 0;
}

int is_oversealist(node * n)
{
    return oversealist_judge(n->key->data, n->key->len);
}

void charge_oversealist_state() //only called at misc core
{

    assert(oversea_htb[0] != NULL || oversea_htb[1] != NULL);
    if (cur_htb == oversea_htb[0]) {
        assert(oversea_htb[1] == NULL);
        if (load_oversealist(1) == 0) {
            cur_htb = oversea_htb[1];
            rte_wmb();
            free_htable(0);
        }
    } else {
        assert(oversea_htb[0] == NULL);
        if (load_oversealist(0) == 0) {
            cur_htb = oversea_htb[0];
            rte_wmb();
            free_htable(1);
        }
    }
    //use rte_wmb() to flush cpu cache ,make it valid to other cpu right now
/*
	long ts = time(NULL);
	struct tm *ptm = localtime(&ts);
	int tm = ptm->tm_min % MB;
	if(tm > M1 && oversea_htb_first)
		return;	

	if(tm > M4){
		//40~60,drop unused hash table
		if(cur_htb_pending == 4)
			return;
		assert(cur_htb_pending == 2);
		if(cur_htb == oversea_htb[0]){
			free_htable(1);
			assert(oversea_htb[1] == NULL);
		}else{
			free_htable(0);
			assert(oversea_htb[0] == NULL);
		}
		cur_htb_pending = 4;
	}else if(tm > M3){
		if(cur_htb_pending == 2)
			return;
		assert(cur_htb_pending == 1);

		//30~40 minute,change current_hash_table
		if(cur_htb == oversea_htb[0]){
			cur_htb = oversea_htb[1];
		}else{
			cur_htb = oversea_htb[0];
		}
		assert(cur_htb != NULL);
		cur_htb_pending = 2;
	}

	else if(tm > M2){
		//20~30 minute,gap time
		assert(cur_htb_pending == 1);
	}else{
		if(cur_htb_pending == 1 && oversea_htb_first == 0) 
			return;
		assert((cur_htb_pending == 4 || cur_htb_pending == 1));

		//0~20minute,rend oversealist next
		assert(oversea_htb[0] != NULL || oversea_htb[1] != NULL);
		if(cur_htb == oversea_htb[0]){
			assert(oversea_htb[1] == NULL);
			if(load_oversealist(1) <0 )
				oversea_htb_first = 1;
			else 
				oversea_htb_first = 0;
		}else{
			assert(oversea_htb[0] == NULL);
			if(load_oversealist(0) <0 )
				oversea_htb_first = 1;
			else
				oversea_htb_first = 0;
		}
		cur_htb_pending = 1;
		
	}
*/
}
