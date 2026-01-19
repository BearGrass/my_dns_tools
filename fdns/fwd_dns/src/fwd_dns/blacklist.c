#include "request.h"
#include "blacklist.h"
#include "log.h"
#include<assert.h>
#ifndef JHASH_INITVAL
#define JHASH_INITVAL 0X2314
#endif
#define BLACKLISTN_HASH_SIZE 10240
#define BLACKLISTN_FILE ".blacklist_active"
#define DATA_OK_FLAG "-----blacklistNdataok-----"

static int black_label[LABEL_MAX];
static int emax = -1, emin = -1;

typedef struct black_domain_t {
    uint8_t *key;
    uint8_t *org_key;
    uint8_t org_klen;
    uint8_t klen;
    uint8_t label;
    uint32_t hval;
    hash_table *tb;
    struct list_head list;
} black_domain;

static hash_table *black_htb[2], *heap[2];
static hash_table *cur_htb = NULL;

static uint32_t hash_val(const uint8_t * p, uint16_t size);
static hash_table *create_tb(char *name);
static void fix_line(char *line);
static void fix_line2(char *line);
static void fix_black_label(int label);
static int match_black_domain(black_domain * e1, black_domain * e2);
static void _black_domain_add(hash_table * tb, black_domain * bd);
static black_domain *_get_black_domain(uint8_t * key, uint8_t klen,
                                       uint8_t label, char *line);
static black_domain *get_black_domain(char *domain);
static int put_black_domain(black_domain * bd);
static int black_domain_add(hash_table * tb, char *domain);
static int load_blacklist(int id);
static void free_htable(int id);

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
    return (rte_jhash(p, size, JHASH_INITVAL)) & (BLACKLISTN_HASH_SIZE - 1);
}

static hash_table *create_tb(char *name)
{
    hash_table *tb =
        rte_zmalloc_socket(name, BLACKLISTN_HASH_SIZE * sizeof(hash_table), 0,
                           rte_socket_id());
    if (tb == NULL) {
        ALOG(SERVER, ERROR, "Fail to create %s", name);
        return NULL;
    }

    int i;
    for (i = 0; i < BLACKLISTN_HASH_SIZE; i++) {
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
        if(line[len-1] == '\r' || line[len - 1 ] == '\n' || line[len - 1 ] == ' ' || line[len-1] == '\t'){
            line[len-1] = '\0';
            continue;
        }
        break;
    }
    
    while (strlen(line) > 0){
        if (line[strlen(line) - 1] == '.')
            line[strlen(line) - 1] = '\0';
        else
            break;
    }

    for (i = 0; i < strlen(line); i++) {
        if (line[i] >= 'A' && line[i] <= 'Z')
            line[i] = line[i] + 32;
    }

}

static void fix_line2(char *line)
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

    while (strlen(line) >= 0) {
        if (line[strlen(line) - 1] == '.')
            line[strlen(line) - 1] = '\0';
        else
            break;
    }
}

static void fix_black_label(int label)
{
    if (emax == -1) {
        emax = label;
        emin = label;
        return;
    }

    if (emax < label)
        emax = label;
    if (emin > label)
        emin = label;
}

static int match_black_domain(black_domain * e1, black_domain * e2)
{
    assert(e1 != NULL);
    assert(e2 != NULL);
    if (e1->label != e2->label)
        return 0;
    if (e1->hval != e2->hval)
        return 0;
    if (e1->klen != e2->klen)
        return 0;
    if (memcmp(e1->key, e2->key, e1->klen) != 0)
        return 0;
    return 1;
}

static void _black_domain_add(hash_table * tb, black_domain * bd)
{
    hash_table *ht = tb + bd->hval;
    black_domain *e;
    list_for_each_entry(e, &ht->list, list) {
        if (match_black_domain(e, bd)) {
            ALOG(SERVER, WARN, "Cannot do %s cause %s exist", __func__,
                 bd->org_key);
            put_black_domain(bd);
            return;
        }
    }

    bd->tb = ht;
    list_add_tail(&bd->list, &ht->list);
    ALOG(SERVER, INFO,
         "Lcore %d : Add black_domain '%s' to hash %p ,hval %d done",
         rte_lcore_id(), bd->org_key, bd->tb, bd->hval);
    ht->size++;
    return;
}

static black_domain *_get_black_domain(uint8_t * key, uint8_t klen,
                                       uint8_t label, char *line)
{

    black_domain *bd =
        rte_zmalloc_socket(NULL, sizeof(black_domain), 0, rte_socket_id());
    if (bd == NULL) {
        ALOG(SERVER, ERROR, "Cannot do zmalloc size %d in %s",
             sizeof(black_domain), __func__);
        return NULL;
    }

    bd->key = rte_zmalloc_socket(NULL, klen, 0, rte_socket_id());
    if (bd->key == NULL) {
        ALOG(SERVER, ERROR, "Cannot do zmalloc size %d in %s", klen, __func__);
        put_black_domain(bd);
        return NULL;
    }

    bd->org_key =
        rte_zmalloc_socket(NULL, strlen(line) + 1, 0, rte_socket_id());
    if (bd->org_key == NULL) {
        ALOG(SERVER, ERROR, "Cannot do zmalloc size %d in %s", strlen(line) + 1,
             __func__);
        put_black_domain(bd);
        return NULL;
    }

    rte_memcpy(bd->key, key, klen);
    bd->klen = klen;
    assert(bd->klen <= 255);

    rte_memcpy(bd->org_key, line, strlen(line));
    bd->org_key[strlen(line)] = '\0';
    bd->org_klen = strlen(line);

    bd->label = label;
    fix_black_label(label);
    black_label[label]++;
    uint32_t idx = hash_val(key, klen);
    bd->hval = idx;
    INIT_LIST_HEAD(&bd->list);
    return bd;
}

static black_domain *get_black_domain(char *domain)
{
    black_domain *bd = NULL;
    char *line = domain;
    fix_line(line);
    while (strlen(line) >= 0) {
        if (line[0] == '.')
            line++;
        else
            break;
    }
    if (line == NULL)
        return NULL;

    if (strlen(line) >= 256) {
        ALOG(SERVER, ERROR, "black_domain %s size >= 256 , pass", line);
        return NULL;
    }

    if (strlen(line) <= 1) {
        ALOG(SERVER, ERROR, "black_domain %s size <= 1 , pass", line);
        return NULL;
    }

    uint8_t tkey[256], tklen;
    uint8_t *c = NULL, idx, tidx = 0, counter = 0;
    uint8_t label = 0;

    for (idx = 0; idx < strlen(line); idx++) {
        if (!c) {
            c = tkey + tidx;
            tidx++;
        }
        //tidx is now will set value
        if (line[idx] == '.') {
            assert(idx != strlen(line) - 1);
            *c = counter;
            label++;
            counter = 0;
            c = NULL;
        } else {
            tkey[tidx] = (uint8_t) line[idx];
            counter++;
            if (idx != strlen(line) - 1) {
                tidx++;
            } else {
                assert(c != NULL);
                *c = counter;
                label++;
                break;
            }
        }

    }

    tklen = (tidx + 1);

    bd = _get_black_domain(tkey, tklen, label, line);
    return bd;
}

static int put_black_domain(black_domain * bd)
{
    if (bd == NULL)
        return -1;
    if (bd->key)
        rte_free(bd->key);
    if (bd->org_key)
        rte_free(bd->org_key);
    if (!list_empty(&bd->list)) {
        hash_table *ht = bd->tb;
        bd->tb = NULL;
        list_del(&bd->list);
        ht->size--;
        assert(ht->size >= 0);
        black_label[bd->label]--;
        if (black_label[bd->label] <= 0) {

            if (emax == bd->label) {
                int i = bd->label - 1;
                while (i > 0) {
                    if (black_label[i] > 0) {
                        emax = i;
                        break;
                    }
                    i--;
                }
                if (i <= 0)
                    emax = -1;
            }

            if (emin == bd->label) {
                int i = bd->label + 1;
                for (; i < 128; i++) {
                    if (black_label[i] > 0) {
                        emin = i;
                        break;
                    }
                }
                if (i == 128)
                    emin = -1;
            }

        }

    }
    rte_free(bd);
    return 0;
}

int black_domain_add(hash_table * tb, char *domain)
{
    black_domain *bd = get_black_domain(domain);
    if (bd == NULL)
        return -1;
    _black_domain_add(tb, bd);
    return 0;
}

static int load_blacklist(int id)
{
    hash_table *ptb = NULL;
    assert(black_htb[id] == NULL);
    if (cur_htb == heap[1])
        ptb = heap[0];
    else
        ptb = heap[1];
/*    ALOG(SERVER, INFO, "Now begin load blacklist n from file %s",
         BLACKLISTN_FILE);*/
    FILE *fp = fopen(BLACKLISTN_FILE, "r");
    if (!fp) {
        ALOG(SERVER, ERROR, "Open blacklist file %s fail", BLACKLISTN_FILE);
        return -1;
    }
    //ALOG(SERVER, INFO, "Open blacklist N file %s ok", BLACKLISTN_FILE);
    char *line = NULL;
    size_t len = 0;
    int header = 0;
    while (getline(&line, &len, fp) != -1) {
        if (!header) {
            fix_line2(line);
            if (strcmp(DATA_OK_FLAG, line) == 0) {
                header = 1;
                ALOG(SERVER, INFO,
                     "header ok,now refresh blacklist N data from file %s",
                     BLACKLISTN_FILE);
            }
/*            ALOG(SERVER, INFO, "DATA[%s],line[%s],head=%d", DATA_OK_FLAG, line,
                 header);*/
            continue;
        }

        if (black_domain_add(ptb, line) < 0) {
            ALOG(SERVER, ERROR, "black_domain_add %s fail in %s", line,
                 __func__);
        }

    }

    fclose(fp);
    black_htb[id] = ptb;

    //ALOG(SERVER, INFO, "load blacklist N data done");

    return 0;
}

int init_blacklist()
{
    heap[0] = create_tb("blacklist_hash_table_0");
    if (heap[0] == NULL)
        return -1;
    heap[1] = create_tb("blacklist_hash_table_1");
    if (heap[1] == NULL)
        return -1;
    black_htb[0] = black_htb[1] = NULL;
    load_blacklist(0);

    if (black_htb[0] == NULL)
        black_htb[0] = heap[0];
    cur_htb = black_htb[0];
    rte_wmb();
    return 0;
}

static void free_htable(int id)
{

    if (black_htb[id] == NULL) {
        return;
    }

    int i;
    for (i = 0; i < BLACKLISTN_HASH_SIZE; i++) {
        hash_table *ht = black_htb[id] + i;
        while (!(list_empty(&ht->list))) {
            assert(ht->size != 0);
            black_domain *b = list_first_entry(&ht->list, black_domain, list);
            ALOG(SERVER, INFO,
                 "Lcore %d : Del black_domain '%s' with hash %p ,hval %d ,i = %d done",
                 rte_lcore_id(), b->org_key, b->tb, b->hval, i);
            assert(b->tb == ht);
            put_black_domain(b);

        }
        assert(ht->size == 0);
    }
    black_htb[id] = NULL;
}

void charge_blacklist_state()   //only called at misc core
{
    assert(black_htb[0] != NULL || black_htb[1] != NULL);
    if (cur_htb == black_htb[0]) {
        free_htable(1);
        if (load_blacklist(1) == 0) {
            cur_htb = black_htb[1];
            rte_wmb();
        }
    } else {
        free_htable(0);
        if (load_blacklist(0) == 0) {
            cur_htb = black_htb[0];
            rte_wmb();
        }
    }
}

int black_domain_pkt(struct dns_packet *pkt)
{
    if (pkt->labels < emin)
        return 0;

    int ma = pkt->labels > emax ? emax : pkt->labels;
    int i;
    for (i = ma; i >= emin; i--) {
        int begin = pkt->labels - i;
        int addr = pkt->label_offset[begin];
        const uint8_t *k = pkt->qname + addr;
        uint8_t klen = pkt->qname_size - addr - 1;
        if (klen <= 0)
            return 0;
        uint32_t idx = hash_val(k, klen);
        hash_table *ht = cur_htb + idx;
        black_domain *e;
        list_for_each_entry(e, &ht->list, list) {
            if (klen != e->klen)
                continue;
            if (strncasecmp((const char *)k, (const char *)e->key, klen) != 0)
                continue;
            if (addr != 0)
                return 1;
        }
    }
    return 0;
}
