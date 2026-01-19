#include<stdint.h>
#include<stdlib.h>
#include <rte_jhash.h>
#include <rte_atomic.h>
#include <rte_timer.h>
#include <assert.h>
#include <arpa/inet.h>
#include"view.h"
#include "msg.h"
#include"bit.h"
#include"log.h"
#include "common.h"
#include "request.h"
#include "storage.h"
#include "user_config.h"
#include "stats.h"
#include "iplib.h"
#include "view_maps.h"

#define FORWARDER_HSZIE 10240

static hash_table *forwarder_hash_table[RTE_MAX_LCORE];
view_db_t *g_recs_views;
view_db_t *g_auth_views;
view_db_t *g_backup_views;
lcore_fwder_mgr g_fwder_mgr[RTE_MAX_LCORE];

static inline char *to_str_state(int state);
static inline void set_forwarder_state2(forwarder * f, uint8_t x);

uint32_t find_view_by_strip(char *ip) {
    uint32_t tip = inet_addr(ip);
    tip = Lntohl(tip);
    return ip_bitmap_get(tip, 0);
}

view_db_t *view_db_init(const char *name) {
    view_db_t *new_view_db = NULL;

    new_view_db = rte_zmalloc_socket(name, sizeof(view_db_t), 0,
            rte_socket_id());
    if (new_view_db == NULL) {
        RTE_LOG(ERR, LDNS, "Fail to create %s", name);
        return NULL;
    }
    //new_view_db->all_view_state = UP;

    return new_view_db;
}

int view_init() {
    int lcore_id;

    g_recs_views = view_db_init("recs_view_db");
    if (g_recs_views == NULL) {
        return -1;
    }
    g_recs_views->srv_type = SRV_TYPE_REC;

    g_auth_views = view_db_init("auth_view_db");
    if (g_auth_views == NULL) {
        return -1;
    }
    g_auth_views->srv_type = SRV_TYPE_AUTH;

    g_backup_views = view_db_init("backup_view_db");
	if (g_backup_views == NULL) {
		return -1;
	}
	g_backup_views->srv_type = SRV_TYPE_REC;

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        char name[30];
        sprintf(name, "forwarder_hash_table_%d", lcore_id);
        forwarder_hash_table[lcore_id] =
            rte_zmalloc_socket(name, FORWARDER_HSZIE * sizeof(hash_table), 0,
                    rte_socket_id());
        if (forwarder_hash_table[lcore_id] == NULL) {
            RTE_LOG(ERR, LDNS, "Fail to create %s", name);
            return -1;
        }

        int i;
        for (i = 0; i < FORWARDER_HSZIE; i++) {
            hash_table *t = forwarder_hash_table[lcore_id] + i;
            INIT_LIST_HEAD((&t->list));
        }
        g_fwder_mgr[lcore_id].nums = 0;
        INIT_LIST_HEAD(&g_fwder_mgr[lcore_id].list);
    }

    return 0;
}

void add_view_basic(uint32_t vid) {
    g_recs_views->view_list[vid].state = UP;
    g_recs_views->view_list[vid].id = vid;
    g_auth_views->view_list[vid].state = UP;
    g_auth_views->view_list[vid].id = vid;
	g_backup_views->view_list[vid].state = UP;
	g_backup_views->view_list[vid].id = vid;
    //set_all_bit(views->view_list[vid].fbitmap, 0,
    //        sizeof(views->view_list[vid].fbitmap));

}

void set_view_backup(view_db_t * views, uint32_t vid, uint32_t backup_id) {
    view *v = &views->view_list[vid];
    v->backup_id = backup_id;
}

void show_view(view_db_t * views, uint32_t id) {
    view *v = &views->view_list[id];
    printf("---------show view[%d]---------\n", id);
    printf("\t[Name]:%s\n", view_id_to_name(id));
    printf("\t[Type]:%d\n", views->srv_type);
    printf("\t[backup]:%s\n", view_id_to_name(v->backup_id));
    printf("\t[ID]:%d\n", v->id);
    printf("\t[state]:%d\n", v->state);
    printf("\t[Forward_nums]:%d\n", v->fnums);

    uint8_t i;
    for (i = 0; i < v->fnums; i++) {
        uint32_t tip = v->fip[i];
        uint32_t fport = v->fport[i];
        int state = find_bit(v->fbitmap, i);
        PRINTF("\t[Forward]:%d.%d.%d.%d:%d health state %d\n", HIP_STR(tip),
               fport, state);
    }
    printf("\n");
}

const char *get_lcore_view_name(uint32_t id) {
    int lcore_id = rte_lcore_id();
    if (id == COMMON_VIEW_ID)
        return "SHAREVIEW";
    if (id >= g_view_nums) {
        printf("Lcore %d : Error,view count is %d,but id para is %d in %s\n",
               lcore_id, g_view_nums, id, __func__);
        //assert(0);
    }
    return view_id_to_name(id);
}

void show_all_view(view_db_t * views) {
    uint32_t i;
    for (i = 0; i < g_view_nums; i++) {
        show_view(views, i);
    }
}

static inline uint32_t hash_val(const uint8_t * p, int size) {
    return (rte_jhash(p, size, JHASH_INITVAL) & (FORWARDER_HSZIE - 1));
}

int forward_add_view(view_db_t * views, uint32_t ip, uint16_t port,
        uint32_t vid, int lcore_id) {
    int socket = rte_lcore_to_socket_id(lcore_id);
    forwarder *f = rte_zmalloc_socket(NULL, sizeof(forwarder), 0, socket);
    if (f == NULL) {
        RTE_LOG(ERR, LDNS, "Fail to rte_zmalloc in %s at socket %d", __func__,
                socket);
        return -1;
    }
    f->ip = ip;
    f->port = port;
    f->bkup_count = 0;
    f->views = views;
    memset(f->bkup_id, 0, sizeof(f->bkup_id));
    INIT_LIST_HEAD((&f->fwder_list));
    uint32_t idx = hash_val((uint8_t *) f, 6);
    hash_table *tb = forwarder_hash_table[lcore_id] + idx;
    forwarder *tmp;
    int exist = 0;
    int i;
    list_for_each_entry(tmp, &tb->list, list) {
        if (tmp->ip == f->ip && tmp->port == f->port) {
            for (i = 0; i < tmp->view_count; i++) {
                if (tmp->view_id[i] == vid) {
                    exist = 1;
                    break;
                }
            }
            tmp->view_id[tmp->view_count++] = vid;
            exist = 1;
            break;
        }
    }

    if (!exist) {
        list_add_tail(&f->list, &tb->list);
        list_add_tail(&f->fwder_list, &g_fwder_mgr[lcore_id].list);
        g_fwder_mgr[lcore_id].nums++;
        f->view_id[f->view_count++] = vid;
        tb->size++;
    } else {
        rte_free(f);
    }
    return 0;
}

forwarder *get_forwarder(uint32_t ip, uint16_t port) {
    int lcore_id = rte_lcore_id();
    forwarder f;
    f.ip = ip;
    f.port = port;
    uint32_t idx = hash_val((uint8_t *) & f, 6);
    hash_table *tb = forwarder_hash_table[lcore_id] + idx;
    forwarder *tmp;
    list_for_each_entry(tmp, &tb->list, list) {
        if (tmp->ip == f.ip && tmp->port == f.port)
            return tmp;
    }
    return NULL;
}

static inline char *to_str_state(int state) {
    if (state == DOWN)
        return "down";
    return "up";
}

/*
static inline  void set_all_view_state(view_db_t * views, uint16_t x) {
    if(views->all_view_state == x)
        return;

    STATS(ALL_VIEW_DOWN);
    //ALOG(SERVER, WARN, "Lcore %d Set all view %s\n", lcore_id, to_str_state(x));
    views->all_view_state = x;
}
*/

static inline void clear_view_backup(view_db_t * views, uint32_t vid,
        uint32_t bkup_vid) {
    view *bv = &views->view_list[bkup_vid];
    int i, j;
    for (i = 0; i < bv->fnums; i++) {
        uint32_t ip = bv->fip[i];
        uint16_t port = bv->fport[i];
        forwarder *f = get_forwarder(ip, port);
        assert(f != NULL);
        for (j = 0; j < f->bkup_count; j++) {
            if (f->bkup_id[j] == vid) {
                //move the back to front
                while (j + 1 < f->bkup_count) {
                    f->bkup_id[j] = f->bkup_id[j + 1];
                    j++;
                }
                f->bkup_count--;
                break;
            }
        }

    }

}

static inline void set_view_state(view_db_t * views, uint32_t vid, uint8_t x) {
    //int up = 0, i;
    int lcore_id = rte_lcore_id();
    view *v = &views->view_list[vid];
    //ALOG(SERVER,WARN,"Lcore %d : Set view %s %s",lcore_id,v->name,to_str_state(x));
    if (x == DOWN) {
        if (!find_bit(views->vstate_bitmap[lcore_id], vid)) {
            /* only first from UP to DOWN should print log */
            //ALOG(SERVER, ERROR, "Lcore %d : Set view %s DOWN", lcore_id, v->name);
            VSTATS(vid, VFWD_DOWN);
            set_bit(views->vstate_bitmap[lcore_id], vid);
        }
    } else {
        if (find_bit(views->vstate_bitmap[lcore_id], vid)) {  /* else some core had set v and v's bakcup to UP */
            /* FROM DOWN TO UP */
            clear_bit(views->vstate_bitmap[lcore_id], vid);
            clear_view_backup(views, vid, v->backup_id);
            if (v->backup_id != 0)
                clear_view_backup(views, vid, 0);
        }
    }

    if (x == v->state) {
        return;
    }
    v->state = x;

    /*
    if (x == UP) {
        set_all_view_state(views, UP);
        return;
    }
    // if x == DOWN
    for (i = 0; i < g_view_nums; i++) {
        if (!is_bad_view(views, i)){
            up = 1;
            break;
        }
    }
    if (!up)
        set_all_view_state(views, DOWN);
    */
}

static inline void set_forwarder_state2(forwarder *f, uint8_t x) {
    int i = 0, j;

    if (x == DOWN) {
        int max = 1000;
        f->down = f->down + 1;
        if (f->down > max)
            f->down = max;
        //ALOG(SERVER,WARN,"Lcore %d Set forwarder %d.%d.%d.%d:%d down(%d/%d)\n",lcore_id,HIP_STR(f->ip),f->port,f->down,g_forwarder_fail_down);
        if (f->down != g_forwarder_fail_down)
            return;
        //down
        STATS(FWD_DOWN);
/*        ALOG(SERVER, WARN,
             "Lcore %d Real ---- Set forwarder %d.%d.%d.%d:%d down", lcore_id,
             HIP_STR(f->ip), f->port);*/
        //enqueue_timer(f);
        for (i = 0; i < f->view_count; i++) {
            int vid = f->view_id[i];
            view *v = &f->views->view_list[vid];
            int up = 0;
            for (j = 0; j < v->fnums; j++) {
                if (v->fip[j] == f->ip && v->fport[j] == f->port) {
                    clear_bit(v->fbitmap, j);   //bad
                    if (up)
                        break;
                } else if (find_bit(v->fbitmap, j))
                    up = 1;
            }
            if (!up)
                set_view_state(f->views, vid, DOWN);

        }
        return;
    }
    // if x == UP

    if (f->down < g_forwarder_fail_down) {
        f->down = 0;
        return;
    }

    f->down = 0;

    //down to up
    for (i = 0; i < f->view_count; i++) {
        int vid = f->view_id[i];
        view *v = &f->views->view_list[vid];
        for (j = 0; j < v->fnums; j++) {
            if (v->fip[j] == f->ip && v->fport[j] == f->port) {
                set_bit(v->fbitmap, j);
            }
        }
        set_view_state(f->views, vid, UP);
    }
}

void set_forwarder_state(uint32_t ip, uint16_t port, uint8_t x)
{
    forwarder *f = get_forwarder(ip, port);
    if (f == NULL)
        return;

    set_forwarder_state_f(f, x);
}

void set_forwarder_state_f(forwarder *f, uint8_t x) {
    int need_send = 1;
    if (x == UP && f->down == 0)
        need_send = 0;
    if (x == DOWN && f->down > g_forwarder_fail_down)
        need_send = 0;
    if (need_send == 0) {
        if (random() % 10 == 1)
            need_send = 1;
    }

    if (need_send) {
        int kid = 0;
        int lcore_id = rte_lcore_id();
        forwarder_state fs;
        fs.ip = f->ip;
        fs.port = f->port;
        fs.state = x;
        struct lcore_msg_info *msg =
            get_cmd_msg_info(MSG_FORWARDER_STATE, sizeof(fs), &fs);
        if (msg != NULL) {
            get_cmd_msg(msg);
            for (kid = 0; kid < gio_count; kid++) {
                if (gio_id[kid] != lcore_id) {
                    send_cmd_msg(msg, gio_id[kid]);
                }
            }
            put_cmd_msg(msg);
        }
    }
    set_forwarder_state2(f, x);
}

void lcore_forwarder_state_share(uint8_t * msg, int msg_len)
{
    forwarder_state *fs = (forwarder_state *) msg;
    forwarder *f = get_forwarder(fs->ip, fs->port);

    set_forwarder_state2(f, fs->state);
}
