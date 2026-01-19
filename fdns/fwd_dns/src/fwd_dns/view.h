#ifndef _DEF_VIEW_
#define _DEF_VIEW_
#include <stdint.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <arpa/inet.h>

#include "list.h"
#include "view_maps.h"

#define VIEW_OK 0
#define VIEW_BAD 1
#define VIEW_FORWARDS_MAX 256
#define VIEW_FORWARDS_BITMAP_SIZE VIEW_FORWARDS_MAX/8
#define VIEW_MAX_COUNT 512
#define VIEW_BITMAP_SIZE VIEW_MAX_COUNT/8
#define JHASH_INITVAL 0x1234
#define VIEW_NAME_MAX 128

#define DOWN 0
#define UP 1
typedef struct view_t{
    /*views is avaliable ?*/
    uint8_t state;

    /*next forwarder begin idx in select forwarder function*/
    uint8_t next_id;

    /*view's forwarder count*/
    uint8_t fnums;

    /*each forwarder health state*/
    uint8_t fbitmap[VIEW_FORWARDS_BITMAP_SIZE];

    /*view id*/
    uint32_t id;

    /*view backup id*/
    uint32_t backup_id;

    /*view recursion ip filled in ECS*/
    uint32_t ecs_ip;

    /*forwarder ip*/
    uint32_t fip[VIEW_FORWARDS_MAX];

    /*forwarder port*/
    uint32_t fport[VIEW_FORWARDS_MAX];
} __rte_cache_aligned view;

typedef struct view_db {
    view view_list[VIEW_MAX_COUNT];
    uint8_t vstate_bitmap[RTE_MAX_LCORE][VIEW_BITMAP_SIZE];
    //uint8_t all_view_state;
    uint8_t srv_type;
} view_db_t;

typedef struct forwarder_t {
    uint32_t ip;
    uint16_t port;
    uint16_t down;
    uint32_t view_count;
    uint32_t view_id[VIEW_MAX_COUNT];
    uint32_t bkup_id[VIEW_MAX_COUNT];
    uint32_t bkup_count;
    struct list_head list;
    struct list_head fwder_list;
    uint64_t ctime;
    /*view db this forwarder belongs to*/
    view_db_t *views;
}forwarder;

typedef struct forwarder_state_t{
    uint32_t ip;
    uint16_t port;
    uint8_t state;
}forwarder_state;


typedef struct _lcore_fwder_mgr{
    struct list_head list;
    int nums;
}lcore_fwder_mgr;


extern lcore_fwder_mgr g_fwder_mgr[RTE_MAX_LCORE];
extern view_db_t *g_recs_views;
extern view_db_t *g_auth_views;
extern view_db_t *g_backup_views;

static inline uint8_t is_bad_view(view_db_t *views, uint32_t vid)
{
    view *v = &views->view_list[vid];
    return (v->state == DOWN);
}

/*
static inline uint16_t is_all_bad_view(view_db_t *views)
{
    return (views->all_view_state == DOWN);
}
*/

extern void show_all_view();
extern void show_view(view_db_t *views, uint32_t id);
extern int view_init();
extern const char * get_lcore_view_name(uint32_t id);
extern void set_forwarder_state(uint32_t ip,uint16_t port,uint8_t x);
extern void set_forwarder_state_f(forwarder *f, uint8_t x);

extern void add_view_basic(uint32_t vid);
extern void set_view_backup(view_db_t *views, uint32_t vid, uint32_t backup_id);
extern uint32_t find_view_by_ipv6(struct in6_addr client_ipv6);
extern uint32_t find_view_by_strip(char *ip);
extern int forward_add_view(view_db_t * views, uint32_t ip, uint16_t port,
        uint32_t vid, int lcore_id);
extern forwarder * get_forwarder(uint32_t ip,uint16_t port);
extern void lcore_forwarder_state_share(uint8_t *msg,int msg_len);
#endif
