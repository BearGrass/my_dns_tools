#ifndef _ADNS_ADMIN_H_
#define _ADNS_ADMIN_H_


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <rte_atomic.h>


#include "net.h"
#include "list.h"
#include "ae.h"
#include "view_maps.h"
#include "networking.h"


#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define EVENT_SET_SIZE 1024
#define ADNS_ADM_MAX_REPLY_LEN (1<<16) /* the real limit, for only 2 Bytes space for msg length*/

#define DNS_BIND_PORT 5858
#define DNS_CMD_PORT  5353


typedef void adnsCommandProc(ioClient *c);
struct adnsCommand {
    int opcode;
    char *desc;
    int flags;
    adnsCommandProc *proc;
};


extern char *g_req_buf;
extern uint32_t g_req_len;
extern int g_init_done;
extern int g_exit_now;


extern int iplib_load_init(void);
extern int parse_view_map(char *file, int view_max_num, struct adns_view_map *tbl, int *view_nums);
extern size_t parse_log_rotate_max_size(const char *name);
extern uint32_t parse_log_rotate_max_count(const char *name);


int update_master(ioClient *c, struct adnsCommand *cmd);
struct adnsCommand *adns_lookup_cmd(int opcode);
int adns_rcode_counter_init();
int adns_drop_pkt_counter_init();
int admin_init();
void admin_cleanup();
char * admin_client_extbuf_get();
void admin_client_extbuf_put(char * client);
int admin_init_client_extbuf_pool(void);

#endif


