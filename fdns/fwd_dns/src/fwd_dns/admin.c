
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rte_spinlock.h>
#include <rte_mempool.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_atomic.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_string_fns.h>

#include "log.h"
#include "ldns.h"
#include "ae.h"
#include "msg.h"
#include "fwdctl_share.h"
#include "anet.h"
#include "admin.h"
#include "networking.h"
#include "common.h"
#include "stats.h"
#include "iplib.h"
#include "dnscache.h"
#include "dnscache_tbl.h"
#include "view.h"
#include "view_maps.h"
#include "request.h"
#include "storage.h"
#include "user_config.h"
#include "bit.h"
#include "qos.h"
#include "adns_log.h"
#include "fwd_user.h"
#include "fwd_user_db.h"
#include "snapshot.h"

int g_init_done = 0;

static void fwd_stats(ioClient * c);
static void fwd_req_stats(ioClient * c);
static void fwd_drop_stats(ioClient * c);
static void fwd_view_stats(ioClient * c);
static void fwd_prefetch_stats(ioClient * c);
static void fwd_set_log(ioClient * c);
static void fwd_set_view_backup(ioClient * c);
static void fwd_del_key(ioClient * c);
static void fwd_delreg_keys(ioClient * c);
static void fwd_denydns_keys(ioClient * c);
static void fwd_nodenydns_keys(ioClient * c);
static void reset_stats(ioClient * c);
static void fwd_version(ioClient * c);
static void fwd_view_nodes(ioClient * c);
static void fwd_view_state(ioClient * c);
static void fwd_dns_state(ioClient * c);
static void fwd_dns_cnts(ioClient * c);
static void nodes_ttl_threshold(ioClient * c);
static void fwd_cpu_stats(ioClient * c);
static void fwd_memory_info(ioClient * c);
static void fwd_set_oversea_status(ioClient * c);
static void fwd_set_black_status(ioClient * c);
static void fwd_set_white_status(ioClient * c);
static void fwd_set_man_white_status(ioClient * c);
static void fwd_set_man_black_status(ioClient * c);
static void fwd_set_lcore_share_status(ioClient *c);
static void fwd_load_iplib(ioClient *c);
static void fwd_fwd_qps_ctl(ioClient *c);
static void fwd_cache_stats(ioClient *c);
//static void fwd_dnscache_batch(ioClient *c);
static void fwd_dnscache_batch_update(ioClient *c);
static void fwd_dnscache_batch_set(ioClient *c);
static void fwd_dnscache_list_domain(ioClient *c);
static void fwd_dnscache_list_detail(ioClient *c);
static void fwd_export_snapshot(ioClient *c);
static void fwd_import_snapshot(ioClient *c);

static void fwd_dnscache_get_queue_offset(ioClient *c);
static void fwd_dnscache_set_queue_offset(ioClient *c);

static void fwd_user_batch_set(ioClient *c);
static void fwd_user_list(ioClient *c);

static void fwd_user_get_queue_offset(ioClient *c);
static void fwd_user_set_queue_offset(ioClient *c);

static void fwd_init_load(ioClient *c);
static void fwd_init_show(ioClient *c);

static int fwd_init_load_file(char *filepath);

static struct mem_info_t g_mem_info;

static struct adnsCommand adnsCommandTable[] = {
    {RNDC_START, "Start name server", 0, rndc_reload_cb},
    {FWD_STATS, "Stats forward dns", 0, fwd_stats},
    {FWD_GET_VERSION, "forward dns version", 0, fwd_version},
    {FWD_REQ_STATS, "Stats request forward dns", 0, fwd_req_stats},
    {FWD_DROP_STATS, "Stats drop forward dns", 0, fwd_drop_stats},
    {FWD_VIEW_STATS, "Stats view forward dns", 0, fwd_view_stats},
    {FWD_VIEW_NODES, "Stats view forward dns nodes", 0, fwd_view_nodes},
    {FWD_VIEW_STATE, "view health state", 0, fwd_view_state},
    {FWD_DNS_STATE, "L2 DNS state", 0, fwd_dns_state},
    {FWD_DNS_CNTS, "forward dns raw counters", 0, fwd_dns_cnts},
    {FWD_CACHE_STATE, "states cache", 0, fwd_cache_stats},
    {FWD_CPU_UTIL, "CPU util", 0, fwd_cpu_stats},
    {FWD_MEMORY_INFO, "memory info", 0, fwd_memory_info},
    {FWD_SET_VIEW_NODES_TTL_THRESHOLD, "Set view ttl fetch threshold", 0,
     nodes_ttl_threshold},
    {FWD_PREFETCH_STATS, "Stats view forward dns", 0, fwd_prefetch_stats},
    {FWD_STATSRESET, "Stats reset", 0, reset_stats},
    {FWD_SET_LOG, "Set forward dns log", 0, fwd_set_log},
    {FWD_SET_BACKUP, "Set forward view backup", 0, fwd_set_view_backup},
    {FWD_DEL, "DEL forward view key/type", 0, fwd_del_key},
    {FWD_DEL_REG, "DEL forward view keys match regex", 0, fwd_delreg_keys},
    {FWD_DENY_DNS_START, "start proctect keys which match regex ", 0,
     fwd_denydns_keys},
    {FWD_DENY_DNS_STOP, "remove protected method ", 0, fwd_nodenydns_keys},
    {FWD_SET_OVERSEA_STATUS, "set oversea status ", 0, fwd_set_oversea_status},
    {FWD_SET_BLACK_STATUS, "set_black_status ", 0, fwd_set_black_status},
    {FWD_SET_WHITE_STATUS, "set_white_status ", 0, fwd_set_white_status},
    {FWD_SET_MAN_WHITE_STATUS, "set_man_white_status ", 0, fwd_set_man_white_status},
    {FWD_SET_MAN_BLACK_STATUS, "set_man_black_status ", 0, fwd_set_man_black_status},
    {FWD_SET_SHARE_STATUS,"set_lcore_data_share_status ",0,fwd_set_lcore_share_status},
    {FWD_SET_IPLIB, "reload_ip_lib", 0, fwd_load_iplib},
    {FWD_SET_KNI_QPS_LIMIT_NUM, "set kni qps limit number", 0, fwd_fwd_qps_ctl},
    {FWD_BATCH_DNSCACHE_UPDATE, "batch update dnscache data", 0, fwd_dnscache_batch_update},
    {FWD_BATCH_DNSCACHE_SET, "batch set dnscache data", 0, fwd_dnscache_batch_set},
    {FWD_LIST_DNSCACHE_DOMAIN, "list dnscache domain", 0, fwd_dnscache_list_domain},
    {FWD_LIST_DNSCACHE_DETAIL, "list dnscache data", 0, fwd_dnscache_list_detail},
    {FWD_GET_DNSCACHE_KAFKA_OFFSET, "set queue offset", 0, fwd_dnscache_get_queue_offset},
    {FWD_SET_DNSCACHE_KAFKA_OFFSET, "echo queue offset", 0, fwd_dnscache_set_queue_offset},
    {FWD_INIT_LOAD_DATA, "init load data", 0, fwd_init_load},
    {FWD_INIT_SHOW_STATUS, "show init status", 0, fwd_init_show},
    {FWD_EXPORT_SNAPSHOT, "export dnscache snapshot", 0, fwd_export_snapshot},
    {FWD_IMPORT_SNAPSHOT, "import dnscache snapshot", 0, fwd_import_snapshot},
    {FWD_USER_BATCH_SET, "batch set user's information", 0, fwd_user_batch_set},
    {FWD_USER_LIST, "list user's information", 0, fwd_user_list},
    {FWD_GET_USER_QUEUE_OFFSET, "get user queue offset", 0, fwd_user_get_queue_offset},
    {FWD_SET_USER_QUEUE_OFFSET, "set user queue offset", 0, fwd_user_set_queue_offset},
};

struct adnsCommand *adns_lookup_cmd(int opcode)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(adnsCommandTable); i++) {
        if (adnsCommandTable[i].opcode == opcode)
            return &adnsCommandTable[i];
    }

    return NULL;
}

static char *view_state_str(int f)
{
    if (f == 0)
        return "UP";
    else
        return "DOWN";
}

static char *fwder_state_str(int f)
{
    if (f == 0)
        return "UP";
    else
        return "DOWN";
}

static void generate_view_state(char *buf, int head)
{
    int i;
    int worker_num = 0;
    int worker[RTE_MAX_LCORE];
    struct lcore_params *lp;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO) {
            worker[worker_num++] = i;

        }
    }
    assert(worker_num != 0);

    char line[200];
    if (head) {
        sprintf(line, "forward_workers_num: %02d\r\n", worker_num);
        strcat(buf, line);

        int y, m, d, H, M, S;
        struct tm *ptm;
        long ts = time(NULL);
        ptm = localtime(&ts);
        y = ptm->tm_year + 1900;
        m = ptm->tm_mon + 1;
        d = ptm->tm_mday;
        H = ptm->tm_hour;
        M = ptm->tm_min;
        S = ptm->tm_sec;
        sprintf(line,
                "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
                ts, y, m, d, H, M, S);
        strcat(buf, line);
    }

    sprintf(line, "------------VIEW HEALTH STATE-----------\r\n");
    strcat(buf, line);

    sprintf(line, "%-25s|%-25s|%-8d|%-8d|%-8d|%-8d|%-8d|%-8d|%-8d\r\n",
            "view_name", "bkup", worker[0], worker[1], worker[2], worker[3],
            worker[4], worker[5], worker[6]);

    strcat(buf, line);

    for (i = 0; i < g_view_nums; i++) {
        sprintf(line, "%-25s|%-25s|%-8s|%-8s|%-8s|%-8s|%-8s|%-8s|%-8s\r\n",
                view_id_to_name(i),
                view_id_to_name(g_recs_views->view_list[i].backup_id),
                view_state_str(find_bit(g_recs_views->vstate_bitmap[worker[0]], i)),
                view_state_str(find_bit(g_recs_views->vstate_bitmap[worker[1]], i)),
                view_state_str(find_bit(g_recs_views->vstate_bitmap[worker[2]], i)),
                view_state_str(find_bit(g_recs_views->vstate_bitmap[worker[3]], i)),
                view_state_str(find_bit(g_recs_views->vstate_bitmap[worker[4]], i)),
                view_state_str(find_bit(g_recs_views->vstate_bitmap[worker[5]], i)),
                view_state_str(find_bit(g_recs_views->vstate_bitmap[worker[6]], i))
            );
        strcat(buf, line);
    }
    sprintf(line, "------------VIEW HEALTH STATE END-----------\r\n");
    strcat(buf, line);
}

static void generate_dns_cnts(char *buf, int buf_size)
{
    int i;
    int worker_num = 0;
    int worker[RTE_MAX_LCORE];
    memset(worker, 0, sizeof(worker));
    struct lcore_params *lp;
    size_t used_len = 0;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO || lp->type == e_LCORE_KNI) {
            worker[worker_num++] = i;

        }
    }
    assert(worker_num != 0);
    used_len += snprintf(buf + used_len, buf_size - used_len,
            "forward_workers_num: %02d\r\n", worker_num);

    int y, m, d, H, M, S;
    struct tm *ptm;
    long ts = time(NULL);
    ptm = localtime(&ts);
    y = ptm->tm_year + 1900;
    m = ptm->tm_mon + 1;
    d = ptm->tm_mday;
    H = ptm->tm_hour;
    M = ptm->tm_min;
    S = ptm->tm_sec;
    used_len += snprintf(buf + used_len, buf_size - used_len,
            "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
            ts, y, m, d, H, M, S);

    used_len += snprintf(buf + used_len, buf_size - used_len,
            "------------RAW COUNTERS-----------\r\n");

    used_len += snprintf(buf + used_len, buf_size - used_len,
            "%-15s|%-17d|%-17d|%-17d|%-17d|%-17d|%-17d|%-17d|%-17d\r\n",
            "cnt_name", worker[0], worker[1], worker[2], worker[3], worker[4],
            worker[5], worker[6], worker[7]);

    for (i = 0; i < LCORE_STATS_MAX; i++) {
        used_len += snprintf(buf + used_len, buf_size - used_len,
                        "%-15s|%-17lu|%-17lu|%-17lu|%-17lu|%-17lu|%-17lu|%-17lu|%-17lu\r\n",
                        fdns_stats_id_to_name(i), lcore_stats[worker[0]][i],
                        lcore_stats[worker[1]][i], lcore_stats[worker[2]][i],
                        lcore_stats[worker[3]][i], lcore_stats[worker[4]][i],
                        lcore_stats[worker[5]][i], lcore_stats[worker[6]][i],
                        lcore_stats[worker[7]][i]);
    }
    used_len += snprintf(buf + used_len, buf_size - used_len,
            "------------RAW COUNTERS END-----------\r\n");
}

static void generate_dns_state(char *buf, int head)
{
    int i, j, k;

    assert(gio_count != 0);

    char line[1024];
    if (head) {
        sprintf(line, "forward_workers_num: %02d\r\n", gio_count);
        strcat(buf, line);

        int y, m, d, H, M, S;
        struct tm *ptm;
        long ts = time(NULL);
        ptm = localtime(&ts);
        y = ptm->tm_year + 1900;
        m = ptm->tm_mon + 1;
        d = ptm->tm_mday;
        H = ptm->tm_hour;
        M = ptm->tm_min;
        S = ptm->tm_sec;
        sprintf(line,
                "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
                ts, y, m, d, H, M, S);
        strcat(buf, line);
    }

    sprintf(line, "------------DNS HEALTH STATE-----------\r\n");
    strcat(buf, line);

    sprintf(line,
            "IP:PORT(ALL COUNT %d) | cpu[%d] |cpu[%d] [view list which has the ip:port configure]\r\n",
            g_fwder_mgr[gio_id[0]].nums, gio_id[0], gio_id[1]);
    strcat(buf, line);

    struct list_head *cur[gio_count];
    for (i = 0; i < gio_count; i++) {
        if (g_fwder_mgr[gio_id[i]].nums == 0)
            return;
        cur[i] = &g_fwder_mgr[gio_id[i]].list;
        assert(cur[i] != cur[i]->next);
        cur[i] = cur[i]->next;
        if (g_fwder_mgr[gio_id[i]].nums != g_fwder_mgr[gio_id[0]].nums) {
            char tmp[100];
            memset(tmp, 0, sizeof(tmp));
            sprintf(tmp, "----L2DNS at core %d not equal to core %d---\r\n",
                    gio_id[i], gio_id[0]);
            strcat(buf, tmp);
            strcat(buf, "---Please retry later,may not init compelete---\r\n");
            return;

        }
    }

    uint32_t ip[gio_count];
    uint16_t port[gio_count];
    int state[gio_count];
    const int M = 1024;

    char vlist[M];
    for (i = 0; i < g_fwder_mgr[gio_id[0]].nums; i++) {
        memset(vlist, 0, sizeof(vlist));
        for (j = 0; j < gio_count; j++) {
            forwarder *f = list_entry(cur[j], forwarder, fwder_list);
            ip[j] = f->ip;
            port[j] = f->port;
            if (f->down >= g_forwarder_fail_down)
                state[j] = 1;
            else
                state[j] = 0;
            cur[j] = cur[j]->next;
            if (j == 0) {
                for (k = 0; k < f->view_count; k++) {
                    if (strlen(vlist) > 2 * M / 3) {
                        strcpy(vlist, "Too many");
                        break;
                    }
                    if (k != 0)
                        strcat(vlist, ",");
                    strcat(vlist, view_id_to_name(f->view_id[k]));
                }
            }
            assert(ip[j] == ip[0]);
            assert(port[j] == port[0]);
        }
        SPRINTF(line, "%d.%d.%d.%d:%d |%-5s|%-5s|%-5s [%s]\r\n",
                HIP_STR(ip[0]), port[0],
                fwder_state_str(state[0]), fwder_state_str(state[1]), fwder_state_str(state[gio_count - 1]), vlist);
        strcat(buf, line);
    }

    strcat(buf, "----SENDOVER----\n");
}

static void generate_view_stats(char *buf, int head)
{
    int i, j;
    int worker_num = 0;
    int worker[RTE_MAX_LCORE];
    struct lcore_params *lp;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO || lp->type == e_LCORE_KNI) {
            worker[worker_num++] = i;

        }
    }
    assert(worker_num != 0);

    char line[200];
    if (head) {
        sprintf(line, "forward_workers_num: %02d\r\n", worker_num);
        strcat(buf, line);

        int y, m, d, H, M, S;
        struct tm *ptm;
        long ts = time(NULL);
        ptm = localtime(&ts);
        y = ptm->tm_year + 1900;
        m = ptm->tm_mon + 1;
        d = ptm->tm_mday;
        H = ptm->tm_hour;
        M = ptm->tm_min;
        S = ptm->tm_sec;
        sprintf(line,
                "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
                ts, y, m, d, H, M, S);
        strcat(buf, line);
    }

    sprintf(line, "------------VIEW STATS-----------\r\n");
    strcat(buf, line);
    sprintf(line,
            "%-22s|%-22s|%-16s|%-16s|%-16s|%-16s|%-16s|%-16s|%-16s|%-16s\r\n",
            "view_name", "backup_view", "in_req", "master_req", "slave_req",
            "backup_in_req", "backup_out_req", "hit_req", "fwd_req",
            "fwd_timeout");
    strcat(buf, line);

    uint64_t stats[VIEW_MAX_COUNT][VS_MAX];
    memset(stats, 0, sizeof(stats));
    for (i = 0; i < g_view_nums; i++) {
        for (j = 0; j < worker_num; j++) {
            int lcore_id = worker[j];
            stats[i][VIN_REQ] += lcore_vstats[lcore_id][i][VIN_REQ];
            stats[i][VMST_REQ] += lcore_vstats[lcore_id][i][VMST_REQ];
            stats[i][VSLV_REQ] += lcore_vstats[lcore_id][i][VSLV_REQ];
            stats[i][VBIN_REQ] += lcore_vstats[lcore_id][i][VBIN_REQ];
            stats[i][VBOUT_REQ] += lcore_vstats[lcore_id][i][VBOUT_REQ];
            stats[i][VHIT_REQ] += lcore_vstats[lcore_id][i][VHIT_REQ];
            stats[i][VFWD_REQ] += lcore_vstats[lcore_id][i][VFWD_REQ];
            stats[i][VFWD_TIMEOUT] += lcore_vstats[lcore_id][i][VFWD_TIMEOUT];
        }
        sprintf(line,
                "%-22s|%-22s|%-16lu|%-16lu|%-16lu|%-16lu|%-16lu|%-16lu|%-16lu|%-16lu\r\n",
                view_id_to_name(i), view_id_to_name(g_recs_views->view_list[i].backup_id),
                stats[i][VIN_REQ], stats[i][VMST_REQ], stats[i][VSLV_REQ],
                stats[i][VBIN_REQ], stats[i][VBOUT_REQ], stats[i][VHIT_REQ],
                stats[i][VFWD_REQ], stats[i][VFWD_TIMEOUT]
            );
        strcat(buf, line);
    }
    sprintf(line, "------------VIEW STATS END-----------\r\n");
    strcat(buf, line);
}

static void generate_view_nodes_stats(char *buf, int head)
{
    int i;
    int worker_num = 0;
    int worker[RTE_MAX_LCORE];
    memset(worker, 0, sizeof(worker));
    struct lcore_params *lp;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO) {
            worker[worker_num++] = i;

        }
    }
    assert(worker_num != 0);

    char line[200];
    if (head) {
        sprintf(line, "forward_workers_num: %02d\r\n", worker_num);
        strcat(buf, line);

        int y, m, d, H, M, S;
        struct tm *ptm;
        long ts = time(NULL);
        ptm = localtime(&ts);
        y = ptm->tm_year + 1900;
        m = ptm->tm_mon + 1;
        d = ptm->tm_mday;
        H = ptm->tm_hour;
        M = ptm->tm_min;
        S = ptm->tm_sec;
        sprintf(line,
                "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
                ts, y, m, d, H, M, S);
        strcat(buf, line);
    }

    sprintf(line, "------------VIEW NODES STATS-----------\r\n");
    strcat(buf, line);

    sprintf(line, "%-22s|%-15d|%-15d|%-15d|%-15d|%-15d|%-15d|%-15d\r\n",
            "view_name", worker[0], worker[1], worker[2], worker[3], worker[4],
            worker[5], worker[6]);

    strcat(buf, line);

    for (i = 0; i < g_view_nums; i++) {
        sprintf(line,
                "%-22s|%-15d|%-15d|%-15d|%-15d|%-15d|%-15d|%-15d\r\n",
                view_id_to_name(i), view_nodes[worker[0]][i],
                view_nodes[worker[1]][i], view_nodes[worker[2]][i],
                view_nodes[worker[3]][i], view_nodes[worker[4]][i],
                view_nodes[worker[5]][i], view_nodes[worker[6]][i]
            );
        strcat(buf, line);
    }
    sprintf(line, "------------VIEW NODES STATS END-----------\r\n");
    strcat(buf, line);
}

static void generate_cache_state(char *buf, int head)
{
    int i, j;
    int worker_num = 0;
    int worker[RTE_MAX_LCORE];
    struct lcore_params *lp;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO) {
            worker[worker_num++] = i;

        }
    }
    assert(worker_num != 0);

    char line[200];
    if (head) {
        sprintf(line, "forward_workers_num: %02d\r\n", worker_num);
        strcat(buf, line);

        int y, m, d, H, M, S;
        struct tm *ptm;
        long ts = time(NULL);
        ptm = localtime(&ts);
        y = ptm->tm_year + 1900;
        m = ptm->tm_mon + 1;
        d = ptm->tm_mday;
        H = ptm->tm_hour;
        M = ptm->tm_min;
        S = ptm->tm_sec;
        sprintf(line,
                "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
                ts, y, m, d, H, M, S);
        strcat(buf, line);
    }

    sprintf(line, "------------CACHE STATS-----------\r\n");
    strcat(buf, line);
    sprintf(line,
            "%-22s|%-22s|%-15s|%-15s|%-15s|\r\n",
            "view", "bkview", "node_new", "node_prefetch", "node_trust");
    strcat(buf, line);

    uint64_t stats[VIEW_MAX_COUNT][VS_MAX];
    memset(stats, 0, sizeof(stats));
    for (i = 0; i < g_view_nums; i++) {
        for (j = 0; j < worker_num; j++) {
            int lcore_id = worker[j];
            stats[i][VNODE_NEW] += lcore_vstats[lcore_id][i][VNODE_NEW];
            stats[i][VNODE_PREFETCH] += lcore_vstats[lcore_id][i][VNODE_PREFETCH];
            stats[i][VNODE_TRUST] += lcore_vstats[lcore_id][i][VNODE_TRUST];
        }
        sprintf(line, "%-22s|%-22s|%-15lu|%-15lu|%-15lu|\r\n",
                view_id_to_name(i), view_id_to_name(g_recs_views->view_list[i].backup_id),
                stats[i][VNODE_NEW], stats[i][VNODE_PREFETCH],
                stats[i][VNODE_TRUST]);
        strcat(buf, line);
    }
}

static inline int get_qps_type(const char *name) {
    int i;

    for(i = 0; i < FWD_QPSLIMIT_MAX_NUM; i++) {
        if (!strcmp(qpslimit_id_name_map[i], name)) {
            return i;
        }
    }

    return i;
}

static void fwd_fwd_qps_ctl(ioClient *c) {
    int ret = -1, i;
    memset(c->buf,0,sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    char *p = ((struct cmd_msg *)c->querybuf)->data, *pos;
    int quota, index = 0;
    char line[200];
    const char *qps_switch[2] = {"off", "on"};

    if (p == NULL) {
        strcat(reply_msg->data,"control qps limit err ");
        ret = -1;
        goto out;
    }

    pos = strstr(p,FWD_DEL_SPLIT);
    if(pos == NULL) {
        if (!strcmp(p, "show")) {
            sprintf(line, "\n------------KNI QPSLIMIT-----------\r\n");
            strcat(reply_msg->data, line);
            for (i = 0; i < FWD_QPSLIMIT_MAX_NUM; i ++) {
                sprintf(line, "%-10s:%-10d%-10s\n", qpslimit_id_name_map[i], g_fwd_qps_quota[i], qps_switch[g_fwd_qps_limit_on[i]]);
                strcat(reply_msg->data, line);
            }
            ret = 0;
            goto out;
        }
        strcat(reply_msg->data,"control qps limit Fail,no ");
        strcat(reply_msg->data,FWD_DEL_SPLIT);
        ret = -1;
        goto out;
    }

    *pos = '\0';
    /* jump to next entry */
    pos = pos + strlen(FWD_DEL_SPLIT);
    quota = atoi(pos);
    if (quota == 0 && pos[0] != '0') {
        strcat(reply_msg->data," set qps limit err (quota must be a number)");
        ret = -1;
        goto out;
    }

    index = get_qps_type(p);
    if(index == FWD_QPSLIMIT_MAX_NUM) {
        strcat(reply_msg->data, " unsupported KNI QPS limit type");
        ret = -1;
        goto out;
    }

    //printf(reply_msg->data," set %s qps limit to %d success", p, quota);
    if (quota == 0) {
        g_fwd_qps_quota[index] = 0;
        g_fwd_qps_limit_on[index] = 0;
		if (index < IP_QPSLIMIT_ID) {
			g_kni_qps_limit_on_status &= ~(1 << index);
		}
    } else {
        g_fwd_qps_quota[index] = quota;
        g_fwd_qps_limit_on[index] = 1;
        if (index < IP_QPSLIMIT_ID) {
            g_kni_qps_limit_on_status |= (1 << index);
        }
    }

    reply_msg->ret_val = 0;
    return;
out:
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}

static void fwd_load_iplib(ioClient *c) {
    int ret;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg*) c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    iplib_cleanup();
    ret = iplib_load_init();
    if (ret < 0) {
        printf(reply_msg->data, "Failed to reload iplib\n");
        c->buf_size += strlen(reply_msg->data) + c->query_size;
        c->bufpos = c->buf_size;
    }
    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}


static void reset_stats(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    stat_init();
    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = 0;
}

static void fwd_view_nodes(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_view_nodes_stats(reply_msg->data, 1);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_view_state(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_view_state(reply_msg->data, 1);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_dns_cnts(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_dns_cnts(reply_msg->data, ADNS_IO_BUFLEN - c->buf_size);
    //printf("dnsstate:len %d,data:%s\n",strlen(reply_msg->data),reply_msg->data);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_dns_state(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_dns_state(reply_msg->data, 1);
    //printf("dnsstate:len %d,data:%s\n",strlen(reply_msg->data),reply_msg->data);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_cache_stats(ioClient *c) {
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_cache_state(reply_msg->data, 1);
    //printf("dnsstate:len %d,data:%s\n",strlen(reply_msg->data),reply_msg->data);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static int __fwd_dnscache_bath(char *data, char *pout, int *offset,
		int buf_rest, int dnscache_cmd) {
    uint8_t *p = (uint8_t*)data;
    uint32_t total;
    int i, ret;
    uint8_t klen;
    uint8_t *qname;
    uint32_t maxttl, minttl, queue_offset;
    zone_id_t zone_id;
    uint8_t sourceedns;
    uint8_t status;
    uint8_t ip_len;
    struct dnscache_node_tbl *new_dnscache_node_tbl = NULL;

    if (dnscache_cmd == DNSCACHE_SET) {
        dnscache_node_tbl_init(&new_dnscache_node_tbl);
    }
    total = *(uint32_t*)p;
    p += 4;

    for (i = 0; i < total; i ++) {
        klen = *p;
        p += 1;
        qname = p;
        p += klen;
        zone_id = *(zone_id_t*)p;
        p += sizeof(zone_id_t);
        maxttl = *(uint32_t*)p;
        p += 4;
        minttl = *(uint32_t*)p;
        p += 4;
        queue_offset = *(uint32_t*)p;
        p += 4;
        sourceedns = *p;
        p += 1;
        status = *p;
        p += 1;
        ip_len = *p;
        p += 1;
        struct dnscache_node *node;
		if (dnscache_cmd == DNSCACHE_SET) {
			ret = dnscache_node_tbl_add_node(new_dnscache_node_tbl, qname, klen,
					zone_id, maxttl, minttl, sourceedns, status, ip_len, &p,
					&node);
		} else {
			if ((queue_offset < g_dnscache_queue_offset)
					// ignore the offset check when nearly rotation
					&& (UINT_MAX - g_dnscache_queue_offset + queue_offset > 10)) {
				ALOG(SERVER, WARN,
						"The msg offset %u is less than current offset %u, ignore it!",
						queue_offset, g_dnscache_queue_offset);

				if (unlikely(ip_len > MAX_SOURCE_IP_NUM)) {
					*offset += snprintf(pout + (*offset), buf_rest - (*offset),
									"DNS cache op (%d) zone id (%d), qname (%s) offset (%u): source num (%u) must less than %d\n",
									dnscache_cmd, zone_id, qname, g_dnscache_queue_offset, ip_len, MAX_SOURCE_IP_NUM);
					return -1;
				}
				p += 8 * ip_len;
				continue;
			}
			ret = dnscache_node_tbl_add_node(g_dnscache_node_tbl, qname, klen,
					zone_id, maxttl, minttl, sourceedns, status, ip_len, &p,
					&node);
		}

        if (ret < 0) {
			*offset += snprintf(pout + (*offset), buf_rest - (*offset),
					"DNS cache op (%d) zone id (%d), qname (%s) offset (%u): failed to add node\n",
					dnscache_cmd, zone_id, qname, g_dnscache_queue_offset);
            return -1;
        }
        dnscache_queue_offset_set(queue_offset);
    }

    if (dnscache_cmd == DNSCACHE_SET) {
        struct dnscache_node_tbl *temp;
        temp = g_dnscache_node_tbl;
        g_dnscache_node_tbl = new_dnscache_node_tbl;
        dnscache_node_tbl_clear(temp);
    }
	*offset += snprintf(pout + (*offset), buf_rest - (*offset),
			"DNS cache op (%d) offset (%u): success process %d nodes\n",
			dnscache_cmd, g_dnscache_queue_offset, total);

    return 0;
}

static void fwd_dnscache_batch_update(ioClient *c) {
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    int offset = 0;
    rte_memcpy(reply_msg, c->querybuf, sizeof(struct cmd_msg));
    c->bufpos = sizeof(struct cmd_msg);
    c->buf_size = sizeof(struct cmd_msg);
    int buf_rest = ADNS_IO_BUFLEN - c->buf_size;

    if (g_init_done) {
        char *pin = ((struct cmd_msg *) c->querybuf)->data;
        char *pout = reply_msg->data;

		reply_msg->ret_val = __fwd_dnscache_bath(pin, pout, &offset, buf_rest,
				DNSCACHE_UPDATE);
    } else {
        reply_msg->ret_val = -1;
		offset += snprintf(reply_msg->data, buf_rest - offset,
				"DNS cache op (%d) offset (%u): initial is not done!\n",
				DNSCACHE_UPDATE, g_dnscache_queue_offset);
    }
    c->buf_size += offset;
    c->buf[c->buf_size] = '\0';
    c->buf_size++;
    c->bufpos = c->buf_size;
    /* set ret value to 'success', write to output buffer */
    ALOG(SERVER, INFO, reply_msg->data);
}

static void fwd_dnscache_batch_set(ioClient *c) {
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    int offset = 0;
    rte_memcpy(reply_msg, c->querybuf, sizeof(struct cmd_msg));
    c->bufpos = sizeof(struct cmd_msg);
    c->buf_size = sizeof(struct cmd_msg);
    int buf_rest = ADNS_IO_BUFLEN - c->buf_size;

    if (g_init_done) {
        char *pin = ((struct cmd_msg *) c->querybuf)->data;
        char *pout = reply_msg->data;

        reply_msg->ret_val = __fwd_dnscache_bath(pin, pout, &offset,
        		buf_rest, DNSCACHE_SET);
    } else {
        reply_msg->ret_val = -1;
		offset += snprintf(reply_msg->data, buf_rest - offset,
				"DNS cache op (%d) offset (%u): initial is not done!\n",
				DNSCACHE_SET, g_dnscache_queue_offset);
    }
    c->buf_size += offset;
    c->buf[c->buf_size] = '\0';
    c->buf_size++;
    c->bufpos = c->buf_size;
    /* set ret value to 'success', write to output buffer */
    ALOG(SERVER, INFO, reply_msg->data);
}

void uint_ip2str(uint32_t ip, char ipstr[15])
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(ipstr, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

static int generate_dnscache_detail(char *buf, int maxlen) {
    char qname[MAX_DOMAIN_LEN];
    char *pos;
    struct dnscache_node **list;
    int i, j, len;

    pos = buf;
    len = 0;
    list = dnscache_node_tbl_list(g_dnscache_node_tbl);
    for (i = 0; i < g_dnscache_node_tbl->cnt; i ++) {
        char ipstr[15];
        adns_qname_to_str_fast((uint8_t *)list[i]->domain_name, qname);
        len = snprintf(pos, maxlen, "%-30s | %-5u | %-5u | %-5u | %-5u | %-5u | ", qname,
				list[i]->src_info->zone_id, list[i]->src_info->cache_ttl_max,
				list[i]->src_info->cache_ttl_min, list[i]->src_info->src_ecs,
				list[i]->src_info->serials);
        if (len >= maxlen) {
            break;
        } else {
            pos += len;
            maxlen -= len;
            len = 0;
        }

        for (j = 0; j < list[i]->src_info->src_len; j ++) {
            uint_ip2str(list[i]->src_info->source[j].ip_addr, ipstr);
            len = snprintf(pos, maxlen, "%s:%d:%d:%s,", ipstr,
            		list[i]->src_info->source[j].port, list[i]->src_info->source[j].down,
					list[i]->src_info->source[j].state == UP? "UP":"DOWN");
            if (len >= maxlen) {
                break;
            } else {
                pos += len;
                maxlen -= len;
                len = 0;
            }
        }

        if (len >= maxlen || maxlen < 2) {
            break;
        }
        *pos = '\n';
        pos += 1;
        maxlen -= 1;
    }

    if (len >= maxlen) {
        pos += (maxlen - 4);
        strcat(pos, "...");
        pos += sizeof("...");
    }
    *pos = '\0';
    free(list);
    return pos - buf;
}

static int generate_dnscache_domain(char *buf, int maxlen) {
    struct dnscache_node **list;
    int i, len;
    char dname[MAX_DOMAIN_LEN];
    char *pos;

    pos = buf;
    list = dnscache_node_tbl_list(g_dnscache_node_tbl);
    for (i = 0; i < g_dnscache_node_tbl->cnt; i ++) {
        adns_qname_to_str_fast((uint8_t *)list[i]->domain_name, dname);
        len = snprintf(pos, maxlen, "%s ", dname);
        if(len >= maxlen) {
            pos += (maxlen - 4);
            strcat(pos, "...");
            pos += sizeof("...");
            break;
        } else {
            pos += len;
            maxlen -= len;
        }
    }
    *pos = '\0';
    free(list);
    return pos - buf;
}

static void fwd_dnscache_list_domain(ioClient *c) {
    int ret, maxlen;

    //memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    maxlen = ADNS_IO_BUFLEN - c->buf_size;
    ret = generate_dnscache_domain(reply_msg->data, maxlen);
    if(ret < 0) {
        c->buf_size += strlen(reply_msg->data);
        reply_msg->ret_val = ret;
    } else {
        c->buf_size += ret;
        reply_msg->ret_val = 0;
    }
}

static void fwd_dnscache_list_detail(ioClient *c) {
    int ret, maxlen;

    //memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size + sizeof(struct cmd_msg);
    maxlen = ADNS_IO_BUFLEN - c->buf_size;
    ret = generate_dnscache_detail(reply_msg->data, maxlen);
    if (ret < 0) {
        c->buf_size += strlen(reply_msg->data);
        reply_msg->ret_val = ret;
    } else {
        c->buf_size += ret;
        reply_msg->ret_val = 0;
    }
}

static void fwd_export_snapshot(ioClient *c) {
    int ret = 0;
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size + sizeof(struct cmd_msg);
    // try to create export data file
    if (opendir(g_data_snapshot_path) == NULL) {
        mkdir(g_data_snapshot_path ,0775);
    }
    char file[255];
    strcpy(file, g_data_snapshot_path);
    strcat(file, g_snapshot_file);
    FILE *fp = fopen(file, "wb");
    if (fp == NULL) {
        ALOG(SERVER, ERROR, "[%s]: Open %s filed.\n", __FUNCTION__, file);
        reply_msg->ret_val = -1;
        return;
    }
    ret = fwd_user_db_export_snapshot(fp);
    if (ret < 0) {
        reply_msg->ret_val = ret;
        fclose(fp);
        return;
    }
    ret = dnscache_export_snapshot(g_dnscache_node_tbl, fp);
    if (ret < 0) {
        reply_msg->ret_val = ret;
        fclose(fp);
        return;
    }
    reply_msg->ret_val = 0;
    char *pos = reply_msg->data;
    sprintf(pos, "Export to %s success\n", file);
    c->buf_size += strlen(reply_msg->data);
    fclose(fp);
    return;
}

static void fwd_import_snapshot(ioClient *c) {
	struct cmd_msg *reply_msg = (struct cmd_msg*) c->buf;
	rte_memcpy(reply_msg, c->querybuf, c->query_size);
	c->bufpos = c->query_size;
	c->buf_size = c->query_size + sizeof(struct cmd_msg);
	char *pos = reply_msg->data;
	char *p = ((struct cmd_msg*) c->querybuf)->data;

	if (fwd_init_load_file(p) == 0) {
		reply_msg->ret_val = -1;
		sprintf(pos, "Import from %s failed\n", p);
	} else {
		reply_msg->ret_val = 0;
		sprintf(pos, "Import from %s success\n", p);
	}
	c->buf_size += strlen(reply_msg->data);
}

static void fwd_dnscache_get_queue_offset(ioClient *c) {
    int offset;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    offset = dnscache_queue_offset_get();
    *(uint32_t*)reply_msg->data = offset;
    c->buf_size += sizeof(uint32_t) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_dnscache_set_queue_offset(ioClient *c) {
    uint32_t offset;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    char *p = ((struct cmd_msg *)c->querybuf)->data;
    offset = atoi(p);
    dnscache_queue_offset_set(offset);
    offset = dnscache_queue_offset_get();
    *(uint32_t*)reply_msg->data = offset;
    c->buf_size += sizeof(uint32_t)+ c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_init_show(ioClient *c) {
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *) c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    *(int *) reply_msg->data = g_init_done;
    c->buf_size += sizeof(int);
    reply_msg->ret_val = 0;
}

static int fwd_init_load_file(char *filepath) {
	int ret;
	FILE *fp;
	int num;
	snapshot_hdr_t hdr;

	fp = fopen(filepath, "rb");
	if (fp == NULL) {
		ALOG(SERVER, ERROR, "The snapshot file %s is not existed", filepath);
		return 0;
	}

	do {
		num = fread(&hdr, sizeof(snapshot_hdr_t), 1, fp);
		if (num == 0) {
			fclose(fp);
			break;
		}

		switch (hdr.snapshot_type) {
		case FWD_USER_SNAPSHOT:
			ret = fwd_user_db_import_snapshot(fp, hdr.payload_size);
			if (ret < 0) {
				fclose(fp);
				return 0;
			}
			break;
		case DNSCACHE_SNAPSHOT:
			ret = dnscache_import_snapshot(fp, hdr.payload_size);
			if (ret < 0) {
				fclose(fp);
				return 0;
			}
			break;
		default:
			ALOG(SERVER, WARN, "Unsupported snapshot type %u in file %s",
					hdr.snapshot_type, filepath);
			if (fseek(fp, hdr.payload_size, SEEK_CUR) != 0) {
				ALOG(SERVER, ERROR,
						"Failed to skip payload size %u for unsupported type %u in file %s",
						hdr.payload_size, hdr.snapshot_type, filepath);
				fclose(fp);
				return 0;
			}
			break;
		}
	} while (num == 1);

	return 1;
}

static void fwd_init_load(ioClient *c) {
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *) c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    if (!g_init_done) {
        char *p = ((struct cmd_msg *) c->querybuf)->data;
        g_init_done = fwd_init_load_file(p);
    }
    *(int *) reply_msg->data = g_init_done;
    c->buf_size += sizeof(int);
    reply_msg->ret_val = 0;
}

static int __fwd_user_batch(char *data, char *pout, int *offset,
        int buf_rest) {
    uint8_t *p = (uint8_t*)data;
    uint32_t total;
    int i, ret;
    int action;
    uint32_t user_id;
    uint32_t queue_offset;
    uint16_t range_num;
    uint8_t status;

    ret = 0;
    total = *(uint32_t*)p;
    p += 4;
    for (i = 0; i < total; i ++) {
        action = *p;
        p += 1;
        user_id = *(uint32_t*)p;
        p += 4;
        queue_offset = *(uint32_t*)p;
        p += 4;
        if (queue_offset < g_user_queue_offset &&
                (UINT_MAX - g_user_queue_offset + queue_offset > 10)) {
            ALOG(SERVER, WARN,
                    "The user offset %u is less than current offset %u, ignore it!",
                    queue_offset, g_user_queue_offset);

            continue;
        }
        switch (action) {
            case ADD_USER:
                status = *p;
                p += 1;
                if (status != USER_STATUS_SERVING && status != USER_STATUS_SUSPEND) {
                    *offset += snprintf(pout + (*offset), buf_rest - (*offset),
                            "the %d user(%d) status(%d) error(shoud be %d %d)", i, user_id,
                            status, USER_STATUS_SERVING, USER_STATUS_SUSPEND);
                    return -1;
                }
                ret = fwd_user_db_add_user(user_id, 0, NULL, status);
                break;
            case DEL_USER:
                ret = fwd_user_db_del_user(user_id);
                break;
            case CHG_USER:
            	break;
            case CHG_USER_STATUS:
                status = *p;
                p += 1;
                ret = fwd_user_db_chg_status(user_id, status);
                offset += snprintf(pout, buf_rest - (*offset),
                        "user change %d status to %d success, offset (%u):\n",
                        user_id, status, g_user_queue_offset);
                break;
            case ADD_USER_IP_RANGE:
            case DEL_USER_IP_RANGE:
            case CHG_USER_IP_RANGE:
                range_num = *(uint16_t*)p;
                p += 2;
                if (range_num >= MAX_USER_IP_RANGE_NUM) {
                    *offset += snprintf(pout + (*offset), buf_rest - (*offset),
                            "the %d user(%d) ip range num too much(%d), must < %d", i, user_id, range_num, MAX_USER_IP_RANGE_NUM);
                    return -1;
                }
                if (action == ADD_USER_IP_RANGE) {
                    ret = fwd_user_db_add_ip_ranges(user_id, range_num, (ip_range_t *)p);
                } else if (action == DEL_USER_IP_RANGE) {
                    ret = fwd_user_db_del_ip_ranges(user_id, range_num, (ip_range_t *)p);
                } else if (action == CHG_USER_IP_RANGE) {
                    ret = fwd_user_db_ref_ip_ranges(user_id, range_num, (ip_range_t *)p);
                }
                p += sizeof(ip_range_t) * range_num;
        }
        if (ret < 0) {
            offset += snprintf(pout + (*offset), buf_rest - (*offset),
                    "user batch set error offset: %u action: %d\n",
                    g_user_queue_offset, action);
            return -1;
        }
        user_queue_offset_set(queue_offset);
    }
    offset += snprintf(pout + (*offset), buf_rest - (*offset),
            "user batch set offset (%u): success %d nodes\n",
            g_user_queue_offset, total);
    return 0;
}

static void fwd_user_batch_set(ioClient *c) {
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    int offset = 0;
    rte_memcpy(reply_msg, c->querybuf, sizeof(struct cmd_msg));
    c->bufpos = sizeof(struct cmd_msg);
    c->buf_size = sizeof(struct cmd_msg);
    int buf_rest = ADNS_IO_BUFLEN - c->buf_size;

    if (g_init_done) {
        char *pin = ((struct cmd_msg *) c->querybuf)->data;
        char *pout = reply_msg->data;

        reply_msg->ret_val = __fwd_user_batch(pin, pout, &offset,
                buf_rest);
    } else {
        reply_msg->ret_val = -1;
        offset += snprintf(reply_msg->data, buf_rest - offset,
                "user add offset (%u): initial is not done!\n",
                g_user_queue_offset);
    }

    c->buf_size += offset;
    c->buf[c->buf_size] = '\0';
    c->buf_size++;
    c->bufpos = c->buf_size;
    /* set ret value to 'success', write to output buffer */
    ALOG(SERVER, INFO, reply_msg->data);
}

static void ip_range_to_str(ip_range_t *ips, int num_ips, char *str) {
    const int IPV4 = 1;
    const int IPV6 = 2;
    int i, len = 0;
    char *pos = str;
    for (i = 0; i < num_ips; i ++) {
        if (ips[i].family == IPV4) {
            char ipv4_str[15];
            uint_ip2str(ips[i].addr.v4, ipv4_str);
            len = sprintf(pos, "%s/%d;", ipv4_str, ips[i].mask);
            pos += len;
            len = 0;
        } else if (ips[i].family == IPV6) {
            char addr[100] = "";
            inet_ntop(AF_INET6, ips[i].addr.v63, addr, 100);
            len = sprintf(pos, "%s/%d;", addr, ips[i].mask);
            pos += len;
            len = 0;
        }
    }
}

static int generate_user_detail(char *buf, int maxlen) {
    char *pos;
    fwd_user_t **list;
    int i, len;

    pos = buf;
    len = 0;
    list = fwd_user_db_list(g_fwd_user_db);
    for (i = 0; i < g_fwd_user_db->user_count; i ++) {
        char ip_str[1024];
        char status_str[255];
        ip_str[0] = 0;
        status_str[0] = 0;
        if (list[i]->status == USER_STATUS_SERVING) {
            strcpy(status_str, "serving");
        } else if (list[i]->status == USER_STATUS_SUSPEND) {
            strcpy(status_str, "suspend");
        }
        ip_range_to_str(list[i]->ip_ranges, list[i]->range_num, ip_str);
        len = snprintf(pos, maxlen, "%-10d | %-10s | %s\n", list[i]->user_id, status_str, ip_str);
        if (len >= maxlen) {
            break;
        } else {
            pos += len;
            maxlen -= len;
            len = 0;
        }
    }
    *pos = '\0';
    free(list);
    return pos - buf;
}

static void fwd_user_list(ioClient *c) {
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    int ret;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size + sizeof(struct cmd_msg);
    int maxlen = ADNS_IO_BUFLEN - c->buf_size;
    ret = generate_user_detail(reply_msg->data, maxlen);
    if (ret < 0) {
        c->buf_size += strlen(reply_msg->data);
        reply_msg->ret_val = ret;
    } else {
        c->buf_size += ret;
        reply_msg->ret_val = 0;
    }
}

static void fwd_user_get_queue_offset(ioClient *c) {
    int offset;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    offset = user_queue_offset_get();
    *(uint32_t*)reply_msg->data = offset;
    c->buf_size += sizeof(uint32_t) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_user_set_queue_offset(ioClient *c) {
    uint32_t offset;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    char *p = ((struct cmd_msg *)c->querybuf)->data;
    offset = atoi(p);
    user_queue_offset_set(offset);
    offset = user_queue_offset_get();
    *(uint32_t*)reply_msg->data = offset;
    c->buf_size += sizeof(uint32_t)+ c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void generate_drop_stats(char *buf, int head)
{
    int i;
    int worker_num = 0;
    int worker[RTE_MAX_LCORE];
    struct lcore_params *lp;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO || lp->type == e_LCORE_KNI) {
            worker[worker_num++] = i;

        }
    }
    assert(worker_num != 0);

    char line[200];
    if (head) {
        sprintf(line, "forward_workers_num: %02d\r\n", worker_num);
        strcat(buf, line);

        int y, m, d, H, M, S;
        struct tm *ptm;
        long ts = time(NULL);
        ptm = localtime(&ts);
        y = ptm->tm_year + 1900;
        m = ptm->tm_mon + 1;
        d = ptm->tm_mday;
        H = ptm->tm_hour;
        M = ptm->tm_min;
        S = ptm->tm_sec;
        sprintf(line,
                "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
                ts, y, m, d, H, M, S);
        strcat(buf, line);
    }

    sprintf(line, "------------DROP STATS-----------\r\n");
    strcat(buf, line);
    sprintf(line,
            "%-10s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s\r\n",
            "worker_id", "udp_filter", "same_req", "dns_parse", "mbuf_append",
            "resp_fwd_none", "jmalloc_fail", "mp_get_fail", "kni_drop");
    strcat(buf, line);

    uint64_t stats[LCORE_STATS_MAX];
    memset(stats, 0, sizeof(stats));
    for (i = 0; i < worker_num; i++) {
        int lcore_id = worker[i];
        stats[UDP_FILTER_DROP] += lcore_stats[lcore_id][UDP_FILTER_DROP];
        stats[SAME_REQ_DROP] += lcore_stats[lcore_id][SAME_REQ_DROP];
        stats[DNS_PARSE_DROP] += lcore_stats[lcore_id][DNS_PARSE_DROP];
        stats[MBUF_APPEND_DROP] += lcore_stats[lcore_id][MBUF_APPEND_DROP];
        stats[RESP_FWD_NONE_DROP] += lcore_stats[lcore_id][RESP_FWD_NONE_DROP];
        stats[JMALLOC_FAIL_DROP] += lcore_stats[lcore_id][JMALLOC_FAIL_DROP];
        stats[MP_GET_FAIL_DROP] += lcore_stats[lcore_id][MP_GET_FAIL_DROP];
        stats[KNI_DROP] += lcore_stats[lcore_id][KNI_DROP];

        sprintf(line,
                "%-10d | %-15lu | %-15lu | %-15lu | %-15lu | %-15lu | %-15lu | %-15lu | %-15lu\r\n",
                lcore_id, lcore_stats[lcore_id][UDP_FILTER_DROP],
                lcore_stats[lcore_id][SAME_REQ_DROP],
                lcore_stats[lcore_id][DNS_PARSE_DROP],
                lcore_stats[lcore_id][MBUF_APPEND_DROP],
                lcore_stats[lcore_id][RESP_FWD_NONE_DROP],
                lcore_stats[lcore_id][JMALLOC_FAIL_DROP],
                lcore_stats[lcore_id][MP_GET_FAIL_DROP],
                lcore_stats[lcore_id][KNI_DROP]);
        strcat(buf, line);
    }

    sprintf(line,
            "%-10s | %-15lu | %-15lu | %-15lu | %-15lu | %-15lu | %-15lu | %-15lu | %-15lu\r\n",
            "all", stats[UDP_FILTER_DROP], stats[SAME_REQ_DROP],
            stats[DNS_PARSE_DROP], stats[MBUF_APPEND_DROP], stats[RESP_FWD_NONE_DROP],
            stats[JMALLOC_FAIL_DROP], stats[MP_GET_FAIL_DROP],
            stats[KNI_DROP]);
    strcat(buf, line);
}

static void generate_prefetch_stats(char *buf, int head)
{
    int i;
    int worker_num = 0;
    int worker[RTE_MAX_LCORE];
    struct lcore_params *lp;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO || lp->type == e_LCORE_KNI) {
            worker[worker_num++] = i;

        }
    }
    assert(worker_num != 0);

    char line[200];
    if (head) {
        sprintf(line, "forward_workers_num: %02d\r\n", worker_num);
        strcat(buf, line);

        int y, m, d, H, M, S;
        struct tm *ptm;
        long ts = time(NULL);
        ptm = localtime(&ts);
        y = ptm->tm_year + 1900;
        m = ptm->tm_mon + 1;
        d = ptm->tm_mday;
        H = ptm->tm_hour;
        M = ptm->tm_min;
        S = ptm->tm_sec;
        sprintf(line,
                "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
                ts, y, m, d, H, M, S);
        strcat(buf, line);
    }
    sprintf(line, "------------PREFETCH STATS-----------\r\n");
    strcat(buf, line);
    sprintf(line, "%-17s | %-17s | %-17s | %-17s | %-17s | %-17s | %-17s\r\n",
            "worker_id", "snd_node", "snd_pkt", "snd_fail", "rcv_pkt",
            "rcv_impact", "ttl_expire");
    strcat(buf, line);

    uint64_t stats[LCORE_STATS_MAX];
    memset(stats, 0, sizeof(stats));
    for (i = 0; i < worker_num; i++) {
        int lcore_id = worker[i];
        stats[TTL_PREFETCH_SEND] += lcore_stats[lcore_id][TTL_PREFETCH_SEND];
        stats[TTL_PREFETCH_NODE] += lcore_stats[lcore_id][TTL_PREFETCH_NODE];
        stats[TTL_PREFETCH_RECV] += lcore_stats[lcore_id][TTL_PREFETCH_RECV];
        stats[TTL_PREFETCH_RECV_IMPACT] +=
            lcore_stats[lcore_id][TTL_PREFETCH_RECV_IMPACT];
        stats[TTL_PREFETCH_SEND_FAIL] +=
            lcore_stats[lcore_id][TTL_PREFETCH_SEND_FAIL];
        stats[TTL_EXPIRE] += lcore_stats[lcore_id][TTL_EXPIRE];
        sprintf(line,
                "%-17d | %-17lu | %-17lu | %-17lu | %-17lu | %-17lu | %-17lu\r\n",
                lcore_id, lcore_stats[lcore_id][TTL_PREFETCH_NODE],
                lcore_stats[lcore_id][TTL_PREFETCH_SEND],
                lcore_stats[lcore_id][TTL_PREFETCH_SEND_FAIL],
                lcore_stats[lcore_id][TTL_PREFETCH_RECV],
                lcore_stats[lcore_id][TTL_PREFETCH_RECV_IMPACT],
                lcore_stats[lcore_id][TTL_EXPIRE]
            );
        strcat(buf, line);
    }

    sprintf(line,
            "%-17s | %-17lu | %-17lu | %-17lu | %-17lu | %-17lu | %-17lu\r\n",
            "all", stats[TTL_PREFETCH_NODE], stats[TTL_PREFETCH_SEND],
            stats[TTL_PREFETCH_SEND_FAIL], stats[TTL_PREFETCH_RECV],
            stats[TTL_PREFETCH_RECV_IMPACT], stats[TTL_EXPIRE]
        );
    strcat(buf, line);
}

static void generate_cpu_stats(char *buf)
{
    int i;
    char line[200];
    struct lcore_params *lp;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type != e_LCORE_IO && lp->type != e_LCORE_KNI && lp->type != e_LCORE_MISC) {
            continue;
        }
        int lcore_id = i;

        sprintf(line,
                "%-4d |%-15lu|%-15lu |%-15lu|%-15lu|%-15lu|%-15lu|%-15lu|%-15lu\r\n",
                lcore_id, gcpu_util[lcore_id].send, gcpu_util[lcore_id].recv,
                gcpu_util[lcore_id].hc_send, gcpu_util[lcore_id].hc_tw,
                gcpu_util[lcore_id].retry, gcpu_util[lcore_id].ttl_ck,
                gcpu_util[lcore_id].msg,
                gcpu_util[lcore_id].all);
        strcat(buf, line);
    }
}

static inline double cal_elt_size(const struct rte_mempool *mp)
{

    return (mp->header_size + mp->elt_size + mp->trailer_size +
            /* Every object has a rte_ring entry, the entry size is aligned  */
            sizeof(void *) * 1.0 * rte_align32pow2(mp->size + 1) / mp->size);
}

int get_memory_info() {
    int socket;
    memset((void*)&g_mem_info, 0, sizeof(struct mem_info_t));
    struct rte_malloc_socket_stats sock_stats;
    struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;

    /* Iterate through all initialised heaps */
    for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
        if ((rte_malloc_get_socket_stats(socket, &sock_stats) < 0))
            continue;

        g_mem_info.heap_stats[socket].heap_totalsz_bytes = sock_stats.heap_totalsz_bytes;
        g_mem_info.heap_stats[socket].heap_freesz_bytes = sock_stats.heap_freesz_bytes;
        g_mem_info.heap_stats[socket].heap_allocsz_bytes = sock_stats.heap_allocsz_bytes;
        g_mem_info.heap_stats[socket].greatest_free_size = sock_stats.greatest_free_size;
        g_mem_info.heap_stats[socket].alloc_count = sock_stats.alloc_count;
        g_mem_info.heap_stats[socket].free_count = sock_stats.free_count;
    }

    rte_rwlock_read_lock(&mcfg->mlock);

    int i = 0, j = 0;
    /* for each memseg */
    for (i = 0; i < RTE_MAX_MEMSEG; i++) {
        if (mcfg->memseg[i].addr == NULL)
            break;
        g_mem_info.total_per_socket[mcfg->memseg[i].socket_id] += mcfg->memseg[i].len;
        g_mem_info.total += mcfg->memseg[i].len;
    }

    /* for each memzone */
    for (i = 0; i < RTE_MAX_MEMZONE; i++) {
        if (mcfg->memzone[i].addr == NULL)
            break;

        g_mem_info.used += mcfg->memzone[i].len;
        g_mem_info.used_per_socket[mcfg->memzone[i].socket_id] += mcfg->memzone[i].len;
        struct rte_mempool *mp = NULL;

        /* mempool */
        if (memcmp(mcfg->memzone[i].name, RTE_MEMPOOL_MZ_PREFIX, 3) == 0) {
            mp = rte_mempool_lookup((mcfg->memzone[i].name) + 3);
            if (mp == NULL) {
                continue;
            }

            size_t memzone_len = 0;
            struct rte_mempool_memhdr *hdr;
            struct rte_memzone *mz = NULL;
            STAILQ_FOREACH(hdr, &mp->mem_list, next) {
                mz = (struct rte_memzone *)hdr->opaque;
                if (mz) {
                    memzone_len += mz->len;
                }
            }


            g_mem_info.zone_info_list[j].is_pool = 1;
            /* name
                * when zone is a pool, zone_name is consisted of 'MP_" + pool_name */
            memcpy(g_mem_info.zone_info_list[j].name, mcfg->memzone[i].name + 3,
                strlen(mcfg->memzone[i].name) - 3);
            /* socket id */
            g_mem_info.zone_info_list[j].socket_id = mcfg->memzone[i].socket_id;
            /* length */
            g_mem_info.zone_info_list[j].len = mcfg->memzone[i].len + \
                sizeof(void*) * rte_align32pow2(mp->size + 1) + sizeof(struct rte_ring) + 64 + memzone_len;
            /* element net size */
            g_mem_info.zone_info_list[j].pool_detail.elt_net_size = mp->elt_size;
            /* element total size */
            g_mem_info.zone_info_list[j].pool_detail.elt_size = cal_elt_size(mp);
            /* element count */
            g_mem_info.zone_info_list[j].pool_detail.elt_count = mp->size;
            /* element available count */
            g_mem_info.zone_info_list[j].pool_detail.avail_count = rte_mempool_avail_count(mp);
            /* common base size */
            g_mem_info.zone_info_list[j].pool_detail.base_size = \
                sizeof(struct rte_mempool) + sizeof(struct rte_ring) + mp->private_data_size + 64 * 2;
        }
        else {
            /* ring is already calculated in mempool */
            if (memcmp(mcfg->memzone[i].name, "RG_MP_", 6) == 0 ) {
                continue;
            }

            /* physical memzone */
            g_mem_info.zone_info_list[j].is_pool = 0;
            /* name */
            memcpy(g_mem_info.zone_info_list[j].name, mcfg->memzone[i].name, strlen(mcfg->memzone[i].name));
            /* socket id */
            g_mem_info.zone_info_list[j].socket_id = mcfg->memzone[i].socket_id;
            /* zone len */
            g_mem_info.zone_info_list[j].len = mcfg->memzone[i].len;
        }
        j ++;
        g_mem_info.count++;
    }
    rte_rwlock_read_unlock(&mcfg->mlock);
    return 0;
}

static void generate_request_stats(char *buf, int head)
{
    int i;
    int worker_num = 0;
    int worker[RTE_MAX_LCORE];
    struct lcore_params *lp;
    for (i = 0; i < RTE_MAX_LCORE; i++) {
        lp = &app.lcore_params[i];
        if (lp->type == e_LCORE_IO || lp->type == e_LCORE_KNI) {
            worker[worker_num++] = i;
        }
    }
    assert(worker_num != 0);

    /*
     *FORMAT
     workers_num: %02d
     server_time: yyyy:mm:dd HH:MM:SS

     %-20s | %-20s | %-20s | %-20s | %-20s
     worker_id | request_in | request_hit | forward_reqest | forwarder_logic_response |forwarder_real_response
     */

    char line[200];
    if (head) {
        sprintf(line, "forward_workers_num: %02d\r\n", worker_num);
        strcat(buf, line);

        int y, m, d, H, M, S;
        struct tm *ptm;
        long ts = time(NULL);
        ptm = localtime(&ts);
        y = ptm->tm_year + 1900;
        m = ptm->tm_mon + 1;
        d = ptm->tm_mday;
        H = ptm->tm_hour;
        M = ptm->tm_min;
        S = ptm->tm_sec;
        sprintf(line,
                "forward_server_time[%ld]: %04d:%02d:%02d - %02d:%02d:%02d\r\n\r\n",
                ts, y, m, d, H, M, S);
        strcat(buf, line);
    }
    sprintf(line, "------------REQUEST STATS-----------\r\n");
    strcat(buf, line);
    sprintf(line,
            "%-18s | %-13s | %-13s | %-18s | %-15s | %-13s | %-15s | %-13s | %-13s\r\n",
            "ipv4_in", "kni_in", "ipv6_in", "req_hit", "fwd_req",
            "tcp_req_in", "fwd_resp", "fwd_timeout", "servfail");
    strcat(buf, line);

    uint64_t stats[LCORE_STATS_MAX];
    memset(stats, 0, sizeof(stats));
    for (i = 0; i < worker_num; i++) {
        int lcore_id = worker[i];
        stats[IPV4_DNS_IN] += lcore_stats[lcore_id][IPV4_DNS_IN];
        stats[KNI_DNS_IN] += lcore_stats[lcore_id][KNI_DNS_IN];
        stats[IPV6_DNS_IN] += lcore_stats[lcore_id][IPV6_DNS_IN];
        stats[HIT_REQ] += lcore_stats[lcore_id][HIT_REQ];
        stats[FWD_REQ] += lcore_stats[lcore_id][FWD_REQ];
        //stats[FWD_LOGIC_RESP] += lcore_stats[lcore_id][FWD_LOGIC_RESP];
        stats[TCP_DNS_IN] += lcore_stats[lcore_id][TCP_DNS_IN];
        stats[FWD_REAL_RESP] += lcore_stats[lcore_id][FWD_REAL_RESP];
        stats[FWD_TIMEOUT] += lcore_stats[lcore_id][FWD_TIMEOUT];
        stats[ANSWER_SERVFAIL] += lcore_stats[lcore_id][ANSWER_SERVFAIL];
        sprintf(line,
                "%-18lu | %-13lu | %-13lu | %-18lu | %-15lu | %-13lu | %-15lu | %-13lu | %-13lu\r\n",
                lcore_stats[lcore_id][IPV4_DNS_IN],
                lcore_stats[lcore_id][KNI_DNS_IN],
                lcore_stats[lcore_id][IPV6_DNS_IN],
                lcore_stats[lcore_id][HIT_REQ],
                lcore_stats[lcore_id][FWD_REQ],
                //lcore_stats[lcore_id][FWD_LOGIC_RESP],
                lcore_stats[lcore_id][TCP_DNS_IN],
                lcore_stats[lcore_id][FWD_REAL_RESP],
                lcore_stats[lcore_id][FWD_TIMEOUT],
                lcore_stats[lcore_id][ANSWER_SERVFAIL]
            );
        strcat(buf, line);
    }

    sprintf(line,
            "%-18lu | %-13lu | %-13lu | %-18lu | %-15lu | %-13lu | %-15lu | %-13lu | %-13lu\r\n",
            stats[IPV4_DNS_IN], stats[KNI_DNS_IN], stats[IPV6_DNS_IN], stats[HIT_REQ], stats[FWD_REQ], //stats[FWD_LOGIC_RESP],
            stats[TCP_DNS_IN], stats[FWD_REAL_RESP], stats[FWD_TIMEOUT], stats[ANSWER_SERVFAIL]
        );
    strcat(buf, line);

}

static void fwd_delreg_keys(ioClient * c)
{
    int ret = -1, i;
    struct lcore_msg_info *msg;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    char *p = reply_msg->data;
    int cmdtype = MSG_DEL_REG_KEYS;

    msg = get_cmd_msg_info(cmdtype, strlen(p), p);
    if (msg == NULL) {
        strcat(reply_msg->data, "cannot get ipc msg for protect keys\r\n");
        goto out;
    }
    get_cmd_msg(msg);
    for (i = 0; i < gio_count; i++) {
        send_cmd_msg(msg, gio_id[i]);
    }
    put_cmd_msg(msg);
    //del_key(name,qtype);  
    char tmp[300];
    sprintf(tmp, "\nDel keys which match [%s] has sent done\n",
            reply_msg->data);
    strcat(reply_msg->data, tmp);
    ret = 0;
out:
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}

static void fwd_denydns_keys(ioClient * c)
{
    int ret = -1, i;
    struct lcore_msg_info *msg;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    char *p = reply_msg->data;
    int cmdtype = MSG_PRO_START;

    msg = get_cmd_msg_info(cmdtype, strlen(p), p);
    if (msg == NULL) {
        strcat(reply_msg->data, "cannot get ipc msg for protect keys\r\n");
        goto out;
    }
    get_cmd_msg(msg);
    for (i = 0; i < gio_count; i++) {
        send_cmd_msg(msg, gio_id[i]);
    }
    put_cmd_msg(msg);
    //del_key(name,qtype);  
    char tmp[300];
    sprintf(tmp, "\nProtect %s has sent done\n", reply_msg->data);
    strcat(reply_msg->data, tmp);
    ret = 0;
out:
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}

static void fwd_nodenydns_keys(ioClient * c)
{
    int ret = -1, i;
    struct lcore_msg_info *msg;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    char p[10] = "all";
    p[3] = '\0';
    int cmdtype = MSG_PRO_STOP;

    msg = get_cmd_msg_info(cmdtype, strlen(p), p);
    if (msg == NULL) {
        strcat(reply_msg->data, "cannot get ipc msg for clean protect\r\n");
        goto out;
    }
    get_cmd_msg(msg);
    for (i = 0; i < gio_count; i++) {
        send_cmd_msg(msg, gio_id[i]);
    }
    put_cmd_msg(msg);
    //del_key(name,qtype);  
    char tmp[300];
    sprintf(tmp, "\nclean protect %s has sent done\n", reply_msg->data);
    strcat(reply_msg->data, tmp);
    ret = 0;
out:
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}

static const char *deal_key(char *name, int qtype, uint8_t stype) {
    struct lcore_msg_info *msg;
    int i;
    //int ret;

    msg = get_del_key_msg_info(name, qtype, stype);
    if (msg == NULL){
        return "cannot get ipc msg for del key\r\n";
    }

    get_cmd_msg(msg);
    for(i = 0 ; i < gio_count ; i++){
        send_cmd_msg(msg, gio_id[i]);
        /*
        ret = send_cmd_msg(msg, gio_id[i]) ;
        if (ret < 0) {
            put_cmd_msg(msg);
            return "failed to send cmd msg\r\n";
        }
        */
    }
    put_cmd_msg(msg);
    ALOG(SERVER, INFO, "Send del key %s type %d stype %d", name, qtype, stype);
    return NULL;
}

static void fwd_del_key(ioClient * c)
{
    int ret = -1;
    int cnt = 0;
    //memset(c->buf,0,sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, sizeof(struct cmd_msg));
    c->bufpos = sizeof(struct cmd_msg);
    c->buf_size = sizeof(struct cmd_msg);
    char *pin = ((struct cmd_msg *)c->querybuf)->data;
    char *pout = reply_msg->data;
    int offset = 0,qtype,i=0,cmdtype;
    char *type;
    struct lcore_msg_info * msg;
    char *token;
    int L = strlen(pin);
    int buf_rest = ADNS_IO_BUFLEN - c->buf_size;
    const char *pstr;
    uint8_t stype = SRV_TYPE_REC;

    ALOG(SERVER, INFO, pin);
    if (L <= 0 || L > 1024) {
        offset += snprintf(pout + offset, buf_rest - offset, "Del string length error %d (0<= || >1024)", L);
        goto out;
    }
    //*(pout - 1) = ':';

    if (likely(strncmp(pin, "batch", 5) == 0)) {
        pin += 5;

		if (*pin == FWD_DEL_STYPE_SPLIT) {
			pin += 1;
			if (strncmp(pin, "auth", 4) == 0) {
				stype = SRV_TYPE_AUTH;
				pin += 4;
			} else if (strncmp(pin, "recu", 4) == 0) {
				stype = SRV_TYPE_REC;
				pin += 4;
			}
		}
		// skip the blank space
		pin += 1;

        token = strtok(pin, FWD_DEL_BATCH_ENTRY_SPLIT);
        while (token != NULL) {
            type = strstr(token, FWD_DEL_BATCH_SPLIT);
            if (type == NULL) {
                offset += snprintf(pout + offset, buf_rest - offset,
                        "Del key Fail,no %s\r\n!", FWD_DEL_BATCH_SPLIT);
                goto out;
            }
            //rte_memcpy(name, token, type - token);
            *type = '\0';
            type = type + strlen(FWD_DEL_BATCH_SPLIT);
            qtype = atoi(type);
            pstr = deal_key(token, qtype, stype);
            if (pstr != NULL) {
                offset += snprintf(pout + offset, buf_rest - offset, "%s",
                        pstr);
                goto out;
            }
            cnt++;
            token = strtok(NULL, FWD_DEL_BATCH_ENTRY_SPLIT);
        }
    } else if (strncmp(pin, "all", 3) == 0) {
        cmdtype = MSG_DEL_ALL_KEY;
        msg = get_cmd_msg_info(cmdtype, 0, NULL);
        if (msg == NULL) {
            offset += snprintf(pout + offset, buf_rest - offset,
                    "cannot get ipc msg for del key\r\n!");
            goto out;
        }
        get_cmd_msg(msg);
        for(i = 0 ; i < gio_count ; i++){
            send_cmd_msg(msg, gio_id[i]);
            /*
            ret = send_cmd_msg(msg, gio_id[i]) ;
            if (ret < 0) {
                break;
            }
            */
        }
        put_cmd_msg(msg);
        cnt++;
    } else {
		if (*pin == FWD_DEL_STYPE_SPLIT) {
			pin += 1;
			if (strncmp(pin, "auth", 4) == 0) {
				stype = SRV_TYPE_AUTH;
				pin += 4;
			} else if (strncmp(pin, "recu", 4) == 0) {
				stype = SRV_TYPE_REC;
				pin += 4;
			}
			// skip the blank space
			pin += 1;
		}
        type = strstr(pin, FWD_DEL_SPLIT);
        if (type == NULL) {
            offset += snprintf(pout + offset, buf_rest - offset,
                    "Del key Fail,no %s\r\n!", FWD_DEL_SPLIT);
            goto out;
        }
        //rte_memcpy(name, p, type - p);
        *type = '\0';
        type = type + strlen(FWD_DEL_SPLIT);
        qtype = atoi(type);
        pstr = deal_key(pin, qtype, stype);
        if (pstr != NULL) {
            offset += snprintf(pout + offset, buf_rest - offset, "%s", pstr);
            goto out;
        }
        cnt++;
    }
    offset += snprintf(pout + offset, buf_rest - offset, "Success: %d!\r\n", cnt);
    ret = 0;

out:
    c->buf_size += offset;
    c->buf[c->buf_size] = '\0';
    c->buf_size++;
    c->bufpos = c->buf_size;
    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
    ALOG(SERVER, INFO, reply_msg->data);
}
static void fwd_set_view_backup(ioClient *c)
{
    int ret;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    char *p = reply_msg->data;

    char *backup = strstr(p, FWD_VIEW_BACKUP_SPLIT);
    if (backup == NULL) {
        strcat(reply_msg->data, " Backup Set Fail,no ");
        strcat(reply_msg->data, FWD_VIEW_BACKUP_SPLIT);
        ret = -1;
        goto out;
    }

    backup = backup + strlen(FWD_VIEW_BACKUP_SPLIT);
    int backup_id = view_name_to_id(backup);
    if (backup_id == -1) {
        char tmp[100];
        sprintf(tmp, " Backup Set Fail,backup view '%s' not exist", backup);
        strcat(reply_msg->data, tmp);
        ret = -1;
        goto out;
    }

    char vname[300];
    memset(vname, 0, sizeof(vname));
    rte_memcpy(vname, p, backup - strlen(FWD_VIEW_BACKUP_SPLIT) - p);
    int view_id = view_name_to_id(vname);
    if (view_id == -1) {
        char tmp[100];
        sprintf(tmp, " Backup Set Fail,origin view '%s' not exist", vname);
        strcat(reply_msg->data, tmp);
        ret = -1;
        goto out;
    }
    set_view_backup(g_recs_views, view_id, backup_id);
    set_view_backup(g_auth_views, view_id, backup_id);
    set_view_backup(g_backup_views, view_id, backup_id);
    strcat(reply_msg->data, " Backup Set OK");
    ret = 0;
out:
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}

static void fwd_set_log(ioClient * c)
{
    int ret;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    if (set_log_level_id(reply_msg->cmd, reply_msg->flags) < 0) {
        sprintf(reply_msg->data,
                "Change log level fail,unknow log type or level\r\n");
        ret = -1;
    } else {
        ret = 0;
        sprintf(reply_msg->data, "Change log level ok\r\n");
    }
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}

static void nodes_ttl_threshold(ioClient * c)
{

    int ret;
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    if (reply_msg->flags < 0 || reply_msg->flags > MVNODES) {
        sprintf(reply_msg->data,
                "Change lcore view node ttl fetch threshold fail,set %d ,not match >= 0 && <= %d\r\n",
                reply_msg->flags, MVNODES);
        ret = -1;
    } else {
        ret = 0;
        set_view_nodes_ttl_threshold(reply_msg->flags);
        sprintf(reply_msg->data,
                "Change lcore view node ttl fetch threshold to %d ok\r\n",
                reply_msg->flags);
    }
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}

static void __fwd_set_status(ioClient * c, int type)
{

    int ret;
    memset(c->buf,0,sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    if(type < 0 || type >= STATUS_TYPE_MAX){
        sprintf(reply_msg->data,"unknow type[%d]\r\n",type);
        ret = -1;
    }else if(reply_msg->flags != STATUS_ON && reply_msg->flags != STATUS_OFF){
        sprintf(reply_msg->data,"Change type [%s] Fail,recv flag [%d] ,not %d or %d\r\n",gstatus_type[type],reply_msg->flags,STATUS_ON,STATUS_OFF);
        ret = -1;
    }else{
        ret = 0;
        switch(type){
            case OVERSEALIST_STATUS:
                        set_oversea_state(reply_msg->flags);
                        break;
            case WHITELIST_STATUS:
                        set_white_state(reply_msg->flags);
                        break;
            case MAN_WHITELIST_STATUS: 
                        set_man_white_state(reply_msg->flags);
                        break;
            case MAN_BLACKLIST_STATUS: 
                        set_man_black_state(reply_msg->flags);
                        break;
 
            case BLACKLIST_STATUS: 
                        set_black_state(reply_msg->flags);
                        break;

            case LCORESHARE_STATUS:
                        set_share_lcore_data(reply_msg->flags);
                        break;
            default:
                     sprintf(reply_msg->data,"unknow type[%d]\r\n",type);
                             ret = -1;
        }
        if(ret != -1)
            sprintf(reply_msg->data,"Change type [%s] to [%s] ok\r\n",gstatus_type[type],gstatus_info[reply_msg->flags]);
    }
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = ret;
}


static void fwd_set_black_status(ioClient * c)
{
    __fwd_set_status(c, BLACKLIST_STATUS);
}
static void fwd_set_oversea_status(ioClient * c)
{
    __fwd_set_status(c, OVERSEALIST_STATUS);
}

static void fwd_set_white_status(ioClient * c)
{
    __fwd_set_status(c, WHITELIST_STATUS);
}

static void fwd_set_man_white_status(ioClient * c)
{
    __fwd_set_status(c, MAN_WHITELIST_STATUS);
}

static void fwd_set_man_black_status(ioClient * c)
{
    __fwd_set_status(c, MAN_BLACKLIST_STATUS);
}
static void fwd_set_lcore_share_status(ioClient *c)
{
    __fwd_set_status(c,LCORESHARE_STATUS);
}

static void fwd_stats(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_request_stats(reply_msg->data, 1);
    generate_prefetch_stats(reply_msg->data, 0);
    generate_drop_stats(reply_msg->data, 0);
    generate_view_stats(reply_msg->data, 0);
    //generate_view_stats_httpdns(reply_msg->data, 0);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_cpu_stats(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_cpu_stats(reply_msg->data);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_memory_info(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    get_memory_info();
    memcpy(reply_msg->data, &g_mem_info, sizeof(struct mem_info_t));
    c->buf_size += sizeof(struct mem_info_t) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_req_stats(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_request_stats(reply_msg->data, 1);
    //generate_request_stats_tcp(reply_msg->data, 0);
    //generate_request_stats_httpdns(reply_msg->data, 0);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_version(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    strcat(reply_msg->data, FWD_VERSION_STR);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_prefetch_stats(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_prefetch_stats(reply_msg->data, 1);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_drop_stats(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_drop_stats(reply_msg->data, 1);
    //generate_drop_stats_httpdns(reply_msg->data, 0);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

static void fwd_view_stats(ioClient * c)
{
    memset(c->buf, 0, sizeof(c->buf));
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;
    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;
    generate_view_stats(reply_msg->data, 1);
    //generate_view_stats_httpdns(reply_msg->data, 0);
    c->buf_size += strlen(reply_msg->data) + c->query_size;
    c->bufpos = c->buf_size;
    reply_msg->ret_val = 0;
}

void rndc_reload_cb(ioClient * c)
{
    int ret;
    struct cmd_msg *reply_msg = (struct cmd_msg *)c->buf;

    rte_memcpy(reply_msg, c->querybuf, c->query_size);
    c->bufpos = c->query_size;
    c->buf_size = c->query_size;

    ret = 0;                    //do reload
    if (ret < 0) {
        printf("reload error\n");
        reply_msg->ret_val = ret;
        return;
    }

    /* set ret value to 'success', write to output buffer */
    reply_msg->ret_val = 0;
}

static int admin_server_init(void)
{
    admin.el = aeCreateEventLoop(EVENT_SET_SIZE);
    if (admin.el == NULL)
        return -1;

    return 0;
}

int listenToPort(void)
{
    int i;

    for (i = 0; i < IO_BINDADDR_NUM; i++) {
        if (admin.bindaddr[i].addr == NULL) {
            printf("bind err\n");
            goto err;
        }

        admin.ipfd[i] = anetTcpServer(admin.neterr, admin.bindaddr[i].port,
                                      admin.bindaddr[i].addr);
        if (admin.ipfd[i] == ANET_ERR) {
            printf("fd error\n");
            goto err;
        }
    }

    return 0;
err:
    printf("listen to port error\n");
    return -1;
}

int admin_init(const char *addr, uint16_t port)
{
    int ret;

    ret = admin_server_init();
    if (ret < 0) {
        fprintf(stderr, "Failed to init event\n");
        goto err;
    }
    printf("admin init start\n");

    INIT_LIST_HEAD(&admin.clients);

    /* init bind addr and port */
    admin.bindaddr[IO_BIND_CMD].addr = admin.bind_addr;
    admin.bindaddr[IO_BIND_CMD].port = admin.bind_port;

    /* Open the TCP listening socket for DNS. */
    if (listenToPort() < 0)
        goto err;

    /* Create an event handler for accepting new connections in TCP */

    printf("create file event\n");
    if (aeCreateFileEvent(admin.el, admin.ipfd[IO_BIND_CMD], AE_READABLE,
                          acceptTcpCmd, NULL) == AE_ERR)
        goto err;

    printf("admin init end\n");
    return 0;

err:
    return -1;
}

void admin_cleanup(void)
{

}
