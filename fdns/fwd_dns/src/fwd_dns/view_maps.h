#ifndef _ADNS_VIEW_MAPS_H_
#define _ADNS_VIEW_MAPS_H_


#include <string.h>
#include <stdio.h>
#include <stdint.h>


#define VIEW_NAME_LEN    64
#define VIEW_ID_DEFAULT  0
#define VIEW_ID_MAX      2560


struct adns_view_map {
    int id;
    char name[VIEW_NAME_LEN];
};


extern int g_view_nums;
extern int g_view_nums;
extern char *g_view_map_file;
extern int g_vgroup_map[VIEW_ID_MAX];
extern struct adns_view_map *g_view_map_tbl;

static inline const char *view_id_to_name(int id)
{
    if (id > g_view_nums) {
        return "Err_Unknown";
    }

    return g_view_map_tbl[id].name;
}

int view_name_to_id(const char *name);
int parse_view_map(char *file, int view_max_num);
int view_map_init(void);
void view_map_cleanup(void);

#endif

