#ifndef _ADNS_VIEW_MAPS_H_
#define _ADNS_VIEW_MAPS_H_


#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "adns_types.h"


#define VIEW_NAME_LEN    64
#define VIEW_ID_DEFAULT  0
#define VIEW_ID_MIN      1
#define VIEW_ID_MAX      (1 << (sizeof(adns_viewid_t) * ADNS_UINT8_BIT))


struct adns_view_map {
    int id;
    char name[VIEW_NAME_LEN];
};


extern int  *g_p_view_nums;
extern char *g_view_map_file;

#ifdef __cplusplus 
extern "C" { 
#endif

char *view_id_to_name(int id);
char *custom_view_id_to_name(int id);
int view_name_to_id(const char *name);
int parse_view_map(char *file, int view_max_num, struct adns_view_map *tbl, int *view_nums);
int view_map_init(void);
void view_map_cleanup(void);

#ifdef __cplusplus 
}
#endif


#endif

