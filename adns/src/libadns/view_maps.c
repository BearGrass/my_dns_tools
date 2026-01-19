#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <rte_malloc.h>

#include "view_maps.h"
#include "adns_conf.h"


int * g_p_view_nums = 0;
struct adns_view_map *g_view_map_tbl = NULL;
struct adns_view_map *g_custom_view_map_tbl = NULL;


char *view_id_to_name(int id)
{
    if (id < 1 || id > *g_p_view_nums) {
        return NULL;
    }
  
    return g_view_map_tbl[id - 1].name;
}

char *custom_view_id_to_name(int id)
{
    if (id >= g_private_route_per_zone_max_num) {
        return NULL;
    }
    return g_custom_view_map_tbl[id].name;
}


int view_name_to_id(const char *name)
{
    int i;

    for (i = 0; i < *g_p_view_nums; i++) {
        if (strcasecmp(g_view_map_tbl[i].name, name) != 0) {
            continue;
        }
        return g_view_map_tbl[i].id;
    }

    return -1;
}


/*
 * Line format: VIEW NAME | VIEW ID
 * eg: BIYING 7
 * eg: GOOGLE 8
 */
static int parse_map_entry(struct adns_view_map *entry, char *line)
{
    int i;
    char *str, *token, *saveptr, *buf[5];

    for (i = 0, str = line; ; i++, str = NULL) {
        token = strtok_r(str, " ", &saveptr);
        if (token == NULL) {
            break;
        }
        
        if (i >= 3) {
            break;  
        }
        buf[i] = token;
    }

    if (i != 2) {
        fprintf(stderr, "[%s]: Invalid argment: %s\n", __FUNCTION__, line);
        return -1;
    }

    snprintf(entry->name, VIEW_NAME_LEN, "%s", buf[0]);
    entry->id = atoi(buf[1]);
    
    return 0;
}


int parse_view_map(char *file, int view_max_num, struct adns_view_map *tbl, int *view_nums)
{
    FILE *fp;
    int   ret, num, line_len;   
    char  line[1024] = {0};
    struct adns_view_map *entry;

    if ((file == NULL) || (tbl == NULL)) {
        fprintf(stderr, "[%s]: File or TBL is NULL\n", __FUNCTION__);
        return -1;  
    }
    
    fp = fopen(file, "r");
    if (fp == NULL) {
        fprintf(stderr, "[%s]: Cannot open file: %s\n", __FUNCTION__, file);
        return -1;
    }

    num = 0;
    while (!feof(fp) && fgets(line, sizeof(line) - 1, fp) != NULL) {
        entry = tbl + num;
        
        line_len = strlen(line);        
        if (line_len > 0) {
            if (line[line_len - 1] == '\n') {
                line[line_len - 1] = '\0';
            }
            
            line_len = strlen(line);    
            if (line_len > 0 && line[line_len - 1] == '\r') {
                line[line_len - 1] = '\0';
            }
        }
    
        ret = parse_map_entry(entry, line);
        if (ret < 0) {
            fprintf(stderr, "[%s]: Failed to parse view map: %s, line is: %d\n", __FUNCTION__, line, num + 1);
            goto err;
        }
        
        if (entry->id >= view_max_num) {
            fprintf(stderr, "[%s]: Invalid id: %s, max_view_id %d\n", __FUNCTION__, line, view_max_num);
            return -1;
        }

        num++;
        if (num >= view_max_num) {
            fprintf(stderr, "[%s]: View id num %d exceed max %d\n", __FUNCTION__, num, view_max_num);
            goto err;
        }
    }

    if (num < VIEW_ID_MIN) {
        fprintf(stderr, "[%s]: View id num %d less than min %d\n", __FUNCTION__, num, VIEW_ID_MIN);
        goto err;
    }

    *view_nums = num;
    fclose(fp);
    return 0;

err:
    fclose(fp);
    return -1;
}


int view_map_init(void)
{
    int ret, size, i;

    size = sizeof(struct adns_view_map) * g_view_max_num;
    g_view_map_tbl = rte_malloc(NULL, size, 0);
    if (g_view_map_tbl == NULL) {
        fprintf(stderr, "[%s]: Failed to alloc memory for view map table\n", __FUNCTION__);
        return -1;
    }

    ret = parse_view_map(g_view_map_file, g_view_max_num, g_view_map_tbl, g_p_view_nums);
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to parse view map file %s\n", __FUNCTION__, g_view_map_file);
        rte_free(g_view_map_tbl);
        return -1;
    }

    size = sizeof(struct adns_view_map) * g_private_route_per_zone_max_num;
    g_custom_view_map_tbl = rte_malloc(NULL, size, 0);
    if (g_custom_view_map_tbl == NULL) {
        fprintf(stderr, "[%s]: Failed to alloc memory for custom view map table\n", __FUNCTION__);
        rte_free(g_view_map_tbl);
        return -1;
    }
    for (i = 0; i < g_private_route_per_zone_max_num; i ++) {
        snprintf(g_custom_view_map_tbl[i].name, VIEW_NAME_LEN, "%sview_%d", CUSTOM_VIEW_PREFIX, i);
    }
    
    return 0;
}


void view_map_cleanup()
{
    if (g_view_map_tbl != NULL) {
        memset(g_view_map_tbl, 0, sizeof(struct adns_view_map) * g_view_max_num);
    }
}

