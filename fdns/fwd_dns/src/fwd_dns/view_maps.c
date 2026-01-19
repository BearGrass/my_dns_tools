#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <rte_core.h>

#include "view_maps.h"
#include "common.h"
#include "view.h"
#include "bit.h"

char* g_view_map_file = "etc/view_name_id.map";
int g_view_nums = 0;
int view_max_num = 10240;
struct adns_view_map *g_view_map_tbl = NULL;

int view_name_to_id(const char *name)
{
    int i;

    if (name == NULL)
        return -1;

    for (i = 0; i < g_view_nums; i++) {
        if (strcmp((g_view_map_tbl+i)->name, name) != 0) {
            continue;
        }
        return (g_view_map_tbl+i)->id;
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
    //printf("%s %d\n", entry->name, entry->id);
    return 0;
}


int parse_view_map(char *file, int view_max_num)
{
    FILE *fp;
    int   ret;
    char  line[1024] = {0};
    struct adns_view_map entry;

    if ((file == NULL) || (g_view_map_tbl == NULL)) {
        fprintf(stderr, "[%s]: File or TBL is NULL\n", __FUNCTION__);
        return -1;
    }
    fp = fopen(file, "r");
    if (fp == NULL) {
        fprintf(stderr, "[%s]: Cannot open file: %s\n", __FUNCTION__, file);
        return -1;
    }

    // Init the default view
    g_view_map_tbl[0].id = 0;
    strcpy(g_view_map_tbl[0].name, "default");
    add_view_basic(0);
    g_view_nums = 1;

    while (!feof(fp) && fgets(line, sizeof(line) - 1, fp) != NULL) {
//        while (L > 0 && isspace(line[L])) {
//            line[L--] = '\0';
//        }
//        while(start < L && isspace(line[start])) {
//            start ++;
//        }
        ret = parse_map_entry(&entry, line);
        if (ret < 0) {
            fprintf(stderr, "[%s]: Failed to parse view map: %s, line is: %d\n", __FUNCTION__, line, g_view_nums);
            goto err;
        }
        if (entry.id >= view_max_num){
            fprintf(stderr, "[%s]: Invalid id: %s, max_view_id %d\n", __FUNCTION__, line, view_max_num);
            return -1;
        }

        g_view_map_tbl[entry.id].id = entry.id;
        strcpy(g_view_map_tbl[entry.id].name, entry.name);
        add_view_basic(entry.id);
        g_view_nums++;
        if (g_view_nums >= view_max_num){
            fprintf(stderr, "[%s]: View id num %d exceed max %d\n", __FUNCTION__, g_view_nums, VIEW_ID_MAX);
            goto err;
        }

        printf("g_view_list[%d].name = %s\n", entry.id, entry.name);
    }

    fclose(fp);
    return 0;

err:
    fclose(fp);
    return -1;
}

int view_map_init(void)
{
    int ret, size;

    size = sizeof(struct adns_view_map) * VIEW_ID_MAX;
    g_view_map_tbl = rte_malloc(NULL, size, 0);
    if (g_view_map_tbl == NULL) {
        fprintf(stderr, "[%s]: Failed to alloc memory for view map table\n", __FUNCTION__);
        return -1;
    }

    RTE_LOG(ERR, LDNS, "start parse_view_map\n");
    ret = parse_view_map(g_view_map_file, VIEW_ID_MAX);
    if (ret < 0) {
        fprintf(stderr, "[%s]: Failed to parse view map file %s\n", __FUNCTION__, g_view_map_file);
        rte_free(g_view_map_tbl);
        return -1;
    }

    return 0;
}


void view_map_cleanup()
{
    if (g_view_map_tbl != NULL) {
        rte_free(g_view_map_tbl);
        g_view_map_tbl = NULL;
    }
}


