#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "snapshot.h"

char *g_data_snapshot_path = NULL;
const char *g_snapshot_file = "snapshot.data";

void set_snapshot_path(char *path) {
    g_data_snapshot_path = path;
    printf("LDNS: Set snapshot path to %s\n", path);
}

