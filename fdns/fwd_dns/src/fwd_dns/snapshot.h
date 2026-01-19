#ifndef _SNAPSHOT_H
#define _SNAPSHOT_H

#include <stdio.h>

extern char *g_data_snapshot_path;
extern const char *g_snapshot_file;

typedef enum SNAPSHOT_TYPE {
	DNSCACHE_SNAPSHOT = 0,
	FWD_USER_SNAPSHOT
} SNAPSHOT_TYPE_T;

typedef struct snapshot_hdr {
	SNAPSHOT_TYPE_T snapshot_type;
	uint32_t payload_size;
} __attribute__((packed)) snapshot_hdr_t;

static inline void print_byte(FILE *fp, int len, uint8_t *p) {
	fwrite(p, len, 1, fp);
}

void set_snapshot_path(char *path);

#endif
