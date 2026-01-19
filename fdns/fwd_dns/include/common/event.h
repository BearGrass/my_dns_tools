
#ifndef _ADNS_EVENT_H_
#define _ADNS_EVENT_H_

#include "list.h"

#define EVENT_DEF_NUMBER 1024

struct event_info;

typedef void (*event_handler_t)(int fd, int events, void *data);

int event_add(int fd, event_handler_t h, void *data);
void event_del(int fd);
int event_modify(int fd, unsigned int events);

void event_loop(int timeout);

int event_init(void);

#endif

