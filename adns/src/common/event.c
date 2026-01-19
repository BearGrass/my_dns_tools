
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "event.h"

static int efd = -1;
static ADNS_LIST_HEAD(events_list);

struct event_info {
    event_handler_t handler;
    int fd;
    void *data;
    struct list_head ei_list;
};

static struct event_info *event_lookup(int fd)
{
    struct event_info *ei;

    list_for_each_entry(ei, &events_list, ei_list) {
        if (ei->fd == fd)
            return ei;
    }

    return NULL;
}

int event_add(int fd, event_handler_t h, void *data)
{
    int ret;
    struct epoll_event ev;
    struct event_info *ei;

    ei = event_lookup(fd);
    if (ei) {
        printf("Event for fd: %d already exist\n", fd);
        return -EEXIST;
    }

    ei = calloc(1, sizeof(struct event_info));
    if (ei == NULL)
        return -ENOMEM;

    ei->fd = fd;
    ei->handler = h;
    ei->data = data;

    ev.events = EPOLLIN;
    ev.data.ptr = ei;

    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
    if (ret) {
        printf("failed to add epoll event: %m\n");
        free(ei);
    } else
        list_add(&ei->ei_list, &events_list);

    return ret;
}

void event_del(int fd)
{
    int ret;
    struct event_info *ei;

    ei = event_lookup(fd);
    if (ei == NULL)
        return;

    ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
    if (ret)
        printf("failed to delete epoll event for fd %d: %m\n", fd);

    list_del(&ei->ei_list);
    free(ei);
}

int event_modify(int fd, unsigned int events)
{
    int ret;
    struct epoll_event ev;
    struct event_info *ei;

    ei = event_lookup(fd);
    if (ei == NULL) {
        printf("event info for fd %d not found\n", fd);
        return -1;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = ei;

    ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
    if (ret) {
        printf("failed to delete epoll event for fd %d: %m\n", fd);
        return -1;
    }

    return 0;
}

void event_loop()
{
    int i, nr;
    struct epoll_event events[128];

    nr = epoll_wait(efd, events, 128, 0);
    if (nr < 0) {
        if (errno == EINTR)
            return;
        printf("epoll_wait failed: %m\n");
        exit(1);
    } else {
        for (i = 0; i < nr; i++) {
            struct event_info *ei;

            ei = (struct event_info *)events[i].data.ptr;
            ei->handler(ei->fd, events[i].events, ei->data);
        }
    }
}

int event_init(void)
{
    efd = epoll_create(EVENT_DEF_NUMBER);
    if (efd < 0) {
        printf("failed to create epoll fd\n");
        return -1;
    }

    return 0;
}

