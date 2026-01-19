
#ifndef _ADNS_DAEMON_H_
#define _ADNS_DAEMON_H_

#include <stdint.h>
#include <unistd.h>

#define ADNS_INITFILE "/var/run/adns_init"
#define RUNDIR "/var/run"
#define PROG_NAME "adns"

char *pid_filename(void);

pid_t pid_read(const char *file);

int pid_write(const char *file);

int pid_remove(const char *file);

int pid_running(pid_t pid);

char *pid_check_and_create(void);

int init_lock(void);
void init_unlock(void);

int daemon_start(void);

#endif

