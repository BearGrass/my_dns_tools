

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <grp.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "daemon.h"


char *make_pidfile_name(void)
{
    char name[64];
    char *filename;

    snprintf(name, 64, "%s/%s.pid", RUNDIR, PROG_NAME);
    filename = strdup(name);

    return filename;
}

pid_t pid_read(const char *file)
{
    char buf[64];
    FILE *fp;
    int ret, readb = 0;

    if (file == NULL)
        return -EINVAL;

    fp = fopen(file, "r");
    if (fp == NULL)
        return -ENOENT;

    // read pid string
    ret = fread(buf, 1, 1, fp);
    while (ret > 0) {
        if (++readb == sizeof(buf) - 1) {
            break;
        }
        ret = fread(buf + readb, 1, 1, fp);
    }

    buf[readb] = '\0';
    fclose(fp);

    if (readb < 1) {
        return -ENOENT;
    }

    // convert buf string to pid
    char *p = NULL;
    unsigned long pid = strtoul(buf, &p, 10);
    if (errno == ERANGE || (*p && !isspace((unsigned char)(*p)))) {
        return -ERANGE;
    }

    return (pid_t)pid;
}

int pid_write(const char *file)
{
    char buf[64];
    int len = 0;

    if (file == NULL)
        return -EINVAL;

    // make pid string
    len = snprintf(buf, sizeof(buf), "%lu", (unsigned long) getpid());
    if (len < 0)
        return -EINVAL;

    // write to pid file
    int fd = open(file, O_RDWR | O_CREAT, 0644);
    if (fd < 0)
        return -1;

    if (write(fd, buf, len) != len) {
        close(fd);
        return -1;
    }

    return 0;
}

int pid_remove(const char *file)
{
    if (unlink(file) < 0) {
        return -EINVAL;
    }

    return 0;
}

int pid_running(pid_t pid)
{
    return kill(pid, 0) == 0;
}

char *pid_check_and_create(void)
{
    struct stat st;
    char *pidfile = make_pidfile_name();
    pid_t pid = pid_read(pidfile);

    /* Check PID for existence and liveness. */
    if (pid > 0 && pid_running(pid)) {
        printf("Server PID found, already running.\n");
        free(pidfile);
        return NULL;
    } else if (stat(pidfile, &st) == 0) {
        printf("Removing stale PID file '%s'.\n", pidfile);
        pid_remove(pidfile);
    }

    /* Create a PID file. */
    int ret = pid_write(pidfile);
    if (ret != 0) {
        printf("Couldn't create a PID file '%s'.\n", pidfile);
        free(pidfile);
        return NULL;
    }

    return pidfile;
}

/*
 * Return zero on success, otherwise return error code.
 */
static int __lock_file(FILE *file, int command, struct flock *lck)
{
    int error;

    lck->l_type = F_WRLCK;
    lck->l_whence = SEEK_SET;
    lck->l_start = 0;
    lck->l_len = 0;
    lck->l_pid = 0;

    do {
        error = fcntl(fileno(file), command, lck) == -1 ? errno : 0;
    } while (error == EINTR);
    return error;
}

static int lock_file(FILE *file, int command)
{
    struct flock lck;

    return __lock_file(file, command, &lck);
}

int __init_lock(void)
{
	int ret;
    FILE *file;
    struct stat s;
	struct flock lck;

	ret = stat(ADNS_INITFILE, &s);
	if (!ret) {
		unlink(ADNS_INITFILE);
	}
	
	if (errno != ENOENT)
		return -1;

    file = fopen(ADNS_INITFILE, "w+");
	if (file == NULL)
		return -1;

	/* try lock file */
    ret = __lock_file(file, F_GETLK, &lck);
	if (ret) {
		goto err;
	}

    if (lck.l_type == F_UNLCK) {
		/* lock file */
        ret = lock_file(file, F_SETLK);
        if (ret) {
            goto err;
        }

	}
	return 0;

err:
    fclose(file);
	return -1;
}

int init_lock(void)
{
	int ret;
    FILE *file;
    struct stat s;

	ret = stat(ADNS_INITFILE, &s);
	if (!ret) {
		unlink(ADNS_INITFILE);
	} else if (errno != ENOENT)
		return -1;

    file = fopen(ADNS_INITFILE, "w+");
	if (file == NULL)
		return -1;

	return 0;
}

void init_unlock(void)
{
	unlink(ADNS_INITFILE);
}

static pid_t daemonize(int nochdir, int noclose, int exitflag)
{
    pid_t pid;
    int ret;

    /* In case of fork is error. */
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "daemon: fork error\n");
        return -1;
    }

    /* In case of this is parent process. */
    if (pid != 0) {
        if (!exitflag)
            exit(0);
        else
            return pid;
    }

    /* Become session leader and get pid. */
    pid = setsid();
    if (pid < -1) {
        fprintf(stderr, "daemon: setsid error");
        return -1;
    }

    /* Change directory to root. */
    if (!nochdir) {
        ret = chdir("/");
        if (ret < 0) {
            fprintf(stderr, "daemon: chdir error");
        }
    }

    /* File descriptor close. */
    if (!noclose) {
        int fd;

        fd = open("/dev/null", O_RDWR, 0);
        if (fd != -1) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2)
                close(fd);
        }
    }

    umask(0);

    return 0;
}

int daemon_start(void)
{
    char *pidfile;

    pidfile = pid_check_and_create();
    if (pidfile == NULL)
        return -1;
    free(pidfile);

    daemonize(0, 1, 0);

    return 0;
}

