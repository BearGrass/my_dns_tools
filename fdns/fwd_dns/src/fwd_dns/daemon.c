#include<stdio.h>
#include<stdlib.h>
#include <unistd.h>
#include "daemon.h"
void daemonize(char *output, char *path)
{

    const int M = 256;
    char tmp[M];
    if (output == NULL)
        output = "/dev/null";
    if (path == NULL)
        path = getcwd(tmp, M);;
    char file[M];
    sprintf(file, "%s/%s", path, output);
    pid_t pid = fork();
    if (pid < 0) {
        printf("Error: fork error\n");
        exit(1);
    }

    if (pid > 0) {
        /*let child's parent to be 1 */
        exit(0);
    }

    /*become  session leader */
    pid = setsid();
    FILE *fp = fopen(file, "a");
    if (fp == NULL) {
        printf("Open file %s Fail\n", file);
        exit(1);
    }

    setvbuf(fp, NULL, _IONBF, 0);

    printf("Change output to %s\n ", file);
    int fd = fileno(fp);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2) {
        fclose(fp);
    }

}
