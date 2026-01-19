#include<stdio.h>
#include<stdlib.h>
#include <unistd.h>
void test(int i)
{
    printf("test %d ------\n", i);
}

void daemonize(char *output, char *path)
{

    test(1);
    const int M = 256;
    char tmp[M];
    if (output == NULL)
        output = "/dev/null";
    if (path == NULL) {
        //path = get_current_dir_name();
        path = getcwd(tmp, M);
    }
    char file[300];
    sprintf(file, "%s/%s", path, output);
    printf("output:%s,path:%s,file:%s\n", output, path, file);
    pid_t pid = fork();
    if (pid < 0) {
        printf("Error: fork error\n");
        exit(1);
    }

    if (pid > 0) {
        /*let child's parent to be 1 */
        exit(0);
    }

    test(2);
    /*become  session leader */
    pid = setsid();
    test(3);
    FILE *fp = fopen(file, "a");
    if (fp == NULL) {
        printf("Open file %s Fail\n", file);
        exit(1);
    }

    setvbuf(fp, NULL, _IONBF, 0);
    test(4);

    int fd = fileno(fp);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > 2) {
        fclose(fp);
    }

    test(5);
    sleep(30);
}

void main()
{
    daemonize("ldns.out", NULL);
}
