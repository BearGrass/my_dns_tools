#include<string.h>
#include<stdio.h>
int main()
{
    char buf[4096];
    char tmp[200];
    memset(buf, 0, sizeof(buf));
    sprintf(tmp, "worker_num: %02d \r\n", 3);
    strcat(buf, tmp);
    sprintf(tmp, "server_time: %d:%-3d:%d \r\n", 2014, 3, 20);
    strcat(buf, tmp);
    sprintf(tmp, "\r\n");
    strcat(buf, tmp);
    sprintf(tmp, "%d %d \r\nend\r\n", 1, 2);
    strcat(buf, tmp);
    printf("%s,len=%d", buf, strlen(buf));
    return 0;
}
