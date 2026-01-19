#include<stdio.h>
#include<stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main()
{
    uint32_t ip = inet_addr("192.168.1.1");
    struct in_addr *i = &ip;
    printf("ip:%ld ->%s\n", ip, inet_ntoa(*i));
    return 0;

}
