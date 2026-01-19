
#ifndef _ADNS_SYNC_H_
#define _ADNS_SYNC_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>


#define SYNC_PACKET_NUM 8192

#define SOCKET_MTU_SIZE 1500

typedef struct sockaddr_t {
    union {
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    };
    socklen_t len;
    uint16_t prefix;
} sockaddr_t;


struct sync_packet {


};
typedef struct sync_packet sync_packet_t;

/*
 * Process DNS udp sync packet, such as notify, axfr, ixfr
 */
extern void sync_udp_process(int fd);


extern int adns_sync_init(void);
extern void adns_sync_cleanup(void);

#endif

