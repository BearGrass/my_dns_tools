
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <string>
#include <iostream>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sstream>
#include <signal.h>
#include "adnsapi.pb.h"

#define HOST "10.97.209.90"
#define PORT 5858

#define CLIENT_NUM  8
#define CONNECT_NUM 50000
#define PINGPONGS   1
int RR_NUM = 0;
//#define DEBUG

#ifdef DEBUG
#define DEBUG_MSG(str) do { std::cout << str; } while( false )
#else
#define DEBUG_MSG(str) do { } while ( false )
#endif

using namespace std;

double get_wall_time()
{
    struct timeval time;
    if (gettimeofday(&time,NULL)){
        return 0;
    }
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
}

const int ADNSAPI_TYPE_LEN = 32;

int gen_input(char ** p_inputBuf)
{
    int ret = -1;
    int inputSize = -1;
    char * inputBuf = NULL;

    ::adnsapi::RefreshZoneInput rzInput;

    ::adnsapi::Zone * zone = rzInput.mutable_zone();
    zone->set_name("TaObao.cOM.");
    zone->mutable_soa()->set_ns("ns.taobao.com.");
    zone->mutable_soa()->set_mail("mx.taobao.com.");
    zone->mutable_soa()->set_serial(10086);
    zone->mutable_soa()->set_refresh(2400);
    zone->mutable_soa()->set_retry(10);
    zone->mutable_soa()->set_expire(2400);
    zone->mutable_soa()->set_nxttl(7200);
    zone->set_cname_opt(false);

    ::google::protobuf::Map< string, ::adnsapi::DomainAttr > * domains =
        rzInput.mutable_domains();

    //(*domains)["www.taobao.com"].set_schdl_mode(::adnsapi::SCHDL_ALLRR);

    stringstream ss;
//    int sec1, sec2, sec3, sec4;
    char c1 = 'a', c2 = 'a', c3 = 'a', c4 = 'a', c5 = 'a', c6 = 'a';
    ::adnsapi::Rr * rr = NULL;
    for (int j = 0; j < RR_NUM; j++) {
        c1 = 'a' + (j >> 4  >> 4  >> 4  >> 4  >> 4) % 16;
        c2 = 'a' + (j >> 4  >> 4  >> 4  >> 4) % 16;
        c3 = 'a' + (j >> 4  >> 4  >> 4) % 16;
        c4 = 'a' + (j >> 4  >> 4) % 16;
        c5 = 'a' + (j >> 4) % 16;
        c6 = 'a' + j % 16;
        ss << c1 << c2 << c3 << c4 << c5 << c6 << ".taobao.com.";
        (*domains)[ss.str()].set_schdl_mode(::adnsapi::SCHDL_ALLRR);
        rr = (*domains)[ss.str()].add_rr_list();

//        rr = (*domains)["www.taobao.com"].add_rr_list();
        rr->set_view("default");
        rr->set_rrclass("IN");
        rr->set_type(::adnsapi::RRTYPE_A);
        rr->set_ttl(60);

//        sec1 = (j >> 24) % 256;
//        sec2 = (j >> 16) % 256;
//        sec3 = (j >> 8)  % 256;
//        sec4 =  j        % 256;
//        ss << sec1 << "." << sec2 << "." << sec3 << "." << sec4;
//        rr->set_rdata(ss.str());
        rr->set_rdata("1.1.1.1");
        rr->set_weight(10);
        ss.str("");
    }


    inputSize = rzInput.ByteSizeLong();
    inputBuf = (char*)malloc(inputSize + ADNSAPI_TYPE_LEN);

    memset(inputBuf, 0, ADNSAPI_TYPE_LEN);
    sprintf((char*)inputBuf, "refreshzone");

    ret = rzInput.SerializeToArray(inputBuf + ADNSAPI_TYPE_LEN, inputSize);
    if (ret == false) {
        return -1;
    }

    DEBUG_MSG("serialized length: " << inputSize << endl);
    inputSize += ADNSAPI_TYPE_LEN;

    *p_inputBuf = inputBuf;
    return inputSize;
}

int gen_input2(char ** p_inputBuf)
{
    int ret = -1;
    int inputSize = -1;
    char * inputBuf = NULL;

    ::adnsapi::RrInput rrInput;

    rrInput.set_zone_name("TaObao.cOM.");
    rrInput.set_domain_name("ng.TaObao.cOM.");

    ::adnsapi::Rr * rr = rrInput.mutable_rr();

    rr->set_view("default");
    rr->set_rrclass("IN");
    rr->set_type(::adnsapi::RRTYPE_A);
    rr->set_ttl(60);

    rr->set_rdata("1.1.1.1");
    rr->set_weight(10);


    inputSize = rrInput.ByteSizeLong();
    inputBuf = (char*)malloc(inputSize + ADNSAPI_TYPE_LEN);

    memset(inputBuf, 0, ADNSAPI_TYPE_LEN);
    sprintf((char*)inputBuf, "addrr");
    //sprintf((char*)inputBuf, "delrr");

    ret = rrInput.SerializeToArray(inputBuf + ADNSAPI_TYPE_LEN, inputSize);
    if (ret == false) {
        return -1;
    }

    DEBUG_MSG("serialized length: " << inputSize << endl);
    inputSize += ADNSAPI_TYPE_LEN;

    *p_inputBuf = inputBuf;
    return inputSize;
}

int gen_input3(char ** p_inputBuf)
{
    int ret = -1;
    int inputSize = -1;
    char * inputBuf = NULL;

    ::adnsapi::ZoneNameInput zoneNameInput;

    zoneNameInput.set_zone_name("TaObao.cOM.");


    inputSize = zoneNameInput.ByteSizeLong();
    inputBuf = (char*)malloc(inputSize + ADNSAPI_TYPE_LEN);

    memset(inputBuf, 0, ADNSAPI_TYPE_LEN);
    sprintf((char*)inputBuf, "setsoasn");

    ret = zoneNameInput.SerializeToArray(inputBuf + ADNSAPI_TYPE_LEN, inputSize);
    if (ret == false) {
        return -1;
    }

    DEBUG_MSG("serialized length: " << inputSize << endl);
    inputSize += ADNSAPI_TYPE_LEN;

    *p_inputBuf = inputBuf;
    return inputSize;
}

int gen_input4(char ** p_inputBuf)
{
    int ret = -1;
    int inputSize = -1;
    char * inputBuf = NULL;

    ::adnsapi::SetSoaSnInput setSoaSnInput;

    setSoaSnInput.set_zone_name("TaObao.cOM.");
    setSoaSnInput.set_sn(100);


    inputSize = setSoaSnInput.ByteSizeLong();
    inputBuf = (char*)malloc(inputSize + ADNSAPI_TYPE_LEN);

    memset(inputBuf, 0, ADNSAPI_TYPE_LEN);
    sprintf((char*)inputBuf, "setsoasn");

    ret = setSoaSnInput.SerializeToArray(inputBuf + ADNSAPI_TYPE_LEN, inputSize);
    if (ret == false) {
        return -1;
    }

    DEBUG_MSG("serialized length: " << inputSize << endl);
    inputSize += ADNSAPI_TYPE_LEN;

    *p_inputBuf = inputBuf;
    return inputSize;
}


void *pingpong(void *)
{
    int fd, total = 0, ret = -1;

    struct hostent *he;
    struct sockaddr_in server;

    size_t inputSize = 0;
    char * inputBuf = NULL;

    uint32_t len_wire = 0;
    uint32_t reply = 0;
    char respbuf[4096];

    he = gethostbyname(HOST);

    for (int i = 0; i < CONNECT_NUM; i++) {

        /* connect */
        bzero(&server, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(PORT);
        server.sin_addr = *((struct in_addr *)he->h_addr);

        fd = socket(AF_INET, SOCK_STREAM, 0);

        ret = connect(fd, (struct sockaddr *)&server, sizeof(struct sockaddr));
        if (ret != 0) {
            perror("connect error");
            continue;
        }
        //ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int));
        //if (ret == -1) {
        //    perror("setsockopt tcp nodelay");
        //    return (void*)-1;
        //}
        //struct timeval timeout;
        //timeout.tv_sec = 60;
        //timeout.tv_usec = 0;
        //ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
        //if (ret == -1) {
        //    perror("setsockopt timeout");
        //    return (void*)-1;
        //}

        inputSize = gen_input(&inputBuf); // refresh zone
        //inputSize = gen_input2(&inputBuf); // add del rr
        //inputSize = gen_input3(&inputBuf); // lookup soa sn
        //inputSize = gen_input4(&inputBuf); // set soa sn

        if (inputSize < 0) {
            continue;
        }

        //len_wire = htonl(inputSize);
        len_wire = htonl(inputSize);
        for (int k = 0; k < PINGPONGS; k++) {
            /* send msg header (length) */
            total = write(fd, (void*)&len_wire, sizeof(uint32_t));
            if (total < 0) {
                perror("write error");
                continue;
            }
            DEBUG_MSG("sent length 1: " << total << endl);

            /* send msg content */
            const int BURST = inputSize / 1;
            for (int j = 0, _total = 0; j * BURST < inputSize; j++) {
                if ( (inputSize - j * BURST) > BURST ) {
                    _total += write(fd, (char*)inputBuf + j * BURST, BURST);
                } else {
                    _total += write(fd, (char*)inputBuf + j * BURST, inputSize - j * BURST);
                }
                if (_total < 0) {
                    perror("send msg error");
                }
            }
            DEBUG_MSG("sent length 2: " << total << endl);
            free(inputBuf);

            /* recv response */
            for (int sofar = 0, nread = 0; sofar < sizeof(uint32_t);) {
                nread = read(fd, ((char*)&reply) + sofar, sizeof(uint32_t) - sofar);
                if (nread < 0) {
                    if (errno == EAGAIN) {
                        continue;
                    } else {
                        perror("recv error");
                        break;
                    }
                } else if (nread == 0) {
                    break;
                } else {
                    sofar += nread;
                }
            }
            reply = ntohl(reply);
            DEBUG_MSG("reply from server: " << endl << "    len: " << reply << endl);

            for (int sofar = 0, nread = 0; sofar < reply;) {
                nread = read(fd, respbuf + sofar, reply - sofar);
                if (nread < 0) {
                    if (errno == EAGAIN) {
                        continue;
                    } else {
                        perror("recv error");
                        break;
                    }
                } else if (nread == 0) {
                    break;
                } else { sofar += nread; }
            }
            ::adnsapi::CommonOutput output;
            output.ParseFromArray(respbuf, reply);

            DEBUG_MSG("    content: " << output.code() << " " << output.msg() << endl);

/*
            ::adnsapi::LookupSoaSnOutput output;
            output.ParseFromArray(respbuf, reply);

            DEBUG_MSG("    content: " << output.base().code() << " " << output.base().msg() 
                    << " " << output.sn() << endl);
*/
        }
        close(fd);
    }
}

int main(int argc, char ** argv)
{

    if (argc != 2) {
        printf("please input rr num.\n");
        return -1;
    }
    RR_NUM = atoi(argv[1]);
    printf("input %d\n", RR_NUM);

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        printf("ignore NOSIGPIPE error.");
        return -1;
    }
    pthread_t tid[CLIENT_NUM];
    for (int i = 0; i < CLIENT_NUM; i++) {
        pthread_create(&tid[i], NULL, pingpong, NULL);
    }

    for (int i = 0; i < CLIENT_NUM; i++) {
        pthread_join(tid[i], NULL);
    }

    cout << endl
         << "clients: " << CLIENT_NUM << endl
         << "connetions per client: " << CONNECT_NUM << endl
         << "PINGPONGS per conn: " << PINGPONGS << endl
         << "RRs: " << RR_NUM << endl << endl;

    return 0;
}
