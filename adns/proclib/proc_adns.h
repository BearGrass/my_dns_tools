#ifndef __PROC_ADNS_H__
#define __PROC_ADNS_H__

int proc_dns_init();
int ndns_tcp_input(int *append_len, char * tcp_input, int tcp_len, int buf_len, uint32_t sip, struct in6_addr * sip6, int isipv6, char * query_buf, struct answer_log_data * log_data);
int proc_fix_lcore(int lcore);
#define ADNS_DNAME_MAXLEN 255     /*!< 1-byte maximum. from src/libadns/consts.h */
#define TCP_QUERY_NAME_LEN (ADNS_DNAME_MAXLEN+1)

#endif
