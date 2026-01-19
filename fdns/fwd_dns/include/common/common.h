#ifndef _DEF_COMMON_H
#define _DEF_COMMON_H
#include<stdint.h>
#include<string.h>
#include <assert.h>
#include <time.h>


#ifndef RTE_LOGTYPE_LDNS 
#define RTE_LOGTYPE_LDNS RTE_LOGTYPE_USER1
#endif

#ifndef _MAX_LCORE
#define _MAX_LCORE 80
#endif

#define IO_RET_CONTINUE 2
#define IO_RET_PASS 1
#define IO_RET_ANSWER    0
#define IO_RET_ERROR    -1
#define IO_RET_STOLEN   -2
#define IO_RET_DROP     -3
#define IO_RET_FREE     -4

#define LCORE_ID (rte_lcore_id())
#define NOW (rte_get_tsc_cycles()/rte_get_tsc_hz()) 
#define NOW64 rte_get_tsc_cycles()
#define HZ (rte_get_tsc_hz()) 
#define R_LOCK(x) rte_rwlock_read_lock((x))
#define R_UNLOCK(x) rte_rwlock_read_unlock((x))
#define W_LOCK(x) rte_rwlock_write_lock((x))
#define W_UNLOCK(x) rte_rwlock_write_unlock((x))
#define VIP_IPADDR_NUM_MAX 16 /* each type service can has 32 IP addr at most */

#define CONTAINER_OF(ptr,type,member)  ((type *) ((char *) (ptr) - (unsigned long) (&((type *) 0)->member)))

//#define HIP_STR(x) (((uint8_t *)&x)[0],((uint8_t *)&x)[1],((uint8_t *)&x)[2],((uint8_t *)&x)[3])
//#define NIP_STR(x) (((uint8_t *)&x)[3],((uint8_t *)&x)[2],((uint8_t *)&x)[1],((uint8_t *)&x)[0])

#define IP(a,b,c,d) ((_u32)(((a) & 0xff) << 24) | \
                       (((b) & 0xff) << 16) | \
                       (((c) & 0xff) << 8)  | \
                       ((d) & 0xff))
#define HIP_STR(addr) \
	((uint8_t *)&addr)[3], \
	((uint8_t *)&addr)[2], \
	((uint8_t *)&addr)[1], \
	((uint8_t *)&addr)[0]


#define NIP_STR(addr) \
	((uint8_t *)&addr)[0], \
	((uint8_t *)&addr)[1], \
	((uint8_t *)&addr)[2], \
	((uint8_t *)&addr)[3]
#define LOG(format,...) do{ \
							int y ,m ,d, H, M , S; \
							struct tm *ptm; \
							long ts = time(NULL);\
							ptm = localtime(&ts);\
							y = ptm->tm_year + 1900;\
							m = ptm->tm_mon + 1;\
							d = ptm->tm_mday;\
							H = ptm->tm_hour;\
							M = ptm->tm_min;\
							S = ptm->tm_sec;\
						 	printf("info : [ %d/%02d/%02d %02d:%02d:%02d ] "format"\n",y,m,d,H,M,S,##__VA_ARGS__);\
						}while(0)
#define ERROR(format,...)  do{ \
							int y ,m ,d, H, M , S; \
							struct tm *ptm; \
							long ts = time(NULL);\
							ptm = localtime(&ts);\
							y = ptm->tm_year + 1900;\
							m = ptm->tm_mon + 1;\
							d = ptm->tm_mday;\
							H = ptm->tm_hour;\
							M = ptm->tm_min;\
							S = ptm->tm_sec;\
						 	printf("info : [ %d/%02d/%02d %02d:%02d:02%d ] "format"\n",y,m,d,H,M,S,##__VA_ARGS__);\
						}while(0)


#define REQUIRE(x) (assert(x))


//used for kelude code check
#define PRINTF printf
#define SPRINTF sprintf

extern uint32_t Lhtonl(uint32_t x);
extern uint32_t Lntohl(uint32_t x);
extern uint16_t Lhtons(uint16_t x);
extern uint16_t Lntohs(uint16_t x);

extern uint8_t gio_count;
extern uint8_t gio_id[_MAX_LCORE];

extern char** str_split(char* a_str, const char a_delim,int *spCount);
extern void str_split_free(char **tokens);

#endif
