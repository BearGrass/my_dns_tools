
#ifndef _LDNS_LOG_DEF_H_
#define _LDNS_LOG_DEF_H_

#include <stdint.h>
#include <stdlib.h>


typedef enum LOG_TYPE {
    LOG_SERVER,
    LOG_QUERY,
    LOG_ANSWER,
	LOG_SECURE,
    LOG_FILE_NUM
}LOG_TYPE_T;

typedef enum LOG_LEVEL{
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_LEVEL_NUM
}LOG_LEVEL_T;

typedef char * (*log_fmt_fun_t)(uint32_t, uint8_t *, uint16_t *);
struct log_msg {
    uint32_t lcore_id;
    LOG_TYPE_T log_type;
    LOG_LEVEL_T log_leve;
    log_fmt_fun_t fmt_fun;
    uint8_t data[0];
};
typedef struct log_msg log_msg_t;
#define LOG_MSG_DATA_SIZE (LOG_SIZE - sizeof(log_msg_t))

static const char * const log_type_str[LOG_FILE_NUM] = {
        "SERVER", "QUERY", "ANSWER", "SECURE"
};
static const char * const log_level_str[LOG_LEVEL_NUM] = {
        "ERROR", "WARN", "INFO", "DEBUG"
};

#endif

