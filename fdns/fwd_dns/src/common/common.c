
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include<rte_byteorder.h>
#include"common.h"

uint32_t Lhtonl(uint32_t x)
{
    return rte_cpu_to_be_32(x);
//  return htonl(x);
}

uint32_t Lntohl(uint32_t x)
{
    return rte_be_to_cpu_32(x);
//  return ntohl(x);
}

uint16_t Lhtons(uint16_t x)
{
    return rte_cpu_to_be_16(x);
//  return htons(x);
}

uint16_t Lntohs(uint16_t x)
{
    return rte_be_to_cpu_16(x);
//  return ntohs(x);
}

char **str_split(char *a_str, const char a_delim, int *spCount)
{
    char **result = 0;
    size_t count = 0;
    char *tmp = a_str;
    char *last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp) {
        if (a_delim == *tmp) {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
     *  *        knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char *) * count);

    if (result) {
        size_t idx = 0;
        char *token = strtok(a_str, delim);

        while (token) {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    *spCount = count - 1;
    return result;
}

void str_split_free(char **tokens)
{
    int i;
    for (i = 0; *(tokens + i); i++) {
        free(*(tokens + i));
    }
    free(tokens);

}
