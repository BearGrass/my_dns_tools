#ifndef _FDNS_DNAME_H_
#define _FDNS_DNAME_H_

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "consts.h"
#include "wire.h"
#include "tolower.h"
#include "dns_pkt.h"

typedef uint8_t adns_dname_t;

static inline int __attribute__ ((always_inline))
    adns_dname_size(const adns_dname_t * name)
{
    if (unlikely(name == NULL))
        return -EINVAL;

    /* Count name size without terminal label. */
    int len = 0;
    while (*name != '\0') {
        /* Compression pointer is 2 octets. */
        if (adns_wire_is_pointer(name)) {
            return len + 2;
        }

        uint8_t lblen = *name + 1;
        len += lblen;
        name += lblen;
    }

    return len + 1;
}

static inline int __attribute__ ((always_inline))
    adns_dname_labels(const uint8_t * name)
{
    if (name == NULL)
        return -1;

    uint8_t count = 0;
    while (*name != '\0') {
        ++count;
        name += (*name + 1);
        if (!name)
            return -1;
    }
    return count;
}

/* For performance issue there is below limitation in these fast functions:
 *   1. No any validation in this function
 *   2. Does not support domain name compression
 *   3. Does not support \x format
 * please make sure the qname is validated and the buff is enough.
 * Please pay attention to that the endp points to the next position of
 * query packet's last valid octet.
 */
static inline int __attribute__ ((always_inline))
adns_qname_valid_size_fast(const adns_dname_t * qname, const uint8_t * endp,
        uint8_t *labels, uint8_t *buff)
{
    /* Count name size with terminal label (\x00). */
    int name_len = 1;
    const uint8_t *next_label;
    *labels = 0;

    while (*qname != '\0') {
        /* Check label length (maximum 63 bytes allowed). */
        if (*qname > LABEL_MAX_SIZE) {
            return -1;
        }
        uint8_t lblen = *qname + 1;
        name_len += lblen;

        if (unlikely(name_len > ADNS_DNAME_MAXLEN)) {
            return -1;
        }
        next_label = qname + lblen;

        /* Check if there's enough space in the name buffer.
         */
        if (unlikely(next_label >= endp)) {
            return -ENOSPC;
        }
        *buff++ = *qname++;

        do {
            *buff++ = adns_tolower(*qname++);
        } while (qname < next_label);
        (*labels)++;
    }
    *buff = '\0';

    return name_len;
}

static inline void __attribute__ ((always_inline))
adns_qname_to_lower_fast(adns_dname_t *qname, adns_dname_t *buff)
{
    adns_dname_t *next_label;

    while (*qname != '\0') {
        next_label = qname + *qname + 1;
        *buff++ = *qname++;

        do {
            *buff++ = adns_tolower(*qname++);
        } while (qname != next_label);
    }
    *buff = '\0';
}

static inline int __attribute__ ((always_inline))
adns_qname_sub_to_lower_fast(adns_dname_t *qname, int sub_labels,
        adns_dname_t *buff, int *qname_len) {
    int qname_labels;

    qname_labels = adns_dname_labels(qname);

    while (qname_labels > sub_labels) {
        qname_labels--;
        *qname_len -= (*qname + 1);
        qname += (*qname + 1);
    }
    adns_qname_to_lower_fast(qname, buff);

    return qname_labels;
}

static inline const uint8_t *__attribute__ ((always_inline))
adns_qname_to_str_fast(const adns_dname_t *qname, char * buff)
{
    uint8_t lblen;
    uint16_t str_len = 0;

    if(unlikely((lblen = *qname) == 0)) {
        buff[0] = '.';
        buff[1] = '\0';

        return ++qname;
    }

    while (lblen != 0) {
        qname++;
        rte_memcpy(buff+str_len, qname, lblen);
        str_len += lblen;
        qname += lblen;
        lblen = *qname;
        // Write label separation.
        buff[str_len++] = '.';
    }

    // String_termination.
    buff[str_len] = '\0';

    return ++qname;
}

#endif
