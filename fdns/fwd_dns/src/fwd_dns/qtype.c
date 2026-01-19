#include "qtype.h"
#include <string.h>
#include "rte_core.h"
#include <assert.h>
char dns_qtype[RTE_MAX_NUMA_NODES][U16_MAX + 1][QTYPE_LEN];
char status_str[16][20];
static void qtn(int i, int qtype, char *str)
{
    assert(strlen(str) < QTYPE_LEN);
    memset(dns_qtype[i][qtype], 0, sizeof(dns_qtype[i][qtype]));
    strcpy(dns_qtype[i][qtype], str);
}

void init_dns_qtype()
{
    int i, j;
    memset(dns_qtype, 0, sizeof(dns_qtype));
    for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
        for (j = 0; j <= U16_MAX; j++) {
            sprintf(dns_qtype[i][j], "%d", j);
        }
    }
    for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
        qtn(i, 0, "NONE");
        qtn(i, 1, "A");
        qtn(i, 2, "NS");
        qtn(i, 3, "MD");
        qtn(i, 4, "MF");
        qtn(i, 5, "CNAME");
        qtn(i, 6, "SOA");
        qtn(i, 7, "MB");
        qtn(i, 8, "MG");
        qtn(i, 9, "MR");

        qtn(i, 10, "NULL");
        qtn(i, 11, "WKS");
        qtn(i, 12, "PTR");
        qtn(i, 13, "HINFO");
        qtn(i, 14, "MINFO");
        qtn(i, 15, "MX");
        qtn(i, 16, "TXT");
        qtn(i, 17, "RP");
        qtn(i, 18, "AFSDB");
        qtn(i, 19, "X25");

        qtn(i, 20, "ISDN");
        qtn(i, 21, "RT");
        qtn(i, 22, "NSAP");
        qtn(i, 23, "NSAP_PTR");
        qtn(i, 24, "SIG");
        qtn(i, 25, "KEY");
        qtn(i, 26, "PX");
        qtn(i, 27, "GPOS");
        qtn(i, 28, "AAAA");
        qtn(i, 29, "LOC");

        qtn(i, 30, "NXT");
        qtn(i, 33, "SRV");
        qtn(i, 35, "NAPTR");
        qtn(i, 36, "KX");
        qtn(i, 37, "CERT");
        qtn(i, 38, "A6");
        qtn(i, 39, "DNAME");

        qtn(i, 41, "OPT");
        qtn(i, 42, "APL");
        qtn(i, 43, "DS");
        qtn(i, 44, "SSHFP");
        qtn(i, 45, "IPSECKEY");
        qtn(i, 46, "RRSIG");
        qtn(i, 47, "NSEC");
        qtn(i, 48, "DNSKEY");
        qtn(i, 49, "DHCID");

        qtn(i, 50, "NSEC3");
        qtn(i, 51, "NSEC3PARAM");
        qtn(i, 52, "TLSA");
        qtn(i, 55, "HIP");

        qtn(i, 99, "SPF");
        qtn(i, 103, "UNSPEC");
        qtn(i, 104, "NID");
        qtn(i, 105, "L32");
        qtn(i, 106, "L64");
        qtn(i, 107, "LP");
        qtn(i, 108, "EUI48");
        qtn(i, 109, "EUI64");
        qtn(i, 249, "TKEY");
        qtn(i, 250, "TSIG");
        qtn(i, 251, "IXFR");
        qtn(i, 252, "AXFR");
        qtn(i, 253, "MAILB");
        qtn(i, 254, "MAILA");
        qtn(i, 255, "ANY");

    }

    memset(status_str, 0, sizeof(status_str));
    strcpy(status_str[0], "NOERROR");
    strcpy(status_str[1], "FORMAT_ERROR");
    strcpy(status_str[2], "SERVFAIL");
    strcpy(status_str[3], "NXDOMAIN");
    strcpy(status_str[4], "NOT_IMPLEMENT");
    strcpy(status_str[5], "REFUSED");
    for (i = 6; i < 15; i++)
        sprintf(status_str[i], "%d", i);
}

