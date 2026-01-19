
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

#include "rte_core.h"
#include "common.h"
#include "ldns.h"
char *run_dir = NULL;

struct app_params app;
char *cfg_profile = NULL;

/*
 * Display the usage for teh command line.
 */
void ldns_usage(const char *prgname)
{
    printf("Usage: %s [EAL options] -- -p PORTMASK [-h] [-f conf_file]\n"
           "  -p PORTMASK  hexadecimal bitmask of ports to configure\n"
           "  -f filename  Configuture file for ldns\n"
           "  -h           Display the help information\n", prgname);
}

/* Return true if socket used, otherwise return false */
int is_socket_used(uint32_t socket)
{
    uint32_t lcore;

    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        if (app.lcore_params[lcore].type == e_LCORE_DISABLED) {
            continue;
        }

        if (socket == rte_lcore_to_socket_id(lcore)) {
            return 1;
        }
    }

    return 0;
}

/* Get rx queue number for specified port */
int get_nic_rx_queues_per_port(uint8_t port)
{
    uint32_t i, count;

    if (port >= RTE_MAX_ETHPORTS) {
        return -1;
    }

    count = 0;
    for (i = 0; i < MAX_RX_QUEUES_PER_NIC_PORT; i++) {
        if (app.nic_rx_queue_mask[port][i] == 1) {
            count++;
        }
    }

    return count;
}

/* Get tx queue number for specified port */
int get_nic_tx_queues_per_port(uint8_t port)
{
    uint32_t i, count;

    if (port >= RTE_MAX_ETHPORTS) {
        return -1;
    }

    count = 0;
    for (i = 0; i < MAX_RX_QUEUES_PER_NIC_PORT; i++) {
        if (app.nic_tx_queue_mask[port][i] == 1) {
            count++;
        }
    }

    return count;
}

/* 
 * Get which lcore poll <port:queue> 
 * Return 0 on success, otherwise return -1
 */
int get_lcore_for_nic_rx(uint8_t port, uint8_t queue, uint32_t * lcore_out)
{
    uint32_t lcore;

    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        struct lcore_params_io *lp = &app.lcore_params[lcore].io;
        uint32_t i;

        if (app.lcore_params[lcore].type == e_LCORE_KNI) {
            if (queue != 0)
                continue;
            *lcore_out = lcore;
            return 0;
        }

        if (app.lcore_params[lcore].type != e_LCORE_IO) {
            continue;
        }

        for (i = 0; i < lp->n_rx_queues; i++) {
            if ((lp->rx_queues[i].port_id == port) &&
                (lp->rx_queues[i].queue_id == queue)) {
                *lcore_out = lcore;
                return 0;
            }
        }
    }

    return -1;
}

int get_lcore_for_nic_tx(uint8_t port, uint8_t queue, uint32_t * lcore_out)
{
    uint32_t lcore;

    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        struct lcore_params_io *lp = &app.lcore_params[lcore].io;
        uint32_t i;

        if (app.lcore_params[lcore].type == e_LCORE_KNI) {
            if (queue != 0)
                continue;
            *lcore_out = lcore;
            return 0;
        }

        if (app.lcore_params[lcore].type != e_LCORE_IO) {
            continue;
        }

        for (i = 0; i < lp->n_rx_queues; i++) {
            if ((lp->tx_queues[i].port_id == port) &&
                (lp->tx_queues[i].queue_id == queue)) {
                *lcore_out = lcore;
                return 0;
            }
        }
    }

    return -1;
}

/* Make port mask from string to int */
static int parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

/* Parsing command line */
int ldns_parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {"portmask", 1, 0, 0},
        {"config", 1, 0, 0},
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    app.argc = argc;
    for (opt = 0; opt < argc; opt++)
        app.argv[opt] = strdup(argv[opt]);

    while ((opt = getopt_long(argc, argvopt, "p:f:h",
                              lgopts, &option_index)) != EOF) {
        switch (opt) {
            case 'p':          /* Port mask (required) */
                app.portmask = parse_portmask(optarg);
                if (app.portmask < 0) {
                    printf("invalid portmask\n");
                    ldns_usage(prgname);
                    return -1;
                }
                break;
            case 'f':          /* config file name */
                if (optarg[0] != '/') {
                    cfg_profile = malloc(PATH_MAX);
                    assert(cfg_profile);
                    snprintf(cfg_profile, PATH_MAX, "%s/%s", run_dir, optarg);
                } else {
                    cfg_profile = optarg;
                }
                fprintf(stderr, "=== config file: %s\n", cfg_profile);
                break;
            case 'h':          /* print usage */
                ldns_usage(prgname);
                return -1;
            default:
                ldns_usage(prgname);
                return -1;
        }
    }

    app.nic_rx_ring_size = DEFAULT_NIC_RX_RING_SIZE;
    app.nic_tx_ring_size = DEFAULT_NIC_TX_RING_SIZE;

    /* If the port mask is not set we exit with usage message. */
    if (app.portmask == 0) {
        printf("Must specify the portmask\n");
        ldns_usage(prgname);
        return -1;
    }

    /* Setup the program name */
    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 0;                 /* reset getopt lib */
    return ret;
}

/* Print params */
void app_print_params(void)
{
    unsigned port, queue, lcore, i;

    /* Print NIC RX configuration */
    printf("NIC RX ports: ");
    for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
        uint32_t n_rx_queues = get_nic_rx_queues_per_port((uint8_t) port);

        if (n_rx_queues == 0) {
            continue;
        }

        printf("%u (", port);
        for (queue = 0; queue < MAX_RX_QUEUES_PER_NIC_PORT; queue++) {
            if (app.nic_rx_queue_mask[port][queue] == 1) {
                printf("%u ", queue);
            }
        }
        printf(")  ");
    }
    printf(";\n");

    /* Print Misc lcore Rx params */

    /* Print I/O lcore RX params */
    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        struct lcore_params_io *lp = &app.lcore_params[lcore].io;

        if (app.lcore_params[lcore].type != e_LCORE_IO || lp->n_rx_queues == 0) {
            continue;
        }

        if (app.lcore_params[lcore].type == e_LCORE_IO) {
            printf("I/O lcore %u (socket %u): ", lcore,
                   rte_lcore_to_socket_id(lcore));

            printf("RX ports  ");
            for (i = 0; i < lp->n_rx_queues; i++) {
                printf("(%u, %u)  ",
                       (unsigned)lp->rx_queues[i].port_id,
                       (unsigned)lp->rx_queues[i].queue_id);
            }
        }
        printf(";\n");
    }

    printf("\n");

    /* Print NIC TX configuration */
    printf("NIC TX ports: ");
    for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
        uint32_t n_tx_queues = get_nic_tx_queues_per_port((uint8_t) port);

        if (n_tx_queues == 0) {
            continue;
        }

        printf("%u (", port);
        for (queue = 0; queue < MAX_TX_QUEUES_PER_NIC_PORT; queue++) {
            if (app.nic_tx_queue_mask[port][queue] == 1) {
                printf("%u ", queue);
            }
        }
        printf(")  ");
    }
    printf(";\n");

    /* Print I/O lcore TX params */
    for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
        struct lcore_params_io *lp = &app.lcore_params[lcore].io;

        if (app.lcore_params[lcore].type != e_LCORE_IO || lp->n_tx_queues == 0)
            continue;

        printf("I/O lcore %u (socket %u): ", lcore,
               rte_lcore_to_socket_id(lcore));

        printf("TX ports  ");
        for (i = 0; i < lp->n_tx_queues; i++) {
            printf("(%u, %u)  ",
                   (unsigned)lp->tx_queues[i].port_id,
                   (unsigned)lp->tx_queues[i].queue_id);
        }

        printf(";\n");
    }
}
