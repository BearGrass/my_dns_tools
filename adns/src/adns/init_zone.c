
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>

#include "init_zone.h"
#include "descriptor.h"
#include "errcode.h"
#include "zone.h"
#include "rrset.h"
#include "node.h"
#include "domain_hash.h"
#include "dname.h"
#include "zonedb.h"
#include "private_route.h"

#include "log.h"


int adns_zonedb_load_init(void)
{
    int ret;

    /* init zonedb */
    ret = adns_zonedb_init();
    if (ret < 0) {
        goto err_zonedb;
    }

    /* zone mempool init */
    ret = adns_zone_init();
    if (ret < 0) {
        goto err_zone;
    }

    /* node mempool init */
    ret = adns_node_init();
    if (ret < 0) {
        goto err_node;
    }

    /* rrset mempool init */
    ret = rrset_init();
    if (ret < 0) {
        goto err_rrset;
    }

    /* private route mempool init */
    ret = adns_private_route_init();
    if (ret < 0) {
        goto err_private_route;
    }

    ret = adns_domaindb_init();
    if(ret < 0){
        goto err_rrset;
    }

    return 0;

err_private_route:
err_rrset:
err_node:
err_zone:
    adns_zonedb_cleanup();
err_zonedb:
    return -1;
}

void adns_zonedb_load_cleanup(void)
{
}

