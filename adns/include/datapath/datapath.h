
#ifndef _ADNS_DATAPATH_H_
#define _ADNS_DATAPATH_H_

#include "rte_core.h"

void raw_input_bulk(struct rte_mbuf **m, int nb_pkts, uint8_t port);

#endif

