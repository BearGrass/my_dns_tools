
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <rte_atomic.h>
#include "adns_fdir.h"
#include "common.h"

// Maximum support 1024 fdir rules.
#define FDIR_MAX_SIZE (1<<10)
static rte_atomic16_t sid;

struct fdir_rule {
    struct rte_fdir_filter filter;
    int id;                     // used as soft_id on perfect mode
    int used;
};

struct fdir_port {
    /*struct list_head list; */
    int count;
};

static struct fdir_port fdir_ports[RTE_MAX_ETHPORTS];
static struct fdir_rule *fdir_rule_tbl[RTE_MAX_ETHPORTS] = { NULL };

static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];

static int port_id_is_invalid(uint8_t port_id)
{
    /*if (port_id < nb_ports) */
    if (port_id < 2)
        return 0;
    printf("Invalid port %d (must be < nb_ports=%d)\n", port_id,
           RTE_MAX_ETHPORTS);

    return 1;
}

static void fdir_set_masks(uint8_t port_id, struct rte_fdir_masks *fdir_masks)
{
    int diag;

    if (port_id_is_invalid(port_id))
        return;

    diag = rte_eth_dev_fdir_set_masks(port_id, fdir_masks);
    if (diag == 0)
        return;

    printf("rte_eth_dev_set_masks_filter for port_id=%d failed diag=%d\n",
           port_id, diag);
}

static int port_reg_off_is_invalid(uint8_t port_id, uint32_t reg_off)
{
    uint64_t pci_len;

    if (reg_off & 0x3) {
        printf("Port register offset 0x%X not aligned on a 4-byte "
               "boundary\n", (unsigned)reg_off);
        return -1;
    }

    pci_len = dev_info[port_id].pci_dev->mem_resource[0].len;
    if (reg_off >= pci_len) {
        printf("Port %d: register offset %u (0x%X) out of port PCI "
               "resource (length=%" PRIu64 ")\n",
               port_id, (unsigned)reg_off, (unsigned)reg_off, pci_len);
        return -1;
    }

    return 0;
}

/*
 * Read operations on a PCI register of a port.
 */
static inline uint32_t port_pci_reg_read(uint8_t port_id, uint32_t reg_off)
{
    void *reg_addr;
    uint32_t reg_v;

    reg_addr = (void *)
        ((char *)dev_info[port_id].pci_dev->mem_resource[0].addr + reg_off);
    reg_v = *((volatile uint32_t *)reg_addr);
    return rte_le_to_cpu_32(reg_v);
}

static inline void
display_port_reg_value(uint8_t port_id, uint32_t reg_off, uint32_t reg_v)
{
    printf("port %d PCI register at offset 0x%X: ", port_id, reg_off);
    printf("0x%08X (%u)\n", (unsigned)reg_v, (unsigned)reg_v);
}

static void __adns_fdir_reg_dump(uint8_t port_id, uint32_t reg_off)
{
    uint32_t reg_v;

    if (port_id_is_invalid(port_id))
        return;

    if (port_reg_off_is_invalid(port_id, reg_off))
        return;

    reg_v = port_pci_reg_read(port_id, reg_off);
    display_port_reg_value(port_id, reg_off, reg_v);
}

// flow director filters control register -- FDIRCTRL
#define FDIRCTRL_OFF 0x0EE00
// Flow Director Filters Other Mask — FDIRM
#define FDIRM_OFF 0x0EE70

static void adns_fdir_reg_dump(uint8_t port_id)
{
    // FDIRCTRL
    __adns_fdir_reg_dump(port_id, FDIRCTRL_OFF);
    // FDIRM
    __adns_fdir_reg_dump(port_id, FDIRM_OFF);
}

static void adns_fdir_set_mask(struct adns_fdir_masks *masks)
{
    struct rte_fdir_masks fdir_masks;

#if 0
    if (masks->mode != ADNS_FDIR_PERFECT)
        return;
#endif

    memset(&fdir_masks, 0, sizeof(struct rte_fdir_masks));

    fdir_masks.set_ipv6_mask = 0;   // set IPv4
    fdir_masks.only_ip_flow = masks->only_ip_flow;
    fdir_masks.vlan_id = 0;
    fdir_masks.vlan_prio = 0;
    fdir_masks.dst_ipv4_mask = masks->dst_ipv4_mask;
    fdir_masks.src_ipv4_mask = masks->src_ipv4_mask;
    fdir_masks.src_port_mask = masks->src_port_mask;
    fdir_masks.dst_port_mask = masks->dst_port_mask;
    fdir_masks.flexbytes = 0;   // not relevant to flexbytes
    fdir_masks.comp_ipv6_dst = 0;

    fdir_set_masks(masks->port_id, &fdir_masks);
}

static void fdir_add_perfect_filter(uint8_t port_id, uint16_t soft_id,
                                    uint8_t queue_id, uint8_t drop,
                                    struct rte_fdir_filter *fdir_filter)
{
    int diag;

    if (port_id_is_invalid(port_id))
        return;

    diag = rte_eth_dev_fdir_add_perfect_filter(port_id, fdir_filter,
                                               soft_id, queue_id, drop);
    struct rte_eth_fdir fdir_infos;

    static const char *fdir_stats_border = "########################";

    if (port_id_is_invalid(port_id))
        return;

    rte_eth_dev_fdir_get_infos(port_id, &fdir_infos);

    printf("\n  %s FDIR infos for port %-2d     %s\n",
           fdir_stats_border, port_id, fdir_stats_border);

    printf("  collision: %-10" PRIu64 "  free:     %" PRIu64 "\n"
           "  maxhash:   %-10" PRIu64 "  maxlen:   %" PRIu64 "\n"
           "  add:       %-10" PRIu64 "  remove:   %" PRIu64 "\n"
           "  f_add:     %-10" PRIu64 "  f_remove: %" PRIu64 "\n",
           (uint64_t) (fdir_infos.collision), (uint64_t) (fdir_infos.free),
           (uint64_t) (fdir_infos.maxhash), (uint64_t) (fdir_infos.maxlen),
           fdir_infos.add, fdir_infos.remove,
           fdir_infos.f_add, fdir_infos.f_remove);
    printf("  %s############################%s\n",
           fdir_stats_border, fdir_stats_border);
    if (diag == 0) {
        printf
            ("rte_eth_dev_fdir_add_perfect_filter for port_id=%d , queue_id = %d , dport = %d ok \n",
             port_id, queue_id, Lntohs(fdir_filter->port_dst));
        return;
    }

    printf
        ("rte_eth_dev_fdir_add_perfect_filter for port_id=%d , queue_id = %d , dport = %d fail,diag = %d \n",
         port_id, soft_id, Lntohs(fdir_filter->port_dst), diag);
}

static void fdir_update_perfect_filter(uint8_t port_id, uint16_t soft_id,
                                       uint8_t queue_id, uint8_t drop,
                                       struct rte_fdir_filter *fdir_filter)
{
    int diag;

    if (port_id_is_invalid(port_id))
        return;

    diag = rte_eth_dev_fdir_update_perfect_filter(port_id, fdir_filter,
                                                  soft_id, queue_id, drop);
    if (diag == 0)
        return;

    printf("rte_eth_dev_fdir_update_perfect_filter for port_id=%d failed "
           "diag=%d\n", port_id, diag);
}

static void fdir_remove_perfect_filter(uint8_t port_id, uint16_t soft_id,
                                       struct rte_fdir_filter *fdir_filter)
{
    int diag;

    if (port_id_is_invalid(port_id))
        return;

    diag = rte_eth_dev_fdir_remove_perfect_filter(port_id, fdir_filter,
                                                  soft_id);
    if (diag == 0)
        return;

    printf("rte_eth_dev_fdir_update_perfect_filter for port_id=%d failed "
           "diag=%d\n", port_id, diag);
}

static int adns_fdir_handle(struct adns_fdir_filter *filter_user)
{
    uint8_t drop;
    struct rte_fdir_filter fdir_filter;

    memset(&fdir_filter, 0, sizeof(struct rte_fdir_filter));

    // Only support ipv4 now.
    fdir_filter.ip_src.ipv4_addr = filter_user->src_addr;
    fdir_filter.ip_dst.ipv4_addr = filter_user->dst_addr;

    fdir_filter.port_dst = rte_cpu_to_be_16(filter_user->dst_port);
    fdir_filter.port_src = rte_cpu_to_be_16(filter_user->src_port);

    //fdir_filter.l4type = RTE_FDIR_L4TYPE_UDP;
    if (filter_user->protocol == IPPROTO_UDP)
        fdir_filter.l4type = RTE_FDIR_L4TYPE_UDP;
    else if (filter_user->protocol == IPPROTO_TCP)
        fdir_filter.l4type = RTE_FDIR_L4TYPE_TCP;
    else if (filter_user->protocol == IPPROTO_SCTP)
        fdir_filter.l4type = RTE_FDIR_L4TYPE_SCTP;
    else
        fdir_filter.l4type = RTE_FDIR_L4TYPE_NONE;
    fdir_filter.iptype = RTE_FDIR_IPTYPE_IPV4;

    fdir_filter.vlan_id = rte_cpu_to_be_16(0);
    fdir_filter.flex_bytes = rte_cpu_to_be_16(0);

    /*drop = filter_user->queue_id < 0 ? 1 : 0; */
    drop = 0;

    // Only use fdir perfect mode
    if (filter_user->opcode == ADNS_FDIR_ADD)
        fdir_add_perfect_filter(filter_user->port_id, filter_user->soft_id,
                                filter_user->queue_id, drop, &fdir_filter);
    else if (filter_user->opcode == ADNS_FDIR_UPDATE)
        fdir_update_perfect_filter(filter_user->port_id, filter_user->soft_id,
                                   filter_user->queue_id, drop, &fdir_filter);
    else if (filter_user->opcode == ADNS_FDIR_DEL)
        fdir_remove_perfect_filter(filter_user->port_id, filter_user->soft_id,
                                   &fdir_filter);

    return 0;
}

/*static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];*/
static int adns_get_dev_info(void)
{
    int i;

    for (i = 0; i < 1; i++) {
        rte_eth_dev_info_get(i, &dev_info[i]);
    }

    return 0;
}

static int adns_fdir_set(void)
{
    int i;
    struct adns_fdir_masks port_masks[2];

    adns_get_dev_info();

    // set masks
    for (i = 0; i < 2; i++) {
        memset(&port_masks[i], 0, sizeof(struct adns_fdir_masks));

        port_masks[i].port_id = i;
        port_masks[i].mode = 0; // Use perfect mode
        port_masks[i].only_ip_flow = 0;
        port_masks[i].src_port_mask = 0;
        port_masks[i].dst_port_mask = 0xffff;
        port_masks[i].src_ipv4_mask = 0;
        port_masks[i].dst_ipv4_mask = 0;
        adns_fdir_set_mask(&port_masks[i]);
    }

    sleep(1);

    // Dump mask register
    for (i = 0; i < 1; i++) {
        adns_fdir_reg_dump(i);
    }
/*
	struct adns_fdir_filter filter;
	memset(&filter, 0, sizeof(struct adns_fdir_filter));

	// redirect ospf packet to kni lcore, iface: vEth1,veth0, port_id=1,0
	filter.opcode = ADNS_FDIR_ADD;
	filter.port_id = 1;
	filter.queue_id = 0;
	filter.soft_id = 0;
	filter.dst_addr = rte_cpu_to_be_32(0xe0000005);
	adns_fdir_handle(&filter);

	memset(&filter, 0, sizeof(struct adns_fdir_filter));
	filter.opcode = ADNS_FDIR_ADD;
	filter.port_id = 0;
	filter.queue_id = 0;
	filter.soft_id = 0;
	filter.dst_addr = rte_cpu_to_be_32(0xe0000005);
	adns_fdir_handle(&filter);

	filter.opcode = ADNS_FDIR_ADD;
	filter.port_id = 1;
	filter.queue_id = 0;
	filter.soft_id = 0;
	filter.dst_addr = rte_cpu_to_be_32(0xe0000006);
	adns_fdir_handle(&filter);

	filter.opcode = ADNS_FDIR_ADD;
	filter.port_id = 0;
	filter.queue_id = 0;
	filter.soft_id = 0;
	filter.dst_addr = rte_cpu_to_be_32(0xe0000006);
	adns_fdir_handle(&filter);
*/
    return 0;
}

int add_fdir_port(uint16_t dport, int queue_id, int i_port)
{
    struct adns_fdir_filter filter;
    memset(&filter, 0, sizeof(struct adns_fdir_filter));
    filter.opcode = ADNS_FDIR_ADD;
    filter.port_id = i_port;
    filter.queue_id = queue_id;

    filter.soft_id = rte_atomic16_add_return(&sid, 1);;
    filter.dst_port = dport;
    filter.protocol = IPPROTO_UDP;
    adns_fdir_handle(&filter);
    return 0;
}

int adns_fdir_init(void)
{
    int i, j, ret;
    rte_atomic16_init(&sid);
    rte_atomic16_set(&sid, 1);

    // init each port fdir meta struct
    /*for (i = 0; i < RTE_MAX_ETHPORTS; i++) { */
    for (i = 0; i < 1; i++) {
        fdir_ports[i].count = 0;
        /*INIT_LIST_HEAD(&fdir_ports[i].list); */
    }

    // prealloc memory for fdir rule table
    /*for (i = 0; i < RTE_MAX_ETHPORTS; i++) { */
    for (i = 0; i < 1; i++) {
        fdir_rule_tbl[i] = (struct fdir_rule *)malloc(sizeof(struct fdir_rule)
                                                      * FDIR_MAX_SIZE);
        if (fdir_rule_tbl[i] == NULL)
            goto err_tbl;
        memset(fdir_rule_tbl[i], 0, sizeof(struct fdir_rule) * FDIR_MAX_SIZE);
    }

    adns_fdir_set();

    // retrive fdir infos
    // A structure used to report the status of the flow director filters in use.
    struct rte_eth_fdir fdir_info;
    memset(&fdir_info, 0, sizeof(struct rte_eth_fdir));
    for (j = 0; j < 1; j++) {
        ret = rte_eth_dev_fdir_get_infos(j, &fdir_info);
        // dump fdir info
        printf("collision: %u, free: %u, maxhash: %u, maxlen: %u, add: %" PRIu64
               ", " "remove: %" PRIu64 ", f_add: %" PRIu64 ", f_remove: %"
               PRIu64 "\n", fdir_info.collision, fdir_info.free,
               fdir_info.maxhash, fdir_info.maxlen, fdir_info.add,
               fdir_info.remove, fdir_info.f_add, fdir_info.f_remove);
    }

    return 0;

err_tbl:
    for (j = 0; j < i; j++) {
        free(fdir_rule_tbl[j]);
        fdir_rule_tbl[j] = NULL;
    }

    return -1;
}

void adns_fdir_cleanup(void)
{
    int i;

    for (i = 0; i < 1; i++) {
        free(fdir_rule_tbl[i]);
        fdir_rule_tbl[i] = NULL;
    }
}
