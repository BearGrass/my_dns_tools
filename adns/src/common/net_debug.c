
#include <stdio.h>

#include "rte_core.h"
#include <rte_ip.h>

#include "net_debug.h"


static inline void print_ether_addr(const char *what, const struct ether_addr *eth_addr)
{   
    printf("%s%02X:%02X:%02X:%02X:%02X:%02X",
            what,
            eth_addr->addr_bytes[0],
            eth_addr->addr_bytes[1],
            eth_addr->addr_bytes[2],
            eth_addr->addr_bytes[3],
            eth_addr->addr_bytes[4],
            eth_addr->addr_bytes[5]);
}              

static void net_ether_dump(const struct ether_hdr *eth_hdr)
{
    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    printf("Ether type: 0X%04X ", ether_type);

    switch (ether_type) {
        case ETHER_TYPE_IPv4:
            printf(" IPv4,");
            break;
        case ETHER_TYPE_IPv6:
            printf(" IPv6,");
            break;
        case ETHER_TYPE_ARP:
            printf(" ARP,");
            break;
        case ETHER_TYPE_RARP:
            printf(" RARP,");
            break;
        case ETHER_TYPE_VLAN:
            printf(" VLAN,");
            break;
        default:
            printf(" Unknown ether type,");
            break;
    }

    print_ether_addr("  src=", &eth_hdr->s_addr);
    print_ether_addr(" - dst=", &eth_hdr->d_addr);

    printf("\n");
}

static void net_arpv4_dump(const struct arpv4_hdr *arp)
{
    const char *arp_op[5] = { 
        "Unknow ARP opcode", 
        "Arp Request",
        "Arp Reply",
        "Rarp Request",
        "Rarp Reply"
    };

    printf("Arp: hard_type: %04xh, protocol: %04xh, hard_size: %d, prot_size: %d, %s\n"
            "     sender mac: %02x:%02x:%02x:%02x:%02x:%02x, ip: %d.%d.%d.%d\n"
            "     target mac: %02x:%02x:%02x:%02x:%02x:%02x, ip: %d.%d.%d.%d\n",
            rte_be_to_cpu_16(arp->hard_type), rte_be_to_cpu_16(arp->protocol), 
            arp->hard_addr_size, arp->prot_addr_size,
            arp_op[rte_be_to_cpu_16(arp->opcode)], 
            arp->sender_mac[0], arp->sender_mac[1], arp->sender_mac[2],
            arp->sender_mac[3], arp->sender_mac[4], arp->sender_mac[5], 
            NIPQUAD(arp->sender_ip),
            arp->target_mac[0], arp->target_mac[1], arp->target_mac[2],
            arp->target_mac[3], arp->target_mac[4], arp->target_mac[5],
            NIPQUAD(arp->target_ip));
}



static void net_ipv4_dump(const struct ipv4_hdr *ipv4_hdr)
{
    uint8_t *opt_ptr;
    uint16_t opt_len;

    printf("IPv4: %d.%d.%d.%d -> %d.%d.%d.%d\n"
            " proto: %u, ver: %02u, ihl: %02d tos: %02d, len: %d, ident: %d,"
            " R: %d, DF: %d, MF: %d, offset: %d, ttl: %d, chksum: 0x%04x\n",
            NIPQUAD(ipv4_hdr->src_addr), NIPQUAD(ipv4_hdr->dst_addr),
            ipv4_hdr->next_proto_id, (ipv4_hdr->version_ihl) >> 4,
            ((ipv4_hdr->version_ihl) & 0xf) << 2, ipv4_hdr->type_of_service,
            rte_be_to_cpu_16(ipv4_hdr->total_length),
            rte_be_to_cpu_16(ipv4_hdr->packet_id),
            (rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & 0x8000) >> 15,
            (rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & 0x4000) >> 14,
            (rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & 0x2000) >> 13,
            rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & 0x1fff,
            ipv4_hdr->time_to_live,
            rte_be_to_cpu_16(ipv4_hdr->hdr_checksum));

    if (rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & 0x1fff )
        printf("  ip fragment offset: %d\n", 
                rte_be_to_cpu_16(ipv4_hdr->fragment_offset) & 0x1fff);

    if ((ipv4_hdr->version_ihl&0xf) > 5) {
        printf("Have options\n");
        /*
         *ipv4_option_dump((uint8_t *)ipv4_hdr + sizeof(struct ipv4_hdr),
         *        (ipv4_hdr->version_ihl & 0xf)*4 - sizeof(struct ipv4_hdr));
         */
    }
    printf("\n");
}


void net_pkt_dump(const void *data)
{
    uint16_t ether_type;
    uint8_t hdr_len;
    struct ether_hdr *eth_hdr;
    struct arpv4_hdr *arpv4_hdr;
    struct ipv4_hdr  *ipv4_hdr;
    struct udp_hdr   *udp_hdr;
    struct tcp_hdr   *tcp_hdr;

    static const char r_type[] = "LDNHO\n";

    eth_hdr = (const struct ether_hdr *)data;
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    net_ether_dump(eth_hdr);

    if (ether_type == ETHER_TYPE_VLAN)
        return;

    hdr_len = sizeof(struct ether_hdr);
    switch (ether_type) {
        case ETHER_TYPE_IPv4:
            ipv4_hdr = (const struct ipv4_hdr *)(data + hdr_len);
            net_ipv4_dump(ipv4_hdr);
            break;
        case ETHER_TYPE_IPv6:
            /*printf(" IPv6,");*/
            break;
        case ETHER_TYPE_ARP:
            arpv4_hdr = (const struct arpv4_hdr *)(data + hdr_len);
            net_arpv4_dump(arpv4_hdr);
            break;
        case ETHER_TYPE_RARP:
            /*printf(" RARP,");*/
            break;
        case ETHER_TYPE_VLAN:
            /*printf(" VLAN,");*/
            break;
        default:
            printf(" Unknown ether type,");
            break;
    }

}


