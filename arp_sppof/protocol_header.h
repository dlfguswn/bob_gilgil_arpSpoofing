#ifndef PROTOCOL_HEADER_H
#define PROTOCOL_HEADER_H
#endif // PROTOCOL_HEADER_H
#include <pcap.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>

#define ETHER_ADDR_LEN 6

#define LIBNET_BIG_ENDIAN 1

#pragma pack(1)
struct libnet_arp_hdr
{
    u_int16_t arp_hrd_type;         /* format of hardware address */
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
    u_int16_t arp_proto;         /* format of protocol address */
    u_int8_t  arp_hrd_size;         /* length of hardware address */
    u_int8_t  arp_proto_size;         /* length of protocol addres */
    u_int16_t arp_op;          /* operation type */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
    /* address information allocated dynamically */
    u_int8_t s_hw_addr[6];
    u_int32_t s_ip_addr;
    u_int8_t t_hw_addr[6];
    u_int32_t t_ip_addr;
};

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

struct ARP_Packet{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_arp_hdr arp_hdr;
};

#pragma pack(1)
