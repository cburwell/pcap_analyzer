#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "checksum.h"
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>

#define TYPE_ARP 0x0806
#define TYPE_IP 0x0800
#define TYPE_TCP 0x06
#define TYPE_ICMP 0x01
#define TYPE_UDP 0x11

#define ETHER_SIZE 14
#define ETHER_ADDR_LEN 6

#define IP_SIZE 20
#define IP_ADDR_LEN 4

#define ARP_SIZE 28
#define ARP_OFFSET 6

#define FIN_MASK 0x1
#define SYN_MASK 0x2
#define RST_MASK 0x4
#define IHL_MASK 0xf

typedef struct {
    uint8_t src[ETHER_ADDR_LEN];     /* Source IP Address */ 
    uint8_t dest[ETHER_ADDR_LEN];    /* Destination IP Address */
    uint16_t type;                   /* Type */
} Ether_Head;

typedef struct {
    uint16_t op;                    /* Operation flag (request, reply) */
    uint8_t s_mac[ETHER_ADDR_LEN];   /* Sender Hardware Address (MAC) */
    uint8_t s_ip[IP_ADDR_LEN];       /* Sender IP Address */
    uint8_t t_mac[ETHER_ADDR_LEN];   /* Target Hardware Address (MAC) */
    uint8_t t_ip[IP_ADDR_LEN];       /* Target IP Address */
} Arp_Head;

typedef struct {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags_frag; 
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t s_ip[IP_ADDR_LEN];
    uint8_t d_ip[IP_ADDR_LEN];
} Ip_Head;

typedef struct {
    uint16_t s_port;    /* Source port */
    uint16_t d_port;    /* Dest port */
} Udp_Head;

typedef struct {
    uint8_t type;
} Icmp_Head;

typedef struct {
    uint16_t s_port;                    /* Source port */
    uint16_t d_port;                    /* Dest port */
    uint32_t seq;                       /* Sequence number */
    uint32_t ack;                       /* Acknowledgement number */
    uint8_t offset;			/* Data offset, etc. */
    uint8_t flags;
    uint16_t win_size;                  /* Window size */
    uint16_t checksum;
} Tcp_Head;

typedef struct {
    uint8_t s_ip[IP_ADDR_LEN];          /* Source ip address */
    uint8_t d_ip[IP_ADDR_LEN];          /* Destination ip address */
    uint8_t zeros;                      
    uint8_t protocol;               
    uint16_t tcp_len;                   /* Length of the tcp header */
} Pseudo_Head;
