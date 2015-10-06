/*
 * Cameron Burwell (cburwell)
 *
 * Packet sniffing program that analyzes pcap files and dissects
 * the received packets, giving information about the various
 * protocols encountered.
 */

#include "pcap_analyzer.h"

/* 
 * Printing utility that takes in an array of bytes to print,
 * how many bytes there are, divisions (ex: ':' or '.'),
 * and the required format
 */
void fmt_print(u_char *toPrint, int iter, char *div, char *fmt)
{
    int i;
    for (i = 0; i < iter; i++) {
        if (i != 0)
            printf("%s", div);
        printf(fmt, toPrint[i]);
    }
    printf("\n");
}

/* Printing utility for known ports */
void print_port(uint16_t port)
{
    switch (port) {
        case 80:
            printf("HTTP\n");
            break;
        case 23:
            printf("Telnet\n");
            break;
        case 21:
            printf("FTP\n");
            break;
        case 110:
            printf("POP3\n");
            break;
        case 25:
            printf("SMTP\n");
            break;
        default:
            printf("%hu\n", port);
            break;
    }
}

/* Analyzes UDP segment of the packet */
void udp(uint8_t *packet)
{
    Udp_Head *head = (Udp_Head*)packet;

    printf("\n\tUDP Header\n");
    printf("\t\tSource Port:  ");
    print_port(ntohs(head->s_port));
    printf("\t\tDest Port:  ");
    print_port(ntohs(head->d_port));
}

/* Analyzes TCP segment of the packet and performs checksum on
 * the new packet that has the attached pseudoheader */
void tcp(uint8_t *packet, uint8_t *ip_head)
{
    Tcp_Head *head = (Tcp_Head*)packet;
    Ip_Head *ip = (Ip_Head*)ip_head;
    uint16_t cksum, ret;
    Pseudo_Head pseudo;

    /* Create pseudo header */
    memcpy(&(pseudo.s_ip), &(ip->s_ip), sizeof(uint8_t) * IP_ADDR_LEN);
    memcpy(&(pseudo.d_ip), &(ip->d_ip), sizeof(uint8_t) * IP_ADDR_LEN);
    memset(&(pseudo.zeros), 0, sizeof(uint8_t));
    pseudo.protocol = ip->protocol;
    pseudo.tcp_len = htons(ntohs(ip->len) - (ip->ver_ihl & IHL_MASK) * 4);

    /* Glue pseudo header to tcp header */
    uint8_t *buff = malloc(sizeof(Pseudo_Head) + ntohs(pseudo.tcp_len));
    memcpy(buff, &pseudo, sizeof(Pseudo_Head));
    memcpy(buff + sizeof(Pseudo_Head), head, ntohs(pseudo.tcp_len));

    printf("\n\tTCP Header\n");
    printf("\t\tSource Port:  ");
    print_port(ntohs(head->s_port));
    printf("\t\tDest Port:  ");
    print_port(ntohs(head->d_port));
    printf("\t\tSequence Number: %u\n", ntohl(head->seq));
    printf("\t\tACK Number: %u\n", ntohl(head->ack));
    printf("\t\tSYN Flag: %s\n", head->flags & SYN_MASK ? "Yes" : "No");
    printf("\t\tRST Flag: %s\n", head->flags & RST_MASK ? "Yes" : "No");;
    printf("\t\tFIN Flag: %s\n", head->flags & FIN_MASK ? "Yes" : "No");
    printf("\t\tWindow Size: %hu\n", ntohs(head->win_size));
    printf("\t\tChecksum: ");
    
    cksum = ntohs(head->checksum);
    ret = in_cksum((uint16_t *)buff, sizeof(Pseudo_Head) +
            ntohs(pseudo.tcp_len));
    if (ret == 0)
        printf("Correct ");
    else
        printf("Incorrect ");
    printf("(0x%x)\n", cksum);
}

/* Analyzes ICMP packet */
void icmp(uint8_t *packet)
{
    Icmp_Head *head = (Icmp_Head*)packet;
    uint8_t type;

    printf("\n\tICMP Header\n");
    printf("\t\tType: ");
    type = head->type;
    if (type == 0)
        printf("Reply");
    else if (type == 8)
        printf("Request");
    else
        printf("Unknown");
}

/* Analyze IP packet and send to appropriate protocol handler */
void ip(uint8_t *packet)
{
    Ip_Head *head = (Ip_Head*)packet;
    uint16_t ret, cksum;
    int type, addtl = 0;

    printf("\tIP Header\n");
    printf("\t\tTOS: 0x%x\n", head->tos);
    printf("\t\tTTL: %u\n", head->ttl);
    
    printf("\t\tProtocol: ");
    type = head->protocol;
    if (type == TYPE_ICMP)
        printf("ICMP\n");
    else if (type == TYPE_TCP)
        printf("TCP\n");
    else if (type == TYPE_UDP)
        printf("UDP\n");
    else
        printf("Unknown\n");

    printf("\t\tChecksum: ");
    cksum = ntohs(head->checksum);
    ret = in_cksum((uint16_t*)head, sizeof(Ip_Head));
    if (ret == 0)
        printf("Correct ");
    else
        printf("Incorrect ");
    printf("(0x%x)\n", cksum);
    
    printf("\t\tSender IP: ");
    fmt_print(head->s_ip, IP_ADDR_LEN, ".", "%d");
    
    printf("\t\tDest IP: ");
    fmt_print(head->d_ip, IP_ADDR_LEN, ".", "%d");
  
    /* If ihl > 5, must take option length into account */
    if ((head->ver_ihl & IHL_MASK) > 5)
        addtl = (head->ver_ihl & IHL_MASK);

    if (type == TYPE_ICMP)
        icmp(packet + IP_SIZE + addtl);
    else if (type == TYPE_TCP)
        tcp(packet + IP_SIZE + addtl, packet);
    else if (type == TYPE_UDP)
        udp(packet + IP_SIZE + addtl);
}

/* Analyzes ARP packet */
void arp(uint8_t *packet)
{
    Arp_Head *head = (Arp_Head*)(packet + ARP_OFFSET);

    printf("\tARP header\n");
    printf("\t\tOpcode: ");
    printf(ntohs(head->op) == 1 ? "Request\n" : "Reply\n");
    
    printf("\t\tSender MAC: ");
    fmt_print(head->s_mac, ETHER_ADDR_LEN, ":", "%x");
    
    printf("\t\tSender IP: ");
    fmt_print(head->s_ip, IP_ADDR_LEN, ".", "%d");
    
    printf("\t\tTarget MAC: ");
    if (ntohs(head->op) == 1)
        printf("0:0:0:0:0:0\n");
    else
        fmt_print(head->t_mac, ETHER_ADDR_LEN, ":", "%x");
    
    printf("\t\tTarget IP: ");
    fmt_print(head->t_ip, IP_ADDR_LEN, ".", "%d");
}

/* Takes in the packet off ethernet and strips it, sending it
 * to the appropraite protocol handlers */
void ethernet(int count, struct pcap_pkthdr *header, uint8_t *packet)
{
    Ether_Head *head = (Ether_Head*)packet;
    u_short type;

    printf("\nPacket number: %d  Packet Len: %d\n\n", count, header->len);
    printf("\tEthernet Header\n");
    
    printf("\t\tDest MAC: ");
    fmt_print(head->src, ETHER_ADDR_LEN, ":", "%x");
    
    printf("\t\tSource MAC: ");
    fmt_print(head->dest, ETHER_ADDR_LEN, ":", "%x");
    
    printf("\t\tType: ");
    type = ntohs(head->type);
    if (type == TYPE_ARP) {
        printf("ARP\n\n");
        /* Pass data starting after internet header */
        arp(packet + ETHER_SIZE);
    }
    else if (type == TYPE_IP) {
        printf("IP\n\n");
        ip(packet + ETHER_SIZE);
    }
    else {
        printf("Unknown\n");
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *header;
    uint8_t *packet;
    int count = 0, stat;

    if (argc != 2) {
        perror("Error: Invalid argument count. Usage: trace <pcap>\n");
        exit(EXIT_FAILURE);
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open pcap file:\n\t%s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* -2 means nothing more to be read */
    while ((stat = pcap_next_ex(handle, &header,
                    (const u_char**)&packet)) != -2) {
        /* -1 indicates error */
        if (stat == -1) {
            pcap_perror(handle, "Error reading packets");
            exit(EXIT_FAILURE);
        }
        
        ethernet(++count, header, packet);
    }

    pcap_close(handle);
    return 0;
}
