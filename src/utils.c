#include <bits/types/struct_timeval.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>

#define MILIS_PER_SECOND 1000.0
#define USEC_PER_MILIS 1000.0

void print_message_with_metadata(const uint8_t *buffer, ssize_t length,
                                 const struct sockaddr_in *sender_addr)
{
    char sender_ip[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &(sender_addr->sin_addr), sender_ip, sizeof(sender_ip)) == NULL) {
        perror("inet_ntop failed");
        return;
    }

    int sender_port = ntohs(sender_addr->sin_port);

    printf("Received %zd bytes\n", length);
    printf("Message: \"%.*s\"\n", (int)length,
           buffer);  // Safe print without assuming null-terminated
    printf("Sender IP: %s\n", sender_ip);
    printf("Sender Port: %d\n", sender_port);
}

void print_raw_packet_metadata(const unsigned char *buffer, ssize_t length)
{
    if ((size_t)length < sizeof(struct iphdr)) {
        fprintf(stderr, "Packet too short to contain an IP header\n");
        return;
    }

    const struct iphdr *ip_header = (const struct iphdr *)buffer;

    struct in_addr src_addr = { .s_addr = ip_header->saddr };
    struct in_addr dst_addr = { .s_addr = ip_header->daddr };

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip));

    printf("=== IP Header ===\n");
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);
    printf("Protocol: %d\n", ip_header->protocol);
    printf("TTL: %d\n", ip_header->ttl);
    printf("Header Length: %d bytes\n", ip_header->ihl * 4);
    printf("Total Length: %d bytes\n", ntohs(ip_header->tot_len));

    // Check protocol is ICMP
    if (ip_header->protocol != IPPROTO_ICMP) {
        printf("Not an ICMP packet.\n");
        return;
    }

    int ip_header_len = ip_header->ihl * 4;
    if ((size_t)length < ip_header_len + sizeof(struct icmphdr)) {
        fprintf(stderr, "Packet too short to contain full ICMP header\n");
        return;
    }

    const struct icmphdr *icmp_header = (const struct icmphdr *)(buffer + ip_header_len);
    printf("\n=== ICMP Header ===\n");
    printf("Type: %d\n", icmp_header->type);
    printf("Code: %d\n", icmp_header->code);
    printf("Checksum: 0x%04x\n", ntohs(icmp_header->checksum));

    // ICMP Error types (3, 4, 5, 11, 12)
    if (icmp_header->type == 3 || icmp_header->type == 4 || icmp_header->type == 5 ||
        icmp_header->type == 11 || icmp_header->type == 12) {
        printf("\n=== ICMP Error Payload (Original Packet Header + 8 Bytes) ===\n");

        const unsigned char *inner_packet = buffer + ip_header_len + sizeof(struct icmphdr);
        size_t inner_len = length - ip_header_len - sizeof(struct icmphdr);

        if (inner_len < sizeof(struct iphdr)) {
            printf("Not enough data for inner IP header\n");
            return;
        }

        const struct iphdr *inner_ip = (const struct iphdr *)inner_packet;
        struct in_addr inner_src = { .s_addr = inner_ip->saddr };
        struct in_addr inner_dst = { .s_addr = inner_ip->daddr };

        char inner_src_ip[INET_ADDRSTRLEN];
        char inner_dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &inner_src, inner_src_ip, sizeof(inner_src_ip));
        inet_ntop(AF_INET, &inner_dst, inner_dst_ip, sizeof(inner_dst_ip));

        printf("Original Source IP: %s\n", inner_src_ip);
        printf("Original Destination IP: %s\n", inner_dst_ip);
        printf("Destination IP (RAW): %d\n", inner_dst.s_addr);
        printf("Original Protocol: %d\n", inner_ip->protocol);

        // Dump first 8 bytes of original payload
        const unsigned char *inner_payload = inner_packet + inner_ip->ihl * 4;
        size_t payload_len = inner_len - inner_ip->ihl * 4;
        size_t to_print = payload_len > 8 ? 8 : payload_len;

        printf("First %zu bytes of original payload: ", to_print);
        for (size_t i = 0; i < to_print; i++) {
            printf("%02x ", inner_payload[i]);
        }
        printf("\n");
    }
    else {
        printf("\nThis is not an ICMP error message with embedded packet.\n");
    }
}

double timeval_to_ms(struct timeval t)
{
    return (double)t.tv_sec * MILIS_PER_SECOND + (double)t.tv_usec / USEC_PER_MILIS;
}

double diff_timeval(struct timeval start, struct timeval finish)
{
    return timeval_to_ms(finish) - timeval_to_ms(start);
}
