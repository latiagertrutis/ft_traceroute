/****************************************************************************/
/* Default method:														    */
/* The traditional, ancient method of tracerouting. Used by default.	    */
/* Probe packets are udp datagrams with  so-called  "unlikely"  destination */
/* ports.   The  "unlikely" port of the first probe is 33434, then for each */
/* next probe it is incremented by one. Since the ports are expected to  be */
/* unused,  the  destination host normally returns "icmp unreach port" as a */
/* final response.  (Nobody knows what happens when some  application       */
/* listens for such ports, though).										    */
/****************************************************************************/

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "traceroute.h"
#include "utils.h"

/* TODO: If this is common, move it to a header */
struct probe {
    int fd;
    int fd_err;
    sockaddr_any *dest;
    uint8_t *data;
    size_t data_len;
    uint16_t port;
};

/* Main probe object for this run. */
/* TODO: Check if it is going to be re-used so it needs to be malloc in init */
static struct probe p = {0};

static int init_tx_socket(int ttl)
{
    p.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (p.fd < 0) {
        perror("socket (udp)");
        return -1;
    }

    /* Set TTL */
    if (setsockopt(p.fd, SOL_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
        perror("setsockopt [IP_TTL]");
        goto error;
    }

    /* TODO: Make non blocking socket? */

    return 0;

error:
    close(p.fd);
    return -1;
}

static int init_rx_socket(void)
{
    /* int opt; */
    /* int one = 1; */
    sockaddr_any src = {0};

    p.fd_err = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (p.fd_err < 0) {
        perror("socket (raw)");
        return -1;
    }

    /* Bind to 0.0.0.0 */
    src.sa_in.sin_family = AF_INET;
    if (bind(p.fd_err, &src.sa, sizeof(sockaddr_any)) < 0) {
        perror("bind");
        goto error;
    }

    /* Default for connection-less sockets is make the user handle MTU */
    /* opt = IP_PMTUDISC_DONT; */
    /* if (setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &opt, sizeof(opt)) < 0) { */
    /*     perror("setsockopt [IP_MTU_DISCOVER]"); */
    /*     return -1; */
    /* } */


    /* TODO: Make non blocking socket? */

    return 0;

error:
    close(p.fd_err);
    return -1;
}

int def_init(void)
{
    size_t i;

    /* Allocate the data */
    p.data = (uint8_t *)malloc(p.data_len);
    if (p.data == NULL) {
        perror("malloc");
        return -errno;
    }

    /* Fill the data */
    for (i = 0; i < p.data_len; i++) {
        p.data[i] = 0x40 + (i & 0x3f);
    }

    /* Define starting port */
    p.port = DEF_START_PORT;

    init_rx_socket();
    if (p.fd_err < 0) {
        return  -errno;
    }

    return 0;
}

int def_setup_probe(int ttl)
{
    init_tx_socket(ttl);
    if (p.fd < 0) {
        return  -errno;
    }

    return 0;
}

int def_send_probe(sockaddr_any *dest)
{
    ssize_t bytes;

    printf("Send to: %d\n", dest->sa_in.sin_addr.s_addr);
    /* Set the current probe port */
    dest->sa_in.sin_port = htons(p.port);

    bytes = sendto(p.fd, p.data, p.data_len, 0, &dest->sa, sizeof(struct sockaddr));
    if (bytes < 0) {
        if (errno != EMSGSIZE && errno != EHOSTUNREACH) {
            perror("sendto");
            return bytes;
        }
    }
    p.dest = dest;
    p.port++;

    /* TODO: Add to select? */

    return bytes;
}

int def_recv_probe(void)
{
    /* (max_mtu - ip_hdr - icmp_hdr) = (1500 - 20 - 8) = 1472 bytes */
    uint8_t buf[1472];
    sockaddr_any from;
    ssize_t bytes;
    socklen_t slen = sizeof(struct sockaddr);

    bytes = recvfrom(p.fd_err, buf, sizeof(buf), 0, &from.sa, &slen);
    if (bytes <= 0) {
        perror("recvfrom");
        printf("Error: %d\n", errno);
        return -1;
    }

    print_raw_packet_metadata(buf, bytes);

    if (!check_ip_packet(buf, bytes, p.dest)) {
        printf("ICMP PACKET INCORRECT!");
    }
    else {
        printf("ICMP PACKET CORRECT!");
    }

    /* TODO: Check that received message sequence (port) is the same as the one sent */

    return bytes;
}

void def_expire_probe(void)
{
    close(p.fd);
    free(p.data);
}
