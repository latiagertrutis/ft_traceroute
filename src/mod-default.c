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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include "traceroute.h"
#include "utils.h"
#include "ip_utils.h"

/* TODO: If this is common, move it to a header */

struct probes {
    int *fd;
    unsigned int n_probes;
    int fd_err;
    sockaddr_any *dest;
    uint8_t *data;
    size_t data_len;
    uint16_t port; // Next port to use
};

/* Main probe object for this run. */
/* TODO: Check if it is going to be re-used so it needs to be malloc in init */
static struct probes p = {0};

static int init_tx_socket(unsigned int idx, int ttl)
{
    int *fd;

    if (idx >= p.n_probes) {
        return -1;
    }

    fd = &p.fd[idx];
    *fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (*fd < 0) {
        perror("socket (udp)");
        return -1;
    }

    /* Set TTL */
    if (setsockopt(*fd, SOL_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
        perror("setsockopt [IP_TTL]");
        goto error;
    }

    /* TODO: Make non blocking socket? */

    return 0;

error:
    close(*fd);
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

    /* TODO: add this as bonus flag F */
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

/* TODO: To avoid early optimization, n_probes is used, the idea is to use only
 * the ammount of probes that will be in air simultaneously. Each probe will be
 * identified by its index in the array, and the index will be
 * current_port - default port.Optimize once is ready */
int def_init(size_t data_len, unsigned int n_probes)
{
    size_t i;
    int ret = 0;

    p.data_len = data_len;
    p.n_probes = n_probes;
    /* Allocate the data */
    /* TODO: Free this memory at the end of the program */
    if (data_len > 0) {
        printf("Try allocate %ld\n", data_len);
        p.data = (uint8_t *)malloc(data_len);
        if (p.data == NULL) {
            perror("malloc");
            return -1;
        }

        /* Fill the data */
        for (i = 0; i < data_len; i++) {
            p.data[i] = 0x40 + (i & 0x3f);
        }
    }

    /* Define starting port */
    p.port = DEF_START_PORT;

    /* Allocate file descriptors for the simultaneous messages in air */
    /* TODO: Free this memory at the end of the program */
    printf("Try allocate %ld\n", sizeof(int) * n_probes);
    p.fd = (int *)malloc(sizeof(int) * n_probes);
    if (p.data == NULL) {
        perror("malloc");
        ret = -1;
        goto error_data;
    }

    for (i = 0; i < n_probes; i++) {
        p.fd[i] = -1;
    }

    /* Raw socket for reception of icmp error messages */
    init_rx_socket();
    if (p.fd_err < 0) {
        ret = -1;
        goto error_fd;
    }

    return ret;

error_fd:
    free(p.fd);
error_data:
    free(p.data);
    return ret;
}


int def_send_probe(sockaddr_any *dest, int ttl)
{
    ssize_t bytes;
    unsigned int idx = p.port - DEF_START_PORT;

    /* Init the probe socket firs. Dgram socket for sending udp packages */
    init_tx_socket(idx, ttl);
    if (p.fd[idx] < 0) {
        return  -errno;
    }

    printf("Send to: %d\n", dest->sa_in.sin_addr.s_addr);
    /* Set the current probe port */
    dest->sa_in.sin_port = htons(p.port);

    bytes = sendto(p.fd[idx], p.data, p.data_len, 0, &dest->sa, sizeof(struct sockaddr));
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

msg_status def_recv_probe(void)
{
    /* max_mtu  = 1500 bytes */
    uint8_t buf[1500];
    uint8_t *icmp_pkg;
    sockaddr_any from;
    ssize_t bytes;
    unsigned int port;
    socklen_t slen = sizeof(struct sockaddr);
    struct icmphdr *icmp_hdr;
    struct iphdr *orig_ip_hdr;
    struct udphdr *orig_udp_hdr;

    bytes = recvfrom(p.fd_err, buf, sizeof(buf), 0, &from.sa, &slen);
    if (bytes <= 0) {
        perror("recvfrom");
        printf("Error: %d\n", errno);
        return -1;
    }

    print_raw_packet_metadata(buf, bytes);

    /* We received a raw message, ip header will preceed the icmp package. Check
     * that space fits what we are expecting and get the start of the icmp package */
    icmp_pkg = get_icmp_packet(buf, bytes);
    if (icmp_pkg == NULL) {
        printf("drop in get_icmp_packet()\n");
        return TRC_MSG_DROP;
    }

    icmp_hdr = (struct icmphdr *)icmp_pkg;
    orig_ip_hdr = (struct iphdr *)(icmp_pkg + sizeof(struct icmphdr));
    orig_udp_hdr = (struct udphdr *)(icmp_pkg + sizeof(struct icmphdr) + (orig_ip_hdr->ihl << 2));

    /* Check the original adress received matches the destination address */
    if (orig_ip_hdr->daddr != p.dest->sa_in.sin_addr.s_addr) {
        printf("drop in address\n");
        return TRC_MSG_DROP;
    }

    /* Check that the port matches (i.e. the index of fds have a valid fd) */
    port = ntohs(orig_udp_hdr->dest);
    printf("Fd in position %d is: %d\n", port, p.fd[port - DEF_START_PORT]);
    if (port < DEF_START_PORT ||
        port >= DEF_START_PORT + p.n_probes ||
        p.fd[port - DEF_START_PORT] < 0) {
        printf("drop in port\n");
        return TRC_MSG_DROP;
    }

    return  check_icmp_type(icmp_hdr->type, icmp_hdr->code);
}

void def_expire_probe(unsigned int idx)
{
    close(p.fd[idx]);
}
