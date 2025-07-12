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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "traceroute.h"

static int init_socket(int ttl)
{
    int opt, fd;
    int one = 1;
    sockaddr_any src = {0};

    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    /* Bind to 0.0.0.0 */
    src.sa_in.sin_family = AF_INET;
    if (bind(fd, &src.sa, sizeof(sockaddr_any)) < 0) {
        perror("bind");
        return -1;
    }

    /* Default for connection-less sockets is make the user handle MTU */
    opt = IP_PMTUDISC_DONT;
    if (setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &opt, sizeof(opt)) < 0) {
        perror("setsockopt [IP_MTU_DISCOVER]");
        return -1;
    }

    /* Timestamp */
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &one, sizeof(int)) < 0) {
        perror("setsockopt [SO_TIMESTAMP]");
        return -1;
    }

    /* Receive Error */
    if (setsockopt(fd, SOL_IP, IP_RECVERR, &one, sizeof(int)) < 0) {
        perror("setsockopt [IP_RECVERR]");
        return -1;
    }

    /* Receive TTL */
    if (setsockopt(fd, SOL_IP, IP_RECVTTL, &one, sizeof(int)) < 0) {
        perror("setsockopt [IP_RECVTTL]");
        return -1;
    }

    /* Set TTL */
    if (setsockopt(fd, SOL_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
        perror("setsockopt [IP_TTL]");
        return -1;
    }

    /* TODO: Make non blocking socket? */

    return fd;
}

int def_init_probe(probe *p)
{
    size_t i;

    /* Allocate the data */
    p->data = (uint8_t *)malloc(p->data_len);
    if (p->data == NULL) {
        perror("malloc");
        return -errno;
    }

    /* Fill the data */
    for (i = 0; i < p->data_len; i++) {
        p->data[i] = 0x40 + (i & 0x3f);
    }

    /* Define starting port */
    p->port = DEF_START_PORT;

    return 0;
}

int def_setup_probe(probe * p, int ttl)
{
    p->fd = init_socket(ttl);
    if (p->fd < 0) {
        perror("init_socket");
        return  -errno;
    }

    return 0;
}

int def_send_probe(probe * p, sockaddr_any *dest)
{
    ssize_t bytes;

    /* Set the current probe port */
    dest->sa_in.sin_port = htons(p->port);

    bytes = sendto(p->fd, p->data, p->data_len, 0, &dest->sa, sizeof(struct sockaddr));
    if (bytes < 0) {
        if (errno != EMSGSIZE && errno != EHOSTUNREACH) {
            perror("sendto");
            return bytes;
        }
    }

    p->port++;

    /* TODO: Add to select? */

    return bytes;
}

void def_recv_probe(probe *p)
{
    sockaddr_any from;
    uint8_t buf[1280];
    ssize_t bytes;
    socklen_t slen = sizeof(struct sockaddr);

    bytes = recvfrom(p->fd, buf, sizeof(buf), 0, &from.sa, &slen);

    /* TODO: Check that received message sequence (port) is the same as the one sent */
}

void def_expire_probe(probe *p)
{
    close(p->fd);
    free(p->data);
}
