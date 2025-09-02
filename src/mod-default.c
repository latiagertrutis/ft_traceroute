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
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>


#include "mod-internal.h"
#include "probe.h"
#include "utils.h"
#include "ip_utils.h"

/* TODO: If this is common, move it to a header */

struct def_data {
    int fd_tx;
    int fd_rx;
    sockaddr_any *dest;
    uint8_t *data;
    size_t data_len;
    int last_ttl;
    uint16_t port; // Next port to use
};

/* Main probe object for this run. */
/* TODO: Check if it is going to be re-used so it needs to be malloc in init */
static struct def_data data = {0};

static int init_tx_socket(void)
{
    data.fd_tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (data.fd_tx < 0) {
        perror("socket (udp)");
        return -1;
    }

    /* TODO: Make non blocking socket? */

    return 0;
}

static int init_rx_socket(void)
{
    /* int opt; */
    /* int one = 1; */
    sockaddr_any src = {0};

    data.fd_rx = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (data.fd_rx < 0) {
        perror("socket (raw)");
        return -1;
    }

    /* Bind to 0.0.0.0 */
    src.sa_in.sin_family = AF_INET;
    if (bind(data.fd_rx, &src.sa, sizeof(sockaddr_any)) < 0) {
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
    close(data.fd_rx);
    return -1;
}

/* TODO: To avoid early optimization, n_probes is used, the idea is to use only
 * the ammount of probes that will be in air simultaneously. Each probe will be
 * identified by its index in the array, and the index will be
 * current_port - default port.Optimize once is ready */
int def_init(sockaddr_any *dest, size_t data_len)
{
    size_t i;
    int ret = 0;

    data.dest = dest;
    data.data_len = data_len;
    /* Allocate the data */
    /* TODO: Free this memory at the end of the program */
    if (data_len > 0) {
        data.data = (uint8_t *)malloc(data_len);
        if (data.data == NULL) {
            perror("malloc");
            return -1;
        }

        /* Fill the data */
        for (i = 0; i < data_len; i++) {
            data.data[i] = 0x40 + (i & 0x3f);
        }
    }

    /* Define starting port */
    data.port = DEF_START_PORT;

    /* Init the transsmission socket. Dgram socket for sending udp packages */
    init_tx_socket();
    if (data.fd_tx < 0) {
        ret = -1;
        goto error_data;
    }

    /* Raw socket for reception of icmp error messages */
    init_rx_socket();
    if (data.fd_rx < 0) {
        ret = -1;
        goto error_fd_tx;
    }

    return ret;

error_fd_tx:
    close(data.fd_tx);
error_data:
    free(data.data);
    return ret;
}

void def_clean()
{
    free(data.data);
    close(data.fd_tx);
    close(data.fd_rx);
}

int def_send_probe(struct probes * ps, int ttl)
{
    ssize_t bytes;
    struct probe *p;
    /* unsigned int idx = p.port - DEF_START_PORT; */

    if (ttl != data.last_ttl) {
        if (set_ttl(data.fd_tx, ttl) != 0) {
            return  -1;
        }
        data.last_ttl = ttl;
    }


    /* printf("Send to: %d\n", p.dest->sa_in.sin_addr.s_addr); */
    /* Set the current probe port */
    data.dest->sa_in.sin_port = htons(data.port);

    bytes = sendto(data.fd_tx, data.data, data.data_len, 0, &data.dest->sa, sizeof(struct sockaddr));
    if (bytes < 0) {
        if (errno != EMSGSIZE && errno != EHOSTUNREACH) {
            perror("sendto");
            return bytes;
        }
    }

    p = get_probe(ps, data.port - DEF_START_PORT);
    if (p == NULL) {
        return -1;
    }
    gettimeofday(&p->sent_time, NULL);

    data.port++;

    return bytes;
}

/* Receive probe, only valid probes that are within the range, return message
 * status and idx of the probe received */
static int rcv_and_check_udp(int fd, struct probes *ps, struct probe_range range)
{
    /* max_mtu  = 1500 bytes */
    uint8_t buf[1500];
    uint8_t *icmp_pkg;
    sockaddr_any from;
    ssize_t bytes;
    unsigned int port, idx;
    socklen_t slen = sizeof(struct sockaddr);
    struct icmphdr *icmp_hdr;
    struct iphdr *ip_hdr, *orig_ip_hdr;
    struct udphdr *orig_udp_hdr;
    struct probe *p;

    bytes = recvfrom(fd, buf, sizeof(buf), 0, &from.sa, &slen);
    if (bytes <= 0) {
        perror("recvfrom");
        printf("Error: %d\n", errno);
        return -1;
    }

    /* print_raw_packet_metadata(buf, bytes); */

    ip_hdr = (struct iphdr *) buf;

    /* We received a raw message, ip header will preceed the icmp package. Check
     * that space fits what we are expecting and get the start of the icmp package */
    icmp_pkg = get_icmp_packet(buf, bytes);
    if (icmp_pkg == NULL) {
        printf("drop in get_icmp_packet()\n");
        return 0;
    }

    icmp_hdr = (struct icmphdr *)icmp_pkg;
    orig_ip_hdr = (struct iphdr *)(icmp_pkg + sizeof(struct icmphdr));
    orig_udp_hdr = (struct udphdr *)(icmp_pkg + sizeof(struct icmphdr) + (orig_ip_hdr->ihl << 2));

    /* Check the original adress received matches the destination address */
    if (orig_ip_hdr->daddr != data.dest->sa_in.sin_addr.s_addr) {
        printf("drop in address\n");
        return 0;
    }

    /* Check that the port is within the range */
    port = ntohs(orig_udp_hdr->dest);
    idx = port - DEF_START_PORT;
    if (port < range.min + DEF_START_PORT ||
        port >= range.max + DEF_START_PORT) {
        printf("drop in port\n");
        return 0;
    }

    p = get_probe(ps, idx);
    if (p == NULL) {
        return -1;
    }
    if (p->sent_time.tv_sec == 0) {
        /* Message was not sent */
        return 0;
    }

    /* Mark reception of message */
    gettimeofday(&p->recv_time, NULL);

    /* Store sender address */
    p->sa.sa.sa_family = AF_INET;
    p->sa.sa_in.sin_addr.s_addr = ip_hdr->saddr;

    switch (check_icmp_type(icmp_hdr->type, icmp_hdr->code)) {
    case TRC_MSG_DROP:
        /* TODO: print something? */
        /* printf("Message Drop\n"); */
        return 0;
    case TRC_MSG_ERROR:
        /* TODO: print something? */
        /* printf("Message Error\n"); */
        /* TRC_MSG_ERROR means that probe is for us but icmp code is not what
         * we expect, so, probe is done but hop is not */
        return 1; // increase one pos
    case TRC_MSG_TTL:
        /* TODO: print something? */
        /* printf("Message TTL\n"); */
        return 1; // increase one pos
    case TRC_MSG_FINAL:
        /* TODO: print something? */
        ps->done = true;
        /* printf("Message Final\n"); */
        return 1;
    }

    return 0;
}

int def_recv_probe(struct probes *ps, int timeout, struct probe_range range)
{
    return select_probes(data.fd_rx, ps, timeout, range, rcv_and_check_udp);
}
