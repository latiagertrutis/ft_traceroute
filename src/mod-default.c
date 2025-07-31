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

#include "traceroute.h"
#include "probe.h"
#include "utils.h"
#include "ip_utils.h"

/* TODO: If this is common, move it to a header */

struct def_data {
    int fd;
    int fd_err;
    sockaddr_any *dest;
    uint8_t *data;
    size_t data_len;
    uint16_t port; // Next port to use
};

/* Main probe object for this run. */
/* TODO: Check if it is going to be re-used so it needs to be malloc in init */
static struct def_data data = {0};

static int init_tx_socket(void)
{
    data.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (data.fd < 0) {
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

    data.fd_err = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (data.fd_err < 0) {
        perror("socket (raw)");
        return -1;
    }

    /* Bind to 0.0.0.0 */
    src.sa_in.sin_family = AF_INET;
    if (bind(data.fd_err, &src.sa, sizeof(sockaddr_any)) < 0) {
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
    close(data.fd_err);
    return -1;
}

static int set_ttl(int ttl)
{
    /* Set TTL */
    if (setsockopt(data.fd, SOL_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
        perror("setsockopt [IP_TTL]");
        return -1;
    }

    return 0;
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
        printf("Try allocate %ld\n", data_len);
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
    if (data.fd < 0) {
        ret = -1;
        goto error_data;
    }

    /* Raw socket for reception of icmp error messages */
    init_rx_socket();
    if (data.fd_err < 0) {
        ret = -1;
        goto error_data;
    }

    return ret;

error_data:
    free(data.data);
    return ret;
}


int def_send_probe(struct probes * ps, int ttl)
{
    ssize_t bytes;
    struct probe *p;
    /* unsigned int idx = p.port - DEF_START_PORT; */

    if (set_ttl(ttl) != 0) {
        return  -1;
    }

    /* printf("Send to: %d\n", p.dest->sa_in.sin_addr.s_addr); */
    /* Set the current probe port */
    data.dest->sa_in.sin_port = htons(data.port);

    bytes = sendto(data.fd, data.data, data.data_len, 0, &data.dest->sa, sizeof(struct sockaddr));
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
static int recv_probe(struct probes *ps, struct probe_range range)
{
    /* max_mtu  = 1500 bytes */
    uint8_t buf[1500];
    uint8_t *icmp_pkg;
    sockaddr_any from;
    ssize_t bytes;
    unsigned int port, idx;
    socklen_t slen = sizeof(struct sockaddr);
    struct icmphdr *icmp_hdr;
    struct iphdr *orig_ip_hdr;
    struct udphdr *orig_udp_hdr;
    struct probe *p;

    bytes = recvfrom(data.fd_err, buf, sizeof(buf), 0, &from.sa, &slen);
    if (bytes <= 0) {
        perror("recvfrom");
        printf("Error: %d\n", errno);
        return -1;
    }

    /* print_raw_packet_metadata(buf, bytes); */

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

    switch (check_icmp_type(icmp_hdr->type, icmp_hdr->code)) {
    case TRC_MSG_DROP:
        /* TODO: print something? */
        printf("Message Drop\n");
        return 0;
    case TRC_MSG_ERROR:
        /* TODO: print something? */
        printf("Message Error\n");
        /* TRC_MSG_ERROR means that probe is for us but icmp code is not what
         * we expect, so, probe is done but hop is not */
        return 1; // increase one pos
    case TRC_MSG_TTL:
        /* TODO: print something? */
        printf("Message TTL\n");
        return 1; // increase one pos
    case TRC_MSG_FINAL:
        /* TODO: print something? */
        ps->done = true;
        printf("Message Final\n");
        return 1;
    }

    return 0;
}

/* TODO: We do not want to see if every probe has a response, is one of the porbes of a given hop (3 probes) is answered this is enough, so we should be waiting  hops not porbes. The only linear variable is the port, some probes may not be responded, but if one in the hop is, the hop is done. */

/* If final probe is read matk probes as done, oterwise, return last pos. Pos can be greater than range.max since the last probe in the range can validate its hop which can contain more probes. If that is the case the next iteration should start from the next hop. */
int def_recv_probe(struct probes *ps, int timeout, struct probe_range range)
{
    int nfds, ready, ret;
    fd_set readfds;
    struct timeval tim;
    unsigned int pos;

    nfds = data.fd_err + 1;
    pos = range.min;
    while (pos < range.max) {
        /* This values are modified in select() so must be re-initialized in each call */
        FD_ZERO(&readfds);
        FD_SET(data.fd_err, &readfds);

        tim.tv_sec = timeout;
        tim.tv_usec = 0;

        ready = select(nfds, &readfds, NULL, NULL, &tim);
        if (ready < 0) {
            return -1;
        }

        if (ready == 0) {
            /* timeout */
            printf("Message Timeout Reception\n");
            /* If timeout occured,  probes in this range will not have a recv_time, meaning they are expired. Return the max position reached. If this position is less than the max we know there are some timeouts */
            return pos;
        }

        /* only one fd set */
        ret = recv_probe(ps, range);
        if (ret < 0) {
            return -1;
        }

        pos += ret;

        if (ps->done) {
            return pos;
        }
    }

    return pos;
}

void def_expire_probe()
{
}
