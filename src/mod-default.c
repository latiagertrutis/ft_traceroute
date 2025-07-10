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
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

#include "traceroute.h"

static int init_socket(int fd, host *host)
{
    int opt;

    if (bind(fd, &host->addr.sa, sizeof(host->addr)) < 0) {
        perror("bind");
        return -1;
    }

    /* Default for connection-less sockets is make the user handle MTU */
    opt = IP_PMTUDISC_DONT;
    if (setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        return -1;
    }

    return fd;
}

int def_setup_probe(probe * p, host *host, int ttl)
{
    p->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (p->fd < 0) {
        perror("socket");
        return -errno;
    }

    if (init_socket(p->fd, host) < 0) {
        perror("init_socket");
        return  -errno;
    }

    return 0;
}

int def_teardown_probe()
{
    return 0;
}

int def_send_probe(probe * p)
{

    return 0;
}

void def_recv_probe(void)
{

}

void def_expire_probe(void)
{

}
