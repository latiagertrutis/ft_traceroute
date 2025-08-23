#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ip_utils.h"
#include "probe.h"

struct def_data {
    int fd;
    sockaddr_any *dest;
    uint8_t *data;
    uint16_t id;
    int last_ttl;
    size_t data_len;
};

static struct def_data data = {0};

static int init_socket()
{
    struct protoent *proto;

    proto = getprotobyname("icmp");
    if (proto == NULL) {
        /* errno is not set by getprotobyname() */
        errno = ENOPROTOOPT;
        return -1;
    }

    data.fd = socket(AF_INET, SOCK_DGRAM, proto->p_proto);
    if (data.fd < 0) {
        perror("socket (icmp)");
        return -1;
    }

    /* TODO: Activate recverror? */

    if (connect(data.fd, &data.dest->sa, sizeof(struct sockaddr)) < 0) {
        perror("connect");
        close(data.fd);
        return -1;
    }

    return 0;
}

static uint16_t get_socket_id(int fd)
{
    sockaddr_any addr;
    socklen_t len = sizeof(struct sockaddr);

    if (getsockname(fd, &addr.sa, &len) >= 0) {
        return ntohs(addr.sa_in.sin_port);
    }

    return getpid() &  0xffff;
}

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

    /* Init socket for transmitting and receving */
    init_socket();
    if (data.fd < 0) {
        ret = -1;
        goto error_data;
    }

    /* Intitalize the identity for the icmp messages */
    data.id = get_socket_id(data.fd);

    /* TODO: add to poll */

    return ret;

error_data:
    free(data.data);
    return ret;
}


int icmp_send_probe(struct probes * ps, int ttl)
{
    if (ttl != data.last_ttl) {
        if (set_ttl(data.fd, ttl) != 0) {
            return  -1;
        }
        data.last_ttl = ttl;
    }


    return 0;
}

int icmp_recv_probe(void)
{
    return 0;
}

void icmp_expire_probe(void)
{

}
