#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/errqueue.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "mod-internal.h"
#include "ip_utils.h"
#include "probe.h"

struct def_data {
    int fd;
    sockaddr_any *dest;
    uint8_t *data;
    uint16_t id;
    int last_ttl;
    size_t data_len;
    uint16_t seq;
};

static struct def_data data = {};

static int init_socket()
{
    struct protoent *proto;
    int one = 1;

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

    if (setsockopt(data.fd, SOL_IP, IP_RECVERR, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_RECVERR");
    }

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

int icmp_init(sockaddr_any *dest, size_t data_len)
{
    size_t i;
    int ret = 0;

    data.dest = dest;
    data.data_len = data_len;
    data.seq = 1;
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

    return ret;

error_data:
    free(data.data);
    return ret;
}

void icmp_clean()
{
    free(data.data);
    close(data.fd);
}

int icmp_send_probe(struct probes * ps, int ttl)
{
    ssize_t bytes;
    struct icmp *pkt = (struct icmp *)data.data;
    struct probe *p = get_probe(ps, data.seq - 1);

    if (p == NULL) {
        return -1;
    }

    if (ttl != data.last_ttl) {
        if (set_ttl(data.fd, ttl) != 0) {
            return  -1;
        }
        data.last_ttl = ttl;
    }

    *pkt = (struct icmp) {
        .icmp_type = ICMP_ECHO,
        .icmp_code = 0,
        .icmp_cksum = 0,
        .icmp_id = htons(data.id),
        .icmp_seq = htons(data.seq),

        /* TODO: In dgram sockets checksum is computed by kernel */
    };

    gettimeofday(&p->sent_time, NULL);

    bytes = send(data.fd, data.data, data.data_len, 0);
    if (bytes < 0) {
        if (errno == ENOBUFS || errno == EAGAIN) {
            return bytes;
        }
        if (errno == EMSGSIZE || errno == EHOSTUNREACH) {
            return 0;    /*  recverr will say more...  */
        }
        perror("send");	/*  not recoverable   */
    }

    data.seq++;

    return bytes;
}

static int rcv_and_check_icmp(int fd, struct probes *ps, struct probe_range range)
{
    ssize_t bytes;
    sockaddr_any from;
    uint8_t control[1024];
    uint8_t buf[1500];
    struct probe *p;
    struct iovec iov = {};
    struct msghdr msg = {};
    struct icmp *icmp;
    struct cmsghdr *cmsg;
    struct sock_extended_err *ee = NULL;

    (void) range;
    /* Init msg struct */
    iov = (struct iovec) {
        .iov_base = buf,
        .iov_len = sizeof(buf),
    };

    msg = (struct msghdr) {
        .msg_name = &from,
        .msg_namelen = sizeof(sockaddr_any),
        .msg_control = control,
        .msg_controllen = sizeof(control),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    /* Try first to read the error queue (most common case) */
    bytes = recvmsg(fd, &msg, MSG_ERRQUEUE);
    if (bytes < 0) {
        /* If not, read the normal queue that should be the final case */
        bytes = recvmsg(fd, &msg, 0);
        if (bytes < 0) {
            perror("recvmsg");
            return -1;
        }
    }

    /* Check the message received */
    if ((size_t)bytes < sizeof(struct icmphdr)) {
        fprintf(stderr, "ICMP received not long enough %ld", bytes);
        return -1;
    }

    icmp = (struct icmp *) buf;

    if (ntohs(icmp->icmp_id) != data.id) {
        fprintf(stderr, "ICMP id not matching expected/read [%d/%d]",
                data.id, ntohs(icmp->icmp_id));
        return -1;
    }

    p = get_probe(ps, ntohs(icmp->icmp_seq) - 1);
    if (p == NULL) {
        return -1;
    }

    if (p->sent_time.tv_sec == 0) {
        /* Message was not sent */
        return 0;
    }

    /* Mark reception of message */
    gettimeofday(&p->recv_time, NULL);

    /* Parse CMSG */
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        void *ptr = CMSG_DATA(cmsg);

        if (ptr == NULL) { continue; }

        switch (cmsg->cmsg_level) {
        case SOL_SOCKET:
            if (cmsg->cmsg_type == SO_TIMESTAMP) {
                p->recv_time = *(struct timeval *)ptr;
            }
            break;
        case SOL_IP:
            if (cmsg->cmsg_type == IP_RECVERR) {
                ee = (struct sock_extended_err *)ptr;
                memcpy(&p->sa, SO_EE_OFFENDER(ee), sizeof(p->sa));
            }
            break;
        }
    }

    if (ee == NULL) {
        memcpy(&p->sa, &from, sizeof(p->sa.sa));
    }

    if (icmp->icmp_type != ICMP_ECHOREPLY) {
        return 1;
    }

    ps->done = true;
    p->final = true;

    return 1;
}

int icmp_recv_probe(struct probes *ps, int timeout, struct probe_range range)
{
    return select_probes(data.fd, ps, timeout, range, rcv_and_check_icmp);
}
