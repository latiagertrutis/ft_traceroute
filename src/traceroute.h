#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

typedef struct probe_s {
    int fd;
    uint8_t *data;
    size_t data_len;
    uint16_t port;
} probe;

typedef union sockaddr_u {
    struct sockaddr sa;
    struct sockaddr_in sa_in;
} sockaddr_any;

typedef struct host_s {
    char *name;
    char *canonname;
    sockaddr_any addr;
} host;

#define DEF_START_PORT	33434	/*  start for traditional udp method   */

#endif
