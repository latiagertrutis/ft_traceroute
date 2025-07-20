#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

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
