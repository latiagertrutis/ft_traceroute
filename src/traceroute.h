#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <netinet/in.h>

typedef struct probe_s {
    int fd;
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

#endif
