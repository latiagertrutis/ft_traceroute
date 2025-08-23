#ifndef IP_UTILS_H
#define IP_UTILS_H

#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>

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

typedef enum msg_status_e {
    TRC_MSG_DROP,
    TRC_MSG_ERROR,
    TRC_MSG_TTL,
    TRC_MSG_FINAL
} msg_status;

uint8_t *get_icmp_packet(uint8_t *buf, size_t len);
msg_status check_icmp_type(int type, int code);
bool equal_addr(const sockaddr_any *a, const sockaddr_any *b);
int set_ttl(int fd, int ttl);
#endif
