#ifndef IP_UTILS_H
#define IP_UTILS_H

#include <netinet/in.h>
#include <stdint.h>

typedef enum msg_status_e {
    TRC_MSG_DROP,
    TRC_MSG_ERROR,
    TRC_MSG_TTL,
    TRC_MSG_FINAL
} msg_status;

uint8_t *get_icmp_packet(uint8_t *buf, size_t len);
msg_status check_icmp_type(int type, int code);

#endif
