#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "ip_utils.h"

/* Check for the expected ICMP error codes. The only case this is not the last
 * probe is when type is time exceeded and it has exeeded because of the ttl.
 * Otherwise this will be the last probe since, either we tested the port or
 * any other error arrived. */
msg_status check_icmp_type(int type, int code)
{
    if (type == ICMP_TIME_EXCEEDED) {
        if (code == ICMP_EXC_TTL) {
            return TRC_MSG_TTL;
        }
    }

    if (type == ICMP_DEST_UNREACH) {

        switch (code) {
        case ICMP_UNREACH_NET:
        case ICMP_UNREACH_NET_UNKNOWN:
        case ICMP_UNREACH_ISOLATED:
        case ICMP_UNREACH_TOSNET:
            break;

        case ICMP_UNREACH_HOST:
        case ICMP_UNREACH_HOST_UNKNOWN:
        case ICMP_UNREACH_TOSHOST:
            break;

        case ICMP_UNREACH_NET_PROHIB:
        case ICMP_UNREACH_HOST_PROHIB:
        case ICMP_UNREACH_FILTER_PROHIB:
            break;

        case ICMP_UNREACH_PORT:
            return TRC_MSG_FINAL;

        case ICMP_UNREACH_PROTOCOL:
            break;

        case ICMP_UNREACH_NEEDFRAG:
            break;

        case ICMP_UNREACH_SRCFAIL:
            break;

        case ICMP_UNREACH_HOST_PRECEDENCE:
            break;

        case ICMP_UNREACH_PRECEDENCE_CUTOFF:
            break;

        default:
            break;
        }

    }

    return TRC_MSG_ERROR;
}

/* Search for icmp packet, and check if it is the icmp error type expected,
 * otherwise return 0. Four possible scenarios can happen here:
 * 1. [TRC_MSG_DROP] We received a message that is not for us, then drop the message
 * 2. [TRC_MSG_ERROR] We received a ICMP error that we are not expecting, then print
 *    the error and set this as the last probe.
 * 3. [TRC_MSG_TTL] We recevied time exceeded because of ttl, then launch the next probe.
 * 4. [TRC_MSG_FINAL] We received "unreach port", then we reached the host, this
 *    is the last probe. */
uint8_t *get_icmp_packet(uint8_t *buf, size_t len)
{
    struct iphdr *ip_hdr;
    size_t hdr_len;

    if (len < sizeof(struct iphdr)) {
        /* Not enough space for ip header */
        return NULL;
    }

    ip_hdr = (struct iphdr*) buf;
    /* Translate 32-bit words to 8-bit (RFC791, 3.1) */
    hdr_len = ip_hdr->ihl << 2;
    if (hdr_len > sizeof(struct iphdr)) {
        return NULL; // paranoia
    }

    if (ip_hdr->protocol != IPPROTO_ICMP) {
        /* Packet is not ICMP */
        return NULL;
    }

    if ((len - hdr_len) < sizeof(struct icmphdr) +
        sizeof(struct iphdr) + sizeof(struct udphdr)) {
        /* Not enough space for icmp msg we are expecting */
        return NULL;
    }

    return buf + hdr_len;
}
