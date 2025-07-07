#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sysexits.h>
#include <argp.h>
#include <string.h>

#include "mod-default.h"
#include "mod-icmp.h"
#include "traceroute.h"

#define MAX_PACKET_LEN	65000

#define DEF_START_PORT	33434	/*  start for traditional udp method   */
#define DEF_UDP_PORT	53	/*  dns   */
#define DEF_TCP_PORT	80	/*  web   */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* Ping options */
#define OPT_VERBOSE		0x01
#define OPT_PATTERN		0x02
#define OPT_FLOOD		0x04
#define OPT_INTERVAL	0x08

typedef enum mode_id_e {
    TRC_DEFAULT,
    TRC_ICMP,
} mode_id;

typedef struct traceroute_stat_s {
    double tmin;                  /* minimum round trip time */
    double tmax;                  /* maximum round trip time */
    double tsum;                  /* sum of all times, for doing average */
    double tsumsq;                /* sum of all times squared, for std. dev. */
} traceroute_stat;

typedef struct traceroute_mode_s {
    mode_id id;
    void (*send_probe) (probe *p, int ttl);
    void (*recv_probe) (void);
    void (*expire_probe) (void);
} trc_mode;


struct host {
    char *name;
    char *canonname;
    struct sockaddr_in addr;
};

typedef struct traceroute_s {
    struct host host;
    int pkt_len;
} traceroute;


volatile bool done = false;

static void traceroute_sigint_handler(int signal)
{
    done = true;
}

static void init_mode(trc_mode * mode, mode_id id)
{
    switch (id) {
    case TRC_DEFAULT:
        mode->id = TRC_DEFAULT;
        mode->send_probe = def_send_probe;
        mode->recv_probe = def_recv_probe;
        mode->expire_probe = def_expire_probe;
        break;
    case TRC_ICMP:
        mode->id = TRC_ICMP;
        mode->send_probe = icmp_send_probe;
        mode->recv_probe = icmp_recv_probe;
        mode->expire_probe = icmp_expire_probe;
        break;
    default:
        /* This should never happen */
        fprintf(stderr, "Error: mode %d does not exist\n", id);
        exit(EXIT_FAILURE);
    }
}

static char doc[] = "Track packet hops over IP";
static char args_doc[] = "HOST [PACKET_LEN]";

static error_t parser(int key, char *arg, struct argp_state *stat)
{
    traceroute *trc;

    trc = stat->input;

    switch (key) {
    case ARGP_KEY_ARG:
        switch (stat->arg_num) {
        case 0:
            trc->host.name = arg;
            break;
        case 1:
            trc->pkt_len = atoi(arg);
            // TODO: Maybe check error here
            if (trc->pkt_len > MAX_PACKET_LEN) {
                fprintf(stderr, "Error: Packet lenght too big: %d (max is %d)\n", trc->pkt_len,
                        MAX_PACKET_LEN);
                exit(EXIT_FAILURE);
            }
            break;
        default:
            argp_usage(stat);
        }
        break;
    case ARGP_KEY_END:
        if (stat->arg_num < 1) {
            argp_usage(stat);
        }
        break;
    default:
        return  ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = {NULL, parser, args_doc, doc};

static int init_addr(struct host *host)
{
    int ret;
    struct addrinfo hints = {0};
    struct addrinfo *res, *tmp;

    hints.ai_family = AF_INET;
    //TOOD: Change this when adding other protocols
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_CANONNAME;

    if (host->name ==  NULL) {
        return -1;
    }

    ret = getaddrinfo(host->name, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "Error: getaddrinfo(): %d\n", ret);
        return -1;
    }

    for (tmp = res; tmp; tmp = tmp->ai_next) {
        if (tmp->ai_family == AF_INET) {
            break;
        }
    }

    if (tmp == NULL) { tmp = res; }

    if (tmp->ai_addrlen > sizeof(struct sockaddr_in)) {
        return -1;
    }

    memcpy(&host->addr, tmp->ai_addr, tmp->ai_addrlen);
    if (tmp->ai_canonname != NULL) {
        host->canonname = strdup(tmp->ai_canonname);
    }

    freeaddrinfo(res);

    return 0;
}

int main(int argc, char** argv)
{
    mode_id id = TRC_DEFAULT;
    trc_mode mode;
    traceroute trc = {
        .host = {NULL, NULL, {0}},
        .pkt_len = MAX_PACKET_LEN,
    };

    argp_parse(&argp, argc, argv, 0, NULL, &trc);

    if (init_addr(&trc.host) != 0) {
        fprintf(stderr, "Error: init_addr()\n");
        exit(EXIT_FAILURE);
    }

    printf("Name: %s\nCanonname: %s\n", trc.host.name, trc.host.canonname);

    free(trc.host.canonname);

    return 0;
}
