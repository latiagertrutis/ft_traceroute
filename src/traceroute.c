#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sysexits.h>

#include "mod-default.h"
#include "traceroute.h"

#define HELP_STRING \
    "Usage: ft_traceroute [OPTION...] HOST ...\n"


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


typedef struct traceroute_s {
} trc;


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
    default:
        /* This should never happen */
        fprintf(stderr, "Error: mode %d does not exist\n", id);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv)
{
    int c;
    mode_id id = TRC_DEFAULT;
    trc_mode mode;

    while ((c = getopt(argc, argv, "vfi:c:p:t:?")) != -1) {
        switch (c) {
        case '?':
            if (optopt && optopt != '?') {
                exit (EX_USAGE);
            }
            printf(HELP_STRING);
            exit(EXIT_SUCCESS);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Specify \"host\" missing argument.");
        exit (EX_USAGE);
    }

    init_mode(&mode, id);
}
