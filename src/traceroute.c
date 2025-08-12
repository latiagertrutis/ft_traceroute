#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sysexits.h>
#include <argp.h>
#include <string.h>

#include "ip_utils.h"
#include "mod-default.h"
#include "mod-icmp.h"
#include "traceroute.h"
#include "probe.h"

#define MAX_PACKET_LEN	65000
#define DEF_PROBES_PER_HOP 3
#define DEF_SIM_PROBES	16
#define DEF_FIRST_HOP 1
#define DEF_MAX_HOPS 30
#define DEF_DATA_LEN	40	/*  all but IP header...  */
#define DEF_START_PORT	33434	/*  start for traditional udp method   */
#define DEF_UDP_PORT	53	/*  dns   */
#define DEF_TCP_PORT	80	/*  web   */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

/* Ping options */
#define OPT_VERBOSE		0x01
#define OPT_PATTERN		0x02
#define OPT_FLOOD		0x04
#define OPT_INTERVAL	0x08

/* Types */
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
    int (*init) (sockaddr_any *dest, size_t data_len);
    int (*send_probe) (struct probes *ps, int ttl);
    int (*recv_probe) (struct probes *ps, int timeout, struct probe_range range);
    void (*expire_probe) (void);
} trc_mode;


typedef struct traceroute_s {
    host dest;
    ssize_t pkt_len;
    unsigned int probes_per_hop;
    unsigned int sim_probes;
    unsigned int first_hop;
    unsigned int max_hops;
} traceroute;

/* Prototypes */
static int init_mode(trc_mode * mode, mode_id id);
static error_t parser(int key, char *arg, struct argp_state *stat);
static int init_addr(host *host);
static int init_mode(trc_mode * mode, mode_id id);

/* Globals */
volatile bool done = false;

/* Statics */
static char doc[] = "Track packet hops over IP";
static char args_doc[] = "HOST [PACKET_LEN]";
static struct argp_option options[] = {
    { "queries", 'q', "NUM", 0, "Set the number of probes per each hop", 0},
    { "first", 'f', "NUM", 0, "Start from the specified hop (instead from 1)", 0},
    { "max-hops", 'm', "NUM", 0, "Set the max number of hops (max TTL to be reached)", 0},
    {0}
};
static struct argp argp = {options, parser, args_doc, doc, NULL, NULL, NULL};

/* static void traceroute_sigint_handler(int signal) */
/* { */
/*     (void) signal; */
/*     done = true; */
/* } */

static int init_mode(trc_mode * mode, mode_id id)
{
    switch (id) {
    case TRC_DEFAULT:
        mode->id = TRC_DEFAULT;
        mode->init  = def_init;
        mode->send_probe = def_send_probe;
        mode->recv_probe = def_recv_probe;
        mode->expire_probe = def_expire_probe;
        break;
    /* case TRC_ICMP: */
    /*     mode->id = TRC_ICMP; */
    /*     mode->send_probe = icmp_send_probe; */
    /*     mode->recv_probe = icmp_recv_probe; */
    /*     mode->expire_probe = icmp_expire_probe; */
    /*     break; */
    default:
        /* This should never happen */
        fprintf(stderr, "Error: mode %d does not exist\n", id);
        return -1;
    }

    return 0;
}

static error_t parser(int key, char *arg, struct argp_state *stat)
{
    traceroute *trc;

    trc = stat->input;

    switch (key) {
    case 'q':
        trc->probes_per_hop = atoi(arg);
        if (trc->probes_per_hop == 0) {
            fprintf(stderr, "Error: Can not set probes per hop equal to 0\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'f':
        trc->first_hop = atoi(arg);
        if (trc->first_hop == 0) {
            fprintf(stderr, "Error: Can not set first hop equal to 0\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'm':
        trc->max_hops = atoi(arg);
        if (trc->max_hops == 0) {
            fprintf(stderr, "Error: Can not set max hops equal to 0\n");
            exit(EXIT_FAILURE);
        }
        break;
    case ARGP_KEY_ARG:
        switch (stat->arg_num) {
        case 0:
            trc->dest.name = arg;
            break;
        case 1:
            trc->pkt_len = atoi(arg);
            // TODO: Maybe check error here
            if (trc->pkt_len > MAX_PACKET_LEN) {
                fprintf(stderr, "Error: Packet lenght too big: %ld (max is %d)\n", trc->pkt_len,
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

static int init_addr(host *host)
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

static void print_header(traceroute *trc)
{
    char addr_buf[INET_ADDRSTRLEN];

    /* Get string of the address name */
    getnameinfo(&trc->dest.addr.sa, sizeof(struct sockaddr),
                addr_buf, sizeof(addr_buf), 0, 0, NI_NUMERICHOST);

    printf ("traceroute to %s (%s), %u hops max, %zu byte packets\n",
            trc->dest.canonname, addr_buf, trc->max_hops, trc->pkt_len);
    fflush (stdout);
}

static void print_probes(struct probes *ps, struct probe_range range)
{
    (void)ps;
    (void)range;
}

static int trace(traceroute *trc, trc_mode *mode)
{
    unsigned int start = (trc->first_hop - 1) * trc->probes_per_hop;
    unsigned int end = trc->max_hops * trc->probes_per_hop;
    int ret = 0;
    struct probes *ps;

    /* TODO: if probes is not used in this level it can be ofuscated in module level */
    ps = init_probes(trc->max_hops * trc->probes_per_hop);
    if (ps == NULL) {
        /* TODO: free probes at end */
        return -1;
    }

    print_header(trc);

    while (start < end) {
        unsigned int n;
        struct probe_range range = {
            .min = start,
            .max = MIN(start + trc->sim_probes, end)
        };

        for (n = range.min; n < range.max; n++) {
            int ttl = n / trc->probes_per_hop + 1;

            /* Do not check error */
            mode->send_probe(ps, ttl);
        }

        start = n;

        mode->recv_probe(ps, 5, range);

        print_probes(ps, range);

        if (ps->done == true) {
            printf("Trace Done!\n");
            start = end;
            continue;
        }
    }

    deinit_probes(ps);

    mode->expire_probe();
    return ret;
}

int main(int argc, char** argv)
{
    int ret = 0;
    mode_id id = TRC_DEFAULT;
    size_t data_len = 0;
    trc_mode mode;
    traceroute trc = {
        .dest = {NULL, NULL, {}},
        .pkt_len = -1,
        .probes_per_hop = DEF_PROBES_PER_HOP,
        .sim_probes = DEF_SIM_PROBES,
        .first_hop = DEF_FIRST_HOP,
        .max_hops = DEF_MAX_HOPS,
    };

    argp_parse(&argp, argc, argv, 0, NULL, &trc);

    if (trc.pkt_len < 0) {
        /* TODO: Move sizeof(struct udphdr) to specific moduele, add a variable of header lenght to manage icmp case which will have no udp header */
        data_len = DEF_DATA_LEN - sizeof(struct udphdr);
        trc.pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
    }
    else if (trc.pkt_len >= (ssize_t)(sizeof(struct iphdr) + sizeof(struct udphdr))) {
        data_len = trc.pkt_len - sizeof(struct iphdr) - sizeof(struct udphdr);
    }

    if (init_addr(&trc.dest) != 0) {
        fprintf(stderr, "Error: init_addr()\n");
        exit(EXIT_FAILURE);
    }

    printf("Name: %s\nCanonname: %s\n", trc.dest.name, trc.dest.canonname);

    if (init_mode(&mode, id) != 0) {
        ret = EXIT_FAILURE;
        goto exit_addr;
    }

    if (mode.init(&trc.dest.addr, data_len) != 0) {
        fprintf(stderr, "Error: Initializing mode: %s\n", strerror(errno));
        ret = EXIT_FAILURE;
        goto exit_addr;
    }

    if (trace(&trc, &mode) != 0) {
        ret = EXIT_FAILURE;
        goto exit_addr;
    }

exit_addr:
    free(trc.dest.canonname);

    return ret;
}
