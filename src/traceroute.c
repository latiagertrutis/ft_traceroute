#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
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
#include <signal.h>

#include "ip_utils.h"
#include "mod-default.h"
#include "mod-icmp.h"

#include "probe.h"
#include "utils.h"

#define MAX_PACKET_LEN	65000
#define DEF_PROBES_PER_HOP 3
#define DEF_SIM_PROBES	16
#define DEF_FIRST_HOP 1
#define DEF_MAX_HOPS 30
#define DEF_DATA_LEN	42	/*  all but headers...  */
#define DEF_START_PORT	33434	/*  start for traditional udp method   */
#define DEF_UDP_PORT	53	/*  dns   */
#define DEF_TCP_PORT	80	/*  web   */
#define DEF_TIMEOUT 5

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
    size_t header_len;
    bool raw_mode;
    int (*init) (sockaddr_any *dest, size_t data_len);
    int (*send_probe) (struct probes *ps, int ttl, unsigned int seq);
    int (*recv_probe) (struct probes *ps, int timeout, struct probe_range range);
    void (*clean) (void);
} trc_mode;


typedef struct traceroute_s {
    host dest;
    ssize_t pkt_len;
    bool resolve_dns;
    mode_id mode;
    int probes_per_hop;
    int sim_probes;
    int first_hop;
    int max_hops;
} traceroute;

/* Prototypes */
static int select_mode(trc_mode * mode, mode_id id);
static error_t parser(int key, char *arg, struct argp_state *stat);
static int init_addr(host *host, mode_id id);

/* Globals */
volatile bool isr_done = false;

/* Statics */
static char doc[] = "Track packet hops over IP";
static char args_doc[] = "HOST [PACKET_LEN]";
static struct argp_option options[] = {
    { "help", 'h', 0, 0, "Display this help menu", 0},
    { "queries", 'q', "NUM", 0, "Set the number of probes per each hop", 0},
    { "first", 'f', "NUM", 0, "Start from the specified hop (instead from 1)", 0},
    { "max-hops", 'm', "NUM", 0, "Set the max number of hops (max TTL to be reached)", 0},
    { "no-dns", 'n', 0, 0, "Do not resolve IP addresses to their domain names", 0},
    { "icmp", 'i', 0, 0, "Set the probe method to ICMP", 0},
    {0}
};
static struct argp argp = {options, parser, args_doc, doc, NULL, NULL, NULL};

static void traceroute_sigint_handler(int signal)
{
    (void) signal;
    isr_done = true;
}

static int select_mode(trc_mode * mode, mode_id id)
{
    switch (id) {
    case TRC_DEFAULT:
        mode->id = TRC_DEFAULT;
        mode->header_len = sizeof(struct udphdr);
        mode->raw_mode = true;
        mode->init  = def_init;
        mode->send_probe = def_send_probe;
        mode->recv_probe = def_recv_probe;
        mode->clean = def_clean;
        break;
    case TRC_ICMP:
        mode->id = TRC_ICMP;
        mode->header_len = sizeof(struct icmphdr);
        mode->raw_mode = false;
        mode->init  = icmp_init;
        mode->send_probe = icmp_send_probe;
        mode->recv_probe = icmp_recv_probe;
        mode->clean = icmp_clean;
        break;
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
        if (trc->probes_per_hop <= 0) {
            fprintf(stderr, "Error: Can not set probes per hop less or equal to 0\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'f':
        trc->first_hop = atoi(arg);
        if (trc->first_hop <= 0) {
            fprintf(stderr, "Error: Can not set first hop less or equal to 0\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'm':
        trc->max_hops = atoi(arg);
        if (trc->max_hops <= 0) {
            fprintf(stderr, "Error: Can not set max hops less or equal to 0\n");
            exit(EXIT_FAILURE);
        }
        if (trc->max_hops > 255) {
            fprintf(stderr, "Error: Can not set max hops greater than 255\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'i':
        trc->mode = TRC_ICMP;
        break;
    case 'n':
        trc->resolve_dns = false;
        break;
    case 'h':
        argp_state_help(stat, stat->out_stream, ARGP_HELP_STD_HELP);
        break;
    case ARGP_KEY_ARG:
        switch (stat->arg_num) {
        case 0:
            trc->dest.name = arg;
            break;
        case 1:
            trc->pkt_len = atoi(arg);
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

    if (trc->first_hop > trc->max_hops) {
        fprintf(stderr, "Error: First hop can not be greater than max hops\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}

static int init_addr(host *host, mode_id id)
{
    int ret;
    struct addrinfo hints = {0};
    struct addrinfo *res, *tmp;

    hints.ai_family = AF_INET;
    // Set to 0 so all types are valid. POSIX does not allow ICMP + DGRAM but linux does
    hints.ai_socktype = 0;
    hints.ai_flags = AI_CANONNAME;

    switch (id) {
    case TRC_DEFAULT:
        hints.ai_protocol = IPPROTO_UDP;
        break;
    case TRC_ICMP:
        hints.ai_protocol = IPPROTO_ICMP;
        break;
    }

    if (host->name ==  NULL) {
        return -1;
    }

    ret = getaddrinfo(host->name, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "Error: %s: Name or service not known [Code: %d]\n", host->name, ret);
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

static char *addr2str(sockaddr_any *addr)
{
    return inet_ntoa(addr->sa_in.sin_addr);
}

static void print_header(traceroute *trc)
{

    printf ("ft_traceroute to %s (%s), %u hops max, %zu byte packets",
            trc->dest.canonname, addr2str(&trc->dest.addr), trc->max_hops, trc->pkt_len);
    fflush (stdout);
}

static void print_addr(sockaddr_any *addr, bool resolve_dns)
{
    char *str;

    if (addr->sa.sa_family == 0) {
        return;
    }

    str = addr2str(addr);

    if (resolve_dns) {
        char addr_buf[1024] = {};

        getnameinfo(&addr->sa, sizeof(struct sockaddr),
                    addr_buf, sizeof(addr_buf), 0, 0, NI_NOFQDN);
        printf (" %s (%s)", addr_buf[0] ? addr_buf : str, str);
    }
    else {
        printf (" %s", str);
    }
}

/* Print a probe range */
static void print_probes(struct probes *ps, struct probe_range range, int probes_per_hop,
                         bool resolve_dns)
{
    static sockaddr_any *prev_addr = NULL;

    for (unsigned int i = range.min; i < range.max; i++) {
        unsigned int ttl = i / probes_per_hop + 1;
        unsigned int probe_module = i % probes_per_hop;
        struct probe *p;

        p = get_probe(ps, i);

        if (probe_module == 0) {
            printf("\n%2u ", ttl);
        }

        if (p->sa.sa.sa_family != AF_INET) {
            printf (" *");
            continue;
        }

        if (probe_module == 0 ||
            equal_addr(&p->sa, prev_addr) == false) {
            print_addr(&p->sa, resolve_dns);
        }

        /* If sa_family != 0 means that there has been a response */
        printf ("  %.3f ms", diff_timeval(p->sent_time, p->recv_time));

        if (p->final == true) {
            /* Print the lasts of this set of tests */
            range.max = MIN(i + probes_per_hop  - probe_module, range.max);
        }

        prev_addr = &p->sa;
    }
}

static int trace(traceroute *trc, trc_mode *mode)
{
    unsigned int start = (trc->first_hop - 1) * trc->probes_per_hop;
    unsigned int end = trc->max_hops * trc->probes_per_hop;
    int ret = 0;
    struct probes *ps;

    ps = init_probes(trc->max_hops * trc->probes_per_hop);
    if (ps == NULL) {
        return -1;
    }

    print_header(trc);

    signal(SIGINT, traceroute_sigint_handler);

    while (start < end) {
        unsigned int n;
        struct probe_range range = {
            .min = start,
            .max = MIN(start + trc->sim_probes, end)
        };

        for (n = range.min; n < range.max; n++) {
            int ttl = n / trc->probes_per_hop + 1;

            /* Do not check error */
            mode->send_probe(ps, ttl, n);
        }

        start = n;

        mode->recv_probe(ps, DEF_TIMEOUT, range);

        print_probes(ps, range, trc->probes_per_hop, trc->resolve_dns);

        if (ps->done == true || isr_done == true) {
            start = end; // Finish
            printf("\n");
            continue;
        }
    }

    deinit_probes(ps);

    return ret;
}

int main(int argc, char** argv)
{
    int ret = 0;
    size_t iphdr_len;
    trc_mode mode;
    traceroute trc = {
        .dest = {NULL, NULL, {}},
        .pkt_len = -1,
        .mode = TRC_DEFAULT,
        .resolve_dns = true,
        .probes_per_hop = DEF_PROBES_PER_HOP,
        .sim_probes = DEF_SIM_PROBES,
        .first_hop = DEF_FIRST_HOP,
        .max_hops = DEF_MAX_HOPS,
    };

    argp_parse(&argp, argc, argv, 0, NULL, &trc);

    if (init_addr(&trc.dest, trc.mode) != 0) {
        exit(EXIT_FAILURE);
    }

    if (select_mode(&mode, trc.mode) != 0) {
        ret = EXIT_FAILURE;
        goto exit_addr;
    }

    /* Add iphdr to the packet len if we are reading from a raw socket */
    iphdr_len = mode.raw_mode ? sizeof(struct iphdr) : 0;
    if (trc.pkt_len < 0) {
        trc.pkt_len =  iphdr_len + mode.header_len + DEF_DATA_LEN;
    }
    else if (trc.pkt_len < (ssize_t)(iphdr_len + mode.header_len)) {
        printf("Error: Packet lenght specified is less than %ld\n", iphdr_len + mode.header_len);
        ret = EXIT_FAILURE;
        goto exit_addr;
    }

    if (mode.init(&trc.dest.addr, trc.pkt_len) != 0) {
        fprintf(stderr, "Error: Initializing mode: %s\n", strerror(errno));
        ret = EXIT_FAILURE;
        goto exit_addr;
    }

    if (trace(&trc, &mode) != 0) {
        ret = EXIT_FAILURE;
        goto exit_mode;
    }

exit_mode:
    mode.clean();
exit_addr:
    free(trc.dest.canonname);

    return ret;
}
