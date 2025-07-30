#ifndef PROBE_H
#define PROBE_H

#include <stdbool.h>
#include <sys/time.h>

struct probe {
    struct timeval sent_time;
    struct timeval recv_time;
};

struct hop {
    bool done;
    struct probe *p;
};

/* TODO: continue here, put probes in trace and pass them to the modules. */
struct probes {
    bool done;
    struct hop *h;
};

struct probe_range {
    unsigned int min;
    unsigned int max;
};

struct probes *init_probes(unsigned int n_hops, unsigned int probes_per_hop);
void deinit_probes(struct probes *ps);
struct probe *get_probe(struct probes *ps, unsigned int idx);

#endif
