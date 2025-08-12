#ifndef PROBE_H
#define PROBE_H

#include <stdbool.h>
#include <sys/time.h>

#include "ip_utils.h"

struct probe {
    struct timeval sent_time;
    struct timeval recv_time;
    sockaddr_any sa;
};

/* TODO: continue here, put probes in trace and pass them to the modules. */
struct probes {
    bool done;
    unsigned int n_probes;
    struct probe *p;
};

struct probe_range {
    unsigned int min;
    unsigned int max;
};

struct probes *init_probes(unsigned int n_probes);
void deinit_probes(struct probes *ps);
struct probe *get_probe(struct probes *ps, unsigned int idx);

#endif
