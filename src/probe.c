#include "probe.h"
#include <stdlib.h>

struct probes *init_probes(unsigned int n_probes)
{
    struct probes *ps;

    ps = calloc(1, sizeof(struct probes));
    if (ps == NULL) {
        return NULL;
    }

    ps->n_probes = n_probes;
    ps->p = calloc(n_probes, sizeof(struct probe));
    if (ps->p == NULL) {
        return NULL;
    }

    return ps;
}

void deinit_probes(struct probes *ps)
{
    free(ps->p);
    free(ps);
}

struct probe *get_probe(struct probes *ps, unsigned int idx)
{
    if (ps == NULL || idx >= ps->n_probes) {
        return NULL;
    }

    return &ps->p[idx];
}
