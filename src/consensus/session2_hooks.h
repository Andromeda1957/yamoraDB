#ifndef YD_SESSION2_HOOKS_H
#define YD_SESSION2_HOOKS_H

#include <stdbool.h>
#include <stdint.h>

/* Compile-only qualification hooks. Ordinary binaries have no environment,
 * file, gate, timing or linkage dependency on this module. */
#ifdef YD_RAFT_SESSION2_TEST_HOOKS
uint64_t yd_session2_mutation_enter(unsigned node, const unsigned char id[16], bool *allowed);
void yd_session2_mutation_exit(unsigned node, const unsigned char id[16], uint64_t call);
void yd_session2_disk_delay(unsigned node);
void yd_session2_index_hold(unsigned node, const unsigned char id[16]);
uint64_t yd_session2_maintenance_begin(unsigned node, const char *kind);
void yd_session2_maintenance_end(unsigned node, const char *kind, uint64_t cycle);
#else
static inline uint64_t yd_session2_mutation_enter(unsigned node, const unsigned char id[16],
                                                 bool *allowed) {
    (void)node; (void)id;
    if (allowed) *allowed = true;
    return 0;
}
static inline void yd_session2_mutation_exit(unsigned node, const unsigned char id[16],
                                            uint64_t call) {
    (void)node; (void)id; (void)call;
}
static inline void yd_session2_disk_delay(unsigned node) { (void)node; }
static inline void yd_session2_index_hold(unsigned node, const unsigned char id[16]) {
    (void)node; (void)id;
}
static inline uint64_t yd_session2_maintenance_begin(unsigned node, const char *kind) {
    (void)node; (void)kind; return 0;
}
static inline void yd_session2_maintenance_end(unsigned node, const char *kind, uint64_t cycle) {
    (void)node; (void)kind; (void)cycle;
}
#endif
#endif
