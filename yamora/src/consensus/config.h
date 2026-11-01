#ifndef YAMORA_CONSENSUS_CONFIG_H
#define YAMORA_CONSENSUS_CONFIG_H
#include "cluster.h"
#include "../value.h"
typedef struct {
    YDRaftConfig raft;
    const char *certificate, *key, *ca, *crl_file;
    unsigned request_timeout_ms;
    YDRaftCheckpointPolicy checkpoints;
    YDRaftCompactionPolicy compaction;
    YDRaftApplicationWorkerPolicy application_compaction;
    YDValue *model;
} YDRaftSettings;
/* Private, bounded, strict YAML. Returned strings borrow the owned model. */
YDRaftSettings *yd_raft_settings_load(const char *path, char *error, size_t length);
void yd_raft_settings_free(YDRaftSettings *settings);
/* Canonical 32 lowercase hex digits, nonzero. Also used for client retry IDs. */
bool yd_raft_id_parse(const char *text, unsigned char id[16]);
#endif
