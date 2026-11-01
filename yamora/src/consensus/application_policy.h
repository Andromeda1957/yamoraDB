#ifndef YAMORA_CONSENSUS_APPLICATION_POLICY_H
#define YAMORA_CONSENSUS_APPLICATION_POLICY_H
#include "../disk.h"
#define YD_RAFT_POLICY_IDENTITY 40U
/* Frozen YDAPPL02 suffix: SHA256(YDPRED01 || presence || catalog hash),
 * admission protocol YDADM01 (7 bytes), exact immutable capability mask (1).
 * Capture never applies policy to historical receipts or document values. */
bool yd_raft_policy_identity(YDDisk *, const YDDiskView *, unsigned char out[40],
    char *, size_t);
bool yd_raft_policy_compatible(YDDisk *, const unsigned char frozen[40]);
bool yd_raft_policy_predecessor(YDDisk *, const YDDiskView *, const unsigned char frozen[40],
    char *, size_t);
#endif
