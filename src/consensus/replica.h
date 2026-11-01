#ifndef YAMORA_CONSENSUS_REPLICA_H
#define YAMORA_CONSENSUS_REPLICA_H
#include "application.h"

/* Only the application owner calls these. Preparation creates one unpublished
 * exclusive transaction; simulation aborts it, committed apply adds the common
 * receipt/checkpoint and publishes it. No process-local staging object exists. */
YDDiskReply yd_raft_replica_prepare(YDDisk *disk, const YDRaftWrite *write,
                                    YDDiskTxn **prepared);
/* Caller owns the immutable view and a fresh quorum read for the whole call. */
YDDiskReply yd_raft_replica_read(YDDisk *disk, const YDDiskView *view,
                                 const char *method, const char *target,
                                 const unsigned char *body, size_t size,
                                 const char *match, const char *none, bool gzip);
/* 0 unrecognized key, 1 well-formed replica key/record, -1 invalid record. */
int yd_raft_replica_key(YDDisk *disk, const YDDiskView *view,
                        const unsigned char *key, size_t size, uint64_t offset,
                        char *error, size_t length);
/* Cross-record validation: exactly one active session owns all staged records. */
bool yd_raft_replica_validate(YDDisk *disk, const YDDiskView *view,
                              char *error, size_t length);
/* Durable read-only destination binding: 0 absent, 1 bound, -1 corrupt.
 * Ordinary application writes must refuse whenever the result is nonzero,
 * even after a restart without the local pre-bootstrap --replica option. */
int yd_raft_replica_destination(YDDisk *disk, const YDDiskView *view,
                                 char *error, size_t length);
#endif
