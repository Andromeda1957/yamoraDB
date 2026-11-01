#ifndef YAMORA_CONSENSUS_CAPTURE_H
#define YAMORA_CONSENSUS_CAPTURE_H
#include "snapshot.h"
typedef struct YDRaftCapture YDRaftCapture;
/* Immutable verified archive. Owns its descriptor and can outlive the source
 * application/controller. Reads may overlap; join readers before close. No
 * operation on this handle selects an application or trims a journal. */
bool yd_raft_capture_manifest(const YDRaftCapture *capture,
                                unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST]);
bool yd_raft_capture_read(const YDRaftCapture *capture, uint64_t offset, void *bytes,
                            size_t size, char *error, size_t length);
void yd_raft_capture_close(YDRaftCapture *capture);
#endif
