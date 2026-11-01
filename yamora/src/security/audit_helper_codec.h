#ifndef YAMORA_AUDIT_HELPER_CODEC_H
#define YAMORA_AUDIT_HELPER_CODEC_H
#include "audit.h"
#define YD_AUDIT_PACKET_BYTES 512U
#define YD_AUDIT_ANCHOR_BYTES 128U
enum { YD_AUDIT_HELLO = 1, YD_AUDIT_BEGIN, YD_AUDIT_FINISH_REQUEST, YD_AUDIT_REPLY };
enum { YD_AUDIT_ACK, YD_AUDIT_IPC_REFUSED, YD_AUDIT_IPC_BUSY, YD_AUDIT_IPC_LIMIT,
    YD_AUDIT_IPC_UNCERTAIN, YD_AUDIT_IPC_ERROR };
typedef struct {
    uint32_t kind;
    uint64_t id;
    YDAuditEvent event;
    unsigned char handle[16];
    YDAuditCompletion completion;
    uint32_t result, request_kind;
    unsigned char incarnation[16];
    uint64_t sequence;
} YDAuditPacket;
/* Pure codecs, explicit LE framing. Failed decode clears the entire output.
 * Input/output must be disjoint. No structure padding goes on disk/wire. */
bool yd_audit_packet_encode(const YDAuditPacket *, unsigned char out[512]);
bool yd_audit_packet_decode(const unsigned char bytes[512], YDAuditPacket *);
bool yd_audit_anchor_encode(const YDAuditHead *, unsigned char out[128]);
bool yd_audit_anchor_decode(const unsigned char bytes[128], YDAuditHead *);
#endif
