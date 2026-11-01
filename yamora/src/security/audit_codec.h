#ifndef YAMORA_SECURITY_AUDIT_CODEC_H
#define YAMORA_SECURITY_AUDIT_CODEC_H
#include "audit.h"

enum {
    YD_AUDIT_GENESIS = 1, YD_AUDIT_INTENT, YD_AUDIT_FINISH,
    YD_AUDIT_SEAL, YD_AUDIT_CONTINUE
};
#define YD_AUDIT_HAS_REVISION 1U
typedef struct YDAuditMAC YDAuditMAC;
/* Decoded representation only. Never serialize the C object or its padding.
 * mac is decoded output; encode computes the actual trailing authenticator. */
typedef struct {
    uint32_t kind, flags;
    YDAuditHead head;
    uint64_t intent, wall_ms, elapsed_us;
    unsigned char previous[32];
    uint32_t transport, authentication, operation, outcome, status, actor_length;
    unsigned char actor[128], revision[16];
    uint32_t subject_length; /* Access-management operations only. */
    unsigned char subject[128];
    uint64_t next_segment;
    unsigned char next_id[16];
    YDAuditLimits limits;
} YDAuditRecord;
bool yd_audit_limits_valid(const YDAuditLimits *);
bool yd_audit_limits_equal(const YDAuditLimits *, const YDAuditLimits *);
bool yd_audit_head_equal(const YDAuditHead *, const YDAuditHead *);
bool yd_audit_nonzero(const unsigned char *, size_t);
/* Pure field validation, without provider work or I/O. */
bool yd_audit_record_valid(const YDAuditRecord *);
/* OpenSSL HMAC/SHA256 only. Provider failures return ERROR, never success or
 * fallback. May allocate/invoke OpenSSL providers; no allocation-free promise.
 * Private codec context: caller supplies exclusive use and joined disposal;
 * the storage owner serializes it. This context grants no storage authority. */
YDAuditMAC *yd_audit_mac_new(const unsigned char key[32]);
void yd_audit_mac_free(YDAuditMAC *);
YDAuditResult yd_audit_record_encode(YDAuditMAC *, const YDAuditRecord *,
    unsigned char out[YD_AUDIT_RECORD_BYTES]);
/* Framing/field/MAC validation. Full stream transitions are checked by the
 * storage verifier. Every failure clears the decoded output. */
YDAuditResult yd_audit_record_decode(YDAuditMAC *,
    const unsigned char bytes[YD_AUDIT_RECORD_BYTES], YDAuditRecord *out);
#endif
