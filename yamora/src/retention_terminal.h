#ifndef YAMORA_RETENTION_TERMINAL_H
#define YAMORA_RETENTION_TERMINAL_H

#include <stdbool.h>
#include <stdint.h>

#define YD_RETENTION_TERMINAL_VERSION 1U
#define YD_RETENTION_TERMINAL_SIZE 8292U
#define YD_RETENTION_TERMINAL_HEADER_BYTES 8192U
#define YD_RETENTION_TERMINAL_DIGEST_BYTES 32U

/* Caller-supplied data, not a native observation or authority capability.
 * headers contains the complete physical slot 0 followed by slot 1. The codec
 * treats those bytes as opaque; native capture must establish their validity,
 * complete reads, actual identities, common fence and exclusive-cut binding.
 * No enrollment, drain, CLEAN, recovery, restart or deletion authority follows.
 * This host struct, including its padding, is never a persistence format. */
typedef struct {
    uint64_t root_device, root_inode;
    uint64_t journal_device, journal_inode, file_size;
    uint32_t fence_version, producer_protocol;
    unsigned char incarnation[32];
    unsigned char headers[YD_RETENTION_TERMINAL_HEADER_BYTES];
} YDRetentionTerminalInput;

/* SHA256 over exactly SIZE bytes, with no reserved/trailing bytes:
 * [0,16) "YAMORA-TERMROOT" plus one NUL;
 * LE32 version at 16, fence_version at 20, producer_protocol at 24;
 * LE64 root_device/root_inode/journal_device/journal_inode/file_size at
 * 28/36/44/52/60; incarnation at 68; ordered opaque headers at 100.
 * Require fence_version == producer_protocol == 1, nonzero incarnation and
 * inodes, and 8192 <= file_size <= INT64_MAX. Devices include zero and their
 * entire uint64_t range. Physical file size need not be page-aligned.
 * Native capture separately checks lossless conversion from native identities.
 *
 * NULL digest returns false without reading input. Otherwise digest names 32
 * writable bytes: every failure clears all 32, including a NULL input or a
 * failed hash primitive that emitted bytes. Eligible input is snapshotted
 * before any output write, supporting exact and partial overlap; clearing an
 * overlapping output destroys those input bytes too. Other input is unchanged.
 * Caller supplies a stable readable typed input and live output, joins calls
 * before changing/freeing buffers, and uses disjoint outputs for concurrency.
 * The implementation has fixed stack storage, no heap/I/O/lock calls or shared
 * mutable state; it calls the linked system OpenSSL Init/Update/Final routines.
 * It does not promise allocation behavior for arbitrary OpenSSL builds/hooks.
 * Hash only: no decoder, disk format, authentication or journal-content proof. */
bool yd_retention_terminal_hash(const YDRetentionTerminalInput *input,
    unsigned char digest[YD_RETENTION_TERMINAL_DIGEST_BYTES]);

#endif
