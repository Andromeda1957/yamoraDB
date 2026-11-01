#ifndef YAMORA_SECURITY_STORAGE_IMAGE_H
#define YAMORA_SECURITY_STORAGE_IMAGE_H
#include "envelope.h"
#include "disk.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YD_STORAGE_IMAGE_KIND UINT32_C(0x59444931)
#define YD_STORAGE_IMAGE_MAX YD_ENVELOPE_PLAINTEXT_MAX
typedef struct YDStorageImage YDStorageImage;
typedef struct {
    /* Independently trusted EXACT encrypted publication identity. Fresh roots
     * use generation 1. Never obtain expected identity from the input file.
     * Native commits and key rotation advance this generation independently
     * from the native superblock generation. Save it in a trusted external
     * checkpoint for restart; this module provides no external rollback anchor. */
    YDEnvelopeIdentity expected;
    uint64_t maximum_bytes; /* 8192..64 MiB, multiple of 4096; includes history. */
    size_t cache_bytes;     /* Native cache: 32 KiB..1 GiB. */
    bool initialize;        /* Create ONLY in an actually empty private root. */
} YDStorageImageOptions;
/* Linux-only bounded standalone profile 5. Root must already be caller-owned
 * private 0700. Holds independent EX namespace flock through last native pin.
 * Full anonymous native extent MUST be mmap/mlock/MADV_DONTDUMP admitted; no
 * named plaintext file, plaintext staging file or weaker fallback exists.
 * Provider is borrowed through the last native pin; key_id selects new writes.
 * Generic native checkpoint/copy, schema, retention and cluster modes refuse.
 * Caller must keep pthread cancellation DISABLED through every call and output
 * adoption/cleanup, and join users before close. Callbacks must return normally
 * preserving that state. Foreign-PID use is unsupported and refuses first.
 * Success acknowledges only after ciphertext file + namespace sync. Any failed
 * publication fences the writer; preserve uncertain ciphertext artifacts.
 * The protected disk file remains named .yamora-disk. Legacy openers refuse it.
 * Process heap, OS swap/core policy and logical/network exports are separate
 * deployment concerns; the anonymous native FILE mapping is locked and omitted
 * from core dumps, but this API does not harden every application allocation. */
YDStorageImage *yd_storage_image_open_at(int directory,
    const YDKeyProvider *provider, const char *key_id,
    const YDStorageImageOptions *options, char *error, size_t length);
/* Borrowed native handle; all application operations retain native transaction,
 * exact-source, tree/index, receipt and replica-staging behavior. Do not close
 * this handle directly. Pins may outlive the wrapper and retain its custody. */
YDDisk *yd_storage_image_disk(YDStorageImage *image);
bool yd_storage_image_identity(YDStorageImage *image, YDEnvelopeIdentity *out);
/* Ciphertext-only, no-overwrite backup into an existing EMPTY private 0700
 * directory, with file and directory durability. Returns the exact identity
 * needed for restore; no disk tree/canonical-header plaintext export occurs.
 * Pending unpublished transactions do not enter the backup. Failure artifacts
 * are retained and never automatically adopted or removed. */
bool yd_storage_image_backup_at(YDStorageImage *image, int destination,
    YDEnvelopeIdentity *out, char *error, size_t length);
/* Authenticate + native-open the backup using independently trusted identity,
 * then copy its exact ciphertext to an EMPTY destination. No plaintext files.
 * Preserves original store/object/generation: this is deliberate restore, not
 * permission to enroll retention or to override an external rollback anchor. */
bool yd_storage_image_restore_at(int backup, int destination,
    const YDKeyProvider *provider, const char *key_id,
    const YDStorageImageOptions *options, char *error, size_t length);
/* Reencrypt the committed native image with fresh DEK/nonce, preserving exact
 * native bytes and advancing encrypted generation. Old provider remains needed
 * by old backups; target becomes borrowed after durable success. */
bool yd_storage_image_rotate(YDStorageImage *image, const YDKeyProvider *target,
    const char *key_id, char *error, size_t length);
void yd_storage_image_close(YDStorageImage *image);
#endif
