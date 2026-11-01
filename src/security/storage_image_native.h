#ifndef YAMORA_SECURITY_STORAGE_IMAGE_NATIVE_H
#define YAMORA_SECURITY_STORAGE_IMAGE_NATIVE_H
#include "../disk.h"

/* Private native adoption contract. The security owner supplies an anonymous,
 * full-extent locked file; native duplicates it and takes one retained context.
 * Native pins inherit one reference; close releases AFTER closing their fd.
 * Every callback runs with cancellation disabled, returns normally and preserves
 * cancellation state. publish runs under native writer custody, outside root
 * lock, after the new superblock is complete and synced, before view/receipt
 * publication. A false result fences the native writer, including uncertainty.
 * Context owns memory/file/namespace/provider custody through final release.
 * Retain must reject foreign PID and refcount exhaustion without mutation. */
typedef struct {
    void *context;
    bool (*publish)(void *, int borrowed_fd, const YDDiskView *, char *, size_t);
    bool (*retain)(void *);
    void (*release)(void *);
} YDDiskImagePersistence;
/* No pathname opens, physical exports or schema/retention/cluster admission.
 * fd is a regular anonymous nlink-zero file, exactly allocation_limit bytes;
 * limit is 8192..64 MiB, page aligned. authenticated_length is the exact prior
 * authenticated plaintext length (zero only for initialize), NOT fd capacity.
 * Decode existing headers against that length. Existing headers MUST be unfenced profile
 * 5. Fresh creation writes native generation1 then calls durable publication
 * before exposing a handle. Only the trusted security module may call this. */
YDDisk *yd_disk_open_image_fd(int borrowed_fd, bool initialize,
    size_t cache_bytes, uint64_t allocation_limit, uint64_t authenticated_length,
    const YDDiskImagePersistence *, char *error, size_t length);
struct YDStorageImage;
/* Config-owner bridge, installed exactly once before exposing any handle.
 * Transfers cleanup ownership only on success; finalizer runs normally with
 * cancellation disabled AFTER actual last native pin and image cleanup. */
bool yd_storage_image_on_last_close(struct YDStorageImage *, void (*finalizer)(void *), void *);
#endif
