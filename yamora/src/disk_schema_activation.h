#ifndef YAMORA_DISK_SCHEMA_ACTIVATION_H
#define YAMORA_DISK_SCHEMA_ACTIVATION_H
#include "disk_schema_barrier.h"

#define YD_SCHEMA_ACTIVATED_MARKER ".yamora-schema-activated"
/* Required application validator, invoked once before ANY valid destination
 * header exists. Reader/view are borrowed, private and read-only, with bounded
 * cache. Validate the COMPLETE selected catalog, every governed document and
 * internal receipt framing, using one caller-owned policy work pool. The shared
 * physical remaining_work counter never increases/refills; callback accounting
 * must also be bounded. No mutation, export, close, descriptor retention,
 * recursive activation, cancellation-state change or nonlocal exit is allowed.
 * A normal OK return reports validation only, not publication authority. */
typedef YDSchemaBarrierResult (*YDDiskSchemaActivationValidator)(void *context,
    YDDisk *reader, const YDDiskView *selected, uint64_t *remaining_work,
    char *error, size_t error_size);

/* Explicit OFFLINE standalone conversion into a NEW separated destination.
 * Preserves the original full native extent, both physical views, exact YAML,
 * internal keys and receipts; never copies directory/session/Raft authority.
 * Source must be a two-valid-slot, unfenced profile-5 standalone root with no
 * other directory entries. Destination must be empty, euid-owned 0700. Reuses
 * prepare_at's debit, O_EXCL, disabled-cancellation, EX exclusion and identity
 * contracts. Requires validator != NULL and successful complete validation.
 * Both invalid destination headers receive durable schema markers BEFORE any
 * valid profile-7 prefix. After validation, exact reread/rebinding and both
 * synced profile-7 headers, the preparing marker is renamed without replacing
 * anything into the permanent custody marker; it grants no opening authority.
 * Preparing candidates refuse schema-aware open. No in-place conversion,
 * automatic retry/adoption, truncation or deletion. Failed/uncertain objects
 * remain preserved; a failure after publication can leave an unacknowledged
 * but fully validated destination. Outputs clear on failure; errno preserved. */
YDSchemaBarrierResult yd_disk_schema_activate_at(int source_directory,
    int destination_directory, uint64_t maximum_bytes, uint64_t *remaining_work,
    YDDiskSchemaActivationValidator validator, void *context,
    YDSchemaBarrierPrepared *out, char *error, size_t error_size);
#endif
