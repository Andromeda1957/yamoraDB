#ifndef YAMORA_SECURITY_FIELD_POLICY_H
#define YAMORA_SECURITY_FIELD_POLICY_H

#include "../value.h"

typedef struct YDFieldPolicy YDFieldPolicy;

/* Owns a validated clone of an array of at most 64 rules:
 * {collection: name, documents: ["*", "exact-id", "prefix-*"],
 *  read: ["*", "profile.name"], write: ["counter"]}.
 * Each list has at most 64 entries. A field grants its entire subtree; only
 * "*" grants the root. Rules union within this one already-selected principal.
 * No identity selection, role union, file I/O, or source rewriting occurs here.
 * Empty policies and NULL handles grant nothing. Error text contains no data. */
YDFieldPolicy *yd_field_policy_new(const YDValue *rules, char *error, size_t length);
void yd_field_policy_free(YDFieldPolicy *policy);

/* id == NULL means collection-wide: ONLY a literal documents "*" matches.
 * path == "" means the complete document, including exact authored YAML.
 * Otherwise path is a bounded dotted path. Unknown collections/IDs/paths deny.
 * Full replacement, creation and deletion MUST check write at path ""; checking
 * only fields present in the submitted replacement would erase hidden fields.
 * Check collection grants separately; a mask never creates a collection grant. */
bool yd_field_policy_allows(const YDFieldPolicy *policy, const char *collection,
                            const char *id, const char *path, bool write);

/* Checks every operation before mutation. Read/modify/write operators ($inc,
 * $mul, $min, $max, $push, $addToSet, $pull) require read AND write authority;
 * $set, $unset and $setOnInsert require write. $rename requires read and write
 * over its source and write over its destination. id == NULL checks a filter
 * update collection-wide, so only documents "*" rules apply. Numeric path
 * segments require authority over their parent array, preventing index shifts
 * from modifying protected siblings.
 * The native patch engine remains responsible for validation/application and
 * preserving exact YAML. No document or request bytes are changed here. */
bool yd_field_policy_patch(const YDFieldPolicy *policy, const char *collection,
                           const char *id, const YDValue *operations,
                           char *error, size_t length);

/* Validates with the native query planner, then checks every filter, sort and
 * projection dependency regardless of data/filter outcome. A dotted filter path
 * can fan out over sequence elements, so it also requires read over its first
 * segment plus any canonical indexes directly after it. No projection means
 * full read. Explain requires full collection read. Existence, IDs and counts
 * are disclosed by an authorized query. Native revision/ETag hashes include
 * hidden source: caller MUST suppress them via field_response and reject
 * global revision preconditions/pagination for masked principals;
 * callers MUST restrict the scan to id when non-NULL (never a whole collection).
 * Collection queries require an unrestricted document selector. Exact-ID
 * queries reject pagination anchors naming another document. */
bool yd_field_policy_query(const YDFieldPolicy *policy, const char *collection,
                           const char *id, const YDValue *spec, const char *revision,
                           char *error, size_t length);

/* Existing aggregation/search APIs expose materialized rows, index metadata,
 * counts or scores. Until field-aware output exists they require full read of
 * ALL source/foreign documents. Aggregation validates the whole native pipeline
 * and every lookup even when input is empty. Search validation/application still
 * belongs to its native engine; this is its mandatory authorization precheck. */
bool yd_field_policy_aggregate(const YDFieldPolicy *policy, const char *collection,
                               const YDValue *pipeline, char *error, size_t length);
bool yd_field_policy_search(const YDFieldPolicy *policy, const char *collection);

/* Feeds, exports, backups and outbound replication expose whole documents or
 * exact source: require full collection read. Incoming replication/restore
 * requires full collection write. Global/raw WAL/archive replication contains
 * other collections and is never authorized by these collection helpers;
 * retain its separate administrator-only gate. */
bool yd_field_policy_stream(const YDFieldPolicy *policy, const char *collection, bool write);

#endif
