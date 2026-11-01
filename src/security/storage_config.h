#ifndef YAMORA_SECURITY_STORAGE_CONFIG_H
#define YAMORA_SECURITY_STORAGE_CONFIG_H
#include "storage_image.h"

#define YD_STORAGE_CONFIG_MAX 16384U
typedef struct YDStorageConfig YDStorageConfig;
/* Strict private JSON, regular current-UID 0600 single-link file, no final
 * symlink, bounded to 16 KiB with stable opened/named metadata. Operator trusts
 * its parent directory/path and exact expected identity independently of the
 * encrypted data. data_dir already exists, private0700; config stays OUTSIDE it.
 * Exact version1 fields: version,mode("create"|"open"),store_id(32 lowerhex),
 * object_id(64 lowerhex),generation,maximum_bytes,cache_bytes,key_id,provider.
 * No defaults, unknown/duplicate fields, coercions, fractional/exponent numbers,
 * mutable provider aliases, partial keyring acceptance or plaintext fallback.
 * Local provider: {type:"local",keys:[{id,key_hex:64 lowerhex}]}, 1..16 keys.
 * This default constructor refuses remote providers without a trusted transport.
 * Cancellation must already be disabled through all calls/adoption/cleanup.
 * Provider and config survive until the image's ACTUAL last native pin close;
 * close invalidates the caller's config, without revoking owned read pins. */
YDStorageConfig *yd_storage_config_open(const char *path, const char *data_dir,
    char *error, size_t length);
/* AWS provider: {type:"aws-kms",key_arn:immutable-full-ARN}; key_id==ARN.
 * Vault: {type:"vault-transit",mount,name,write_version:positive}; key_id==name.
 * http MUST meet key_provider.h's TLS/auth/deadline/read-cap contract and remain
 * alive through last native pin. No credentials are read from JSON or acquired
 * here. A NULL callback refuses these modes before native directory mutation.
 * Existing adapter fixture qualification is not live-provider interoperability. */
YDStorageConfig *yd_storage_config_open_with_http(const char *path, const char *data_dir,
    YDKeyHTTP http, void *http_context, char *error, size_t length);
YDDisk *yd_storage_config_disk(YDStorageConfig *config);
bool yd_storage_config_identity(YDStorageConfig *config, YDEnvelopeIdentity *out);
void yd_storage_config_close(YDStorageConfig *config);
#endif
