#define _GNU_SOURCE
#include "storage_config.h"
#include "storage_image_native.h"
#include "oidc_json.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct YDStorageConfig {
    pid_t process;
    YDKeyProvider *provider;
    YDStorageImage *image;
};
static bool disabled(void) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    if (prior == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(prior, NULL);
    return false;
}
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static unsigned char *read_private(const char *path, size_t *length) {
    *length = 0;
    if (!path || !*path) return NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    struct stat before, named, after;
    bool valid = fd >= 0 && !fstat(fd, &before) && S_ISREG(before.st_mode) &&
        before.st_uid == geteuid() && before.st_nlink == 1 && (before.st_mode & 07777) == 0600 &&
        before.st_size > 0 && before.st_size <= YD_STORAGE_CONFIG_MAX &&
        !lstat(path, &named) && same(&before, &named);
    unsigned char *bytes = valid ? calloc(1, YD_STORAGE_CONFIG_MAX + 1) : NULL;
    size_t at = 0;
    while (bytes && at < (size_t)before.st_size) {
        ssize_t n = read(fd, bytes + at, (size_t)before.st_size - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        at += (size_t)n;
    }
    valid = bytes && at == (size_t)before.st_size && !fstat(fd, &after) && same(&before, &after) &&
        !lstat(path, &named) && same(&after, &named);
    if (fd >= 0) close(fd);
    if (valid) { *length = at; return bytes; }
    if (bytes) { OPENSSL_cleanse(bytes, YD_STORAGE_CONFIG_MAX + 1); free(bytes); }
    return NULL;
}
static bool fields(const YDOIDCJSONNode *node, const char *const *names, size_t count) {
    if (!node || node->type != YD_OIDC_JSON_OBJECT || node->count != count) return false;
    for (size_t i = 0; i < count; i++) if (!yd_oidc_json_get(node, names[i])) return false;
    return true;
}
static const char *string(const YDOIDCJSONNode *node, const char *name, size_t maximum) {
    const YDOIDCJSONNode *value = yd_oidc_json_get(node, name);
    return value && value->type == YD_OIDC_JSON_STRING && value->length &&
        value->length <= maximum ? value->text : NULL;
}
static bool integer(const YDOIDCJSONNode *node, const char *name, uint64_t *out) {
    *out = 0;
    const YDOIDCJSONNode *value = yd_oidc_json_get(node, name);
    if (!value || value->type != YD_OIDC_JSON_NUMBER || !value->length || value->length > 20) return false;
    uint64_t number = 0;
    for (size_t i = 0; i < value->length; i++) {
        unsigned char c = (unsigned char)value->text[i];
        if (c < '0' || c > '9' || number > (UINT64_MAX - (c - '0')) / 10) return false;
        number = number * 10 + c - '0';
    }
    *out = number;
    return true;
}
static bool hex(const char *text, unsigned char *out, size_t size) {
    if (!text || strlen(text) != size * 2) return false;
    for (size_t i = 0; i < size * 2; i++) {
        unsigned char c = (unsigned char)text[i];
        unsigned n;
        if (c >= '0' && c <= '9') n = c - '0';
        else if (c >= 'a' && c <= 'f') n = c - 'a' + 10;
        else return false;
        if (!(i & 1)) out[i / 2] = (unsigned char)(n << 4);
        else out[i / 2] |= (unsigned char)n;
    }
    return true;
}
static YDKeyProvider *local(const YDOIDCJSONNode *node, const char *key_id) {
    static const char *const provider_fields[] = {"type", "keys"};
    static const char *const key_fields[] = {"id", "key_hex"};
    const YDOIDCJSONNode *array = yd_oidc_json_get(node, "keys");
    if (!fields(node, provider_fields, 2) || !array || array->type != YD_OIDC_JSON_ARRAY ||
        !array->count || array->count > YD_KEY_RING_MAX) return NULL;
    YDKeyEntry entries[YD_KEY_RING_MAX] = {0};
    bool valid = true;
    bool selected = false;
    size_t count = 0;
    for (const YDOIDCJSONNode *key = array->first; key && valid; key = key->next) {
        valid = count < array->count && fields(key, key_fields, 2);
        if (!valid) break;
        entries[count].id = string(key, "id", YD_KEY_ID_MAX);
        valid = entries[count].id && hex(string(key, "key_hex", 64), entries[count].bytes, 32);
        if (valid && !strcmp(entries[count].id, key_id)) selected = true;
        count++;
    }
    YDKeyProvider *result = valid && selected && count == array->count ? yd_key_provider_local(entries, count) : NULL;
    OPENSSL_cleanse(entries, sizeof(entries));
    return result;
}
static YDKeyProvider *provider(const YDOIDCJSONNode *node, const char *key_id,
    YDKeyHTTP http, void *context) {
    const char *type = string(node, "type", 32);
    if (!type) return NULL;
    if (!strcmp(type, "local")) return local(node, key_id);
    if (!http) return NULL;
    if (!strcmp(type, "aws-kms")) {
        static const char *const names[] = {"type", "key_arn"};
        const char *arn = string(node, "key_arn", YD_KEY_ID_MAX);
        return fields(node, names, 2) && arn && !strcmp(arn, key_id) ?
            yd_key_provider_aws(arn, http, context) : NULL;
    }
    if (!strcmp(type, "vault-transit")) {
        static const char *const names[] = {"type", "mount", "name", "write_version"};
        const char *mount = string(node, "mount", 128), *name = string(node, "name", 128);
        uint64_t version;
        return fields(node, names, 4) && mount && name && !strcmp(name, key_id) &&
            integer(node, "write_version", &version) && version && version <= UINT32_MAX ?
            yd_key_provider_vault(mount, name, (uint32_t)version, http, context) : NULL;
    }
    return NULL;
}
static void dispose(void *context) {
    YDStorageConfig *config = context;
    yd_key_provider_free(config->provider);
    OPENSSL_cleanse(config, sizeof(*config));
    free(config);
}
YDStorageConfig *yd_storage_config_open_with_http(const char *path, const char *data_dir,
    YDKeyHTTP http, void *http_context, char *error, size_t length) {
    if (!disabled()) goto rejected;
    size_t size = 0;
    unsigned char *bytes = read_private(path, &size);
    YDOIDCJSON *json = NULL;
    bool valid = bytes && yd_oidc_json_parse(bytes, size, 256, &json) == YD_OIDC_JSON_OK;
    if (bytes) { OPENSSL_cleanse(bytes, YD_STORAGE_CONFIG_MAX + 1); free(bytes); }
    const YDOIDCJSONNode *root = yd_oidc_json_root(json);
    static const char *const names[] = {"version", "mode", "store_id", "object_id", "generation",
        "maximum_bytes", "cache_bytes", "key_id", "provider"};
    YDStorageImageOptions options = {.expected = {.kind = YD_STORAGE_IMAGE_KIND}};
    uint64_t version = 0, cache = 0;
    const char *mode = string(root, "mode", 8), *key_id = string(root, "key_id", YD_KEY_ID_MAX);
    valid = valid && fields(root, names, 9) && integer(root, "version", &version) && version == 1 &&
        mode && (!strcmp(mode, "create") || !strcmp(mode, "open")) && key_id &&
        hex(string(root, "store_id", 32), options.expected.store_id, 16) &&
        hex(string(root, "object_id", 64), options.expected.object_id, 32) &&
        integer(root, "generation", &options.expected.generation) && options.expected.generation &&
        integer(root, "maximum_bytes", &options.maximum_bytes) &&
        integer(root, "cache_bytes", &cache) && cache <= SIZE_MAX;
    options.initialize = mode && !strcmp(mode, "create");
    options.cache_bytes = (size_t)cache;
    YDStorageConfig *config = valid ? calloc(1, sizeof(*config)) : NULL;
    if (config) {
        config->process = getpid();
        config->provider = provider(yd_oidc_json_get(root, "provider"), key_id, http, http_context);
        int directory = config->provider && data_dir ?
            open(data_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
        config->image = directory >= 0 ? yd_storage_image_open_at(directory, config->provider,
            key_id, &options, error, length) : NULL;
        if (directory >= 0) close(directory);
    }
    yd_oidc_json_free(json);
    OPENSSL_cleanse(&options, sizeof(options));
    if (config && config->image && yd_storage_image_on_last_close(config->image, dispose, config)) return config;
    if (config) { yd_storage_image_close(config->image); dispose(config); }
rejected:
    if (error && length) snprintf(error, length, "encrypted-storage configuration or native opening rejected");
    return NULL;
}
YDStorageConfig *yd_storage_config_open(const char *path, const char *data_dir, char *error, size_t length) {
    return yd_storage_config_open_with_http(path, data_dir, NULL, NULL, error, length);
}
YDDisk *yd_storage_config_disk(YDStorageConfig *config) {
    return config && config->process == getpid() ? yd_storage_image_disk(config->image) : NULL;
}
bool yd_storage_config_identity(YDStorageConfig *config, YDEnvelopeIdentity *out) {
    if (out) memset(out, 0, sizeof(*out));
    return config && config->process == getpid() && yd_storage_image_identity(config->image, out);
}
void yd_storage_config_close(YDStorageConfig *config) {
    if (!config || config->process != getpid() || !disabled()) return;
    YDStorageImage *image = config->image;
    config->image = NULL;
    yd_storage_image_close(image); /* Final native-pin release disposes config. */
}
