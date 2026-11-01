#ifndef YAMORA_BINARY_H
#define YAMORA_BINARY_H
#include "snapshot.h"

#define YD_BINARY_INITIALIZING ".yamora-initializing"
#define YD_BINARY_MARKER ".yamora-format"
#define YD_BINARY_VALUE_LIMIT (8u * 1024u * 1024u)
#define YD_BINARY_LARGE_VALUE_LIMIT (32u * 1024u * 1024u)
#define YD_BINARY_LARGE_FILE_LIMIT (YD_BINARY_LARGE_VALUE_LIMIT + YD_LARGE_DOCUMENT_LIMIT + 24u)
#define YD_BINARY_FILE_LIMIT (YD_BINARY_VALUE_LIMIT + YD_DOCUMENT_LIMIT + 24u)
/* -1 invalid namespace; 0 directory backend; 1 binary backend. */
int yd_binary_initializing(const char *root);
int yd_binary_present(const char *root, char *error, size_t length);
bool yd_binary_initialize(const char *root, const YamlDBSnapshot *source,
                          char *error, size_t length);
unsigned char *yd_value_encode(const YDValue *value, size_t *length);
YDValue *yd_value_decode(const unsigned char *bytes, size_t length, size_t source_length);
unsigned char *yd_binary_pack(const unsigned char *source, size_t length,
                              size_t *packed_length, char *error, size_t error_length);
bool yd_binary_unpack(const unsigned char *packed, size_t packed_length,
                       unsigned char **source, size_t *length, YDValue **value);
unsigned char *yd_binary_pack_profile(const unsigned char *source, size_t length, bool large,
    size_t *packed_length, char *error, size_t error_length);
bool yd_binary_unpack_profile(const unsigned char *packed, size_t packed_length, bool large,
    unsigned char **source, size_t *length, YDValue **value);
unsigned char *yd_value_encode_profile(const YDValue *value, size_t *length, bool large);
YDValue *yd_value_decode_profile(const unsigned char *bytes, size_t length, size_t source_length, bool large);
#endif
