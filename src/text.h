#ifndef YAMORA_TEXT_H
#define YAMORA_TEXT_H
#include "value.h"
#define YD_TEXT_TERM_BYTES 256U
#define YD_TEXT_DOCUMENT_TERMS 8192U
#define YD_TEXT_QUERY_TERMS 32U
typedef struct {
    char **terms;
    size_t count, limit, slot_count, oversized;
    size_t *slots;
} YDText;
/* Unicode 17.0 L/M/N words, default full case folding, no normalization or
 * language-specific segmentation. Oversized whole words are not indexed. */
YDText *yd_text_new(size_t limit);
bool yd_text_add(YDText *text, const unsigned char *source, size_t size, char *error,
                 size_t length);
bool yd_text_value(YDText *text, const YDValue *value, char *error, size_t length);
void yd_text_finish(YDText *text);
void yd_text_free(YDText *text);
/* Simple (one code point) default case folding from the same Unicode table;
 * code points with only multi-character folding map to themselves. */
uint32_t yd_text_fold_simple(uint32_t code);
/* The folding table is ascending by source code point. Seek returns the first
 * entry at or after code; an entry without simple folding reports itself. */
size_t yd_text_fold_seek(uint32_t code);
bool yd_text_fold_entry(size_t index, uint32_t *code, uint32_t *folded);
#ifdef YD_TEXT_TEST_COUNTS
size_t yd_text_test_allocations(void);
#endif
#endif
