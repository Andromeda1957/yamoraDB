#ifndef YAMORA_QUERY_REGEX_H
#define YAMORA_QUERY_REGEX_H

#include <stdbool.h>
#include <stddef.h>

#define YD_REGEX_PATTERN_LIMIT 4096U

/* A bounded regular-expression dialect compiled to a Thompson NFA. Search
 * advances every alternative in lockstep over the subject, so its time is
 * linear in the subject for a fixed program and never backtracks. Patterns
 * are at most 4096 bytes, 16384 instructions and 1000 counted repetitions;
 * backreferences, lookaround and possessive or atomic groups are rejected. */
typedef struct YDRegex YDRegex;

/* options is NULL or distinct letters from "imsx". *work is debited by the
 * compile cost. Returns NULL with a message for invalid or oversized input,
 * or with *work set to 0 when the allowance ran out. */
YDRegex *yd_regex_compile(const char *pattern, const char *options, size_t *work,
                          char *error, size_t length);
/* Unanchored search of size UTF-8 bytes. Returns 1 on a match, 0 on none and
 * -1 when *work is exhausted or memory is unavailable. */
int yd_regex_search(const YDRegex *regex, const char *subject, size_t size, size_t *work);
void yd_regex_free(YDRegex *regex);

#endif
