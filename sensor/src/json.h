/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Minimal JSON line writer. Builds one object in a fixed buffer, then writes
 * it to stdout followed by '\n' and flushes. No JSON library by design.
 *
 * Strings from the kernel are arbitrary bytes. Output is always valid JSON
 * and valid UTF-8: '"', '\\' and control characters are escaped, valid UTF-8
 * sequences pass through, and each byte of an invalid sequence is written as
 * \u00XX (its Latin-1 code point). That last case is lossy but never breaks
 * the engine's parser.
 */
#ifndef AGENTEDR_JSON_H
#define AGENTEDR_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JSON_BUF_SIZE 16384

struct jbuf {
    char   buf[JSON_BUF_SIZE];
    size_t len;
    bool   first;     /* no field written yet: no leading comma */
    bool   overflow;  /* line too long; jb_end drops it */
};

void jb_begin(struct jbuf *jb);
void jb_str(struct jbuf *jb, const char *key, const char *val, size_t maxlen);
void jb_int(struct jbuf *jb, const char *key, int64_t val);
void jb_bool(struct jbuf *jb, const char *key, bool val);
void jb_null(struct jbuf *jb, const char *key);
/* Writes a JSON array of strings from a buffer of NUL-separated strings. */
void jb_str_list(struct jbuf *jb, const char *key, const char *buf, size_t len);
/* Finishes the object and writes the line. Returns -1 if stdout failed. */
int jb_end(struct jbuf *jb);

#endif /* AGENTEDR_JSON_H */
