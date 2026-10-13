// SPDX-License-Identifier: Apache-2.0
#include "json.h"

#include <stdio.h>
#include <string.h>

static void put(struct jbuf *jb, const char *s, size_t n)
{
    /* Keep 2 bytes spare for the closing "}\n". */
    if (jb->overflow || jb->len + n + 2 > sizeof(jb->buf)) {
        jb->overflow = true;
        return;
    }
    memcpy(jb->buf + jb->len, s, n);
    jb->len += n;
}

static void putc_(struct jbuf *jb, char c) { put(jb, &c, 1); }

/* Length of the valid UTF-8 sequence starting at s (n bytes available),
 * or 0 if invalid. Rejects overlong forms and surrogates (RFC 3629). */
static size_t utf8_len(const unsigned char *s, size_t n)
{
    unsigned char c = s[0];
    unsigned char lo = 0x80, hi = 0xBF;
    size_t need;

    if (c < 0x80)
        return 1;
    if (c >= 0xC2 && c <= 0xDF)
        need = 1;
    else if (c >= 0xE0 && c <= 0xEF) {
        need = 2;
        if (c == 0xE0)
            lo = 0xA0;
        if (c == 0xED)
            hi = 0x9F;
    } else if (c >= 0xF0 && c <= 0xF4) {
        need = 3;
        if (c == 0xF0)
            lo = 0x90;
        if (c == 0xF4)
            hi = 0x8F;
    } else
        return 0;

    if (n < need + 1)
        return 0;
    if (s[1] < lo || s[1] > hi)
        return 0;
    for (size_t i = 2; i <= need; i++)
        if (s[i] < 0x80 || s[i] > 0xBF)
            return 0;
    return need + 1;
}

/* Writes a quoted, escaped JSON string from at most maxlen bytes of s,
 * stopping early at a NUL byte. */
static void put_escaped(struct jbuf *jb, const char *s, size_t maxlen)
{
    const unsigned char *u = (const unsigned char *)s;
    size_t n = strnlen(s, maxlen);
    char esc[8];

    putc_(jb, '"');
    for (size_t i = 0; i < n;) {
        unsigned char c = u[i];
        size_t ulen;

        switch (c) {
        case '"':  put(jb, "\\\"", 2); i++; continue;
        case '\\': put(jb, "\\\\", 2); i++; continue;
        case '\n': put(jb, "\\n", 2);  i++; continue;
        case '\r': put(jb, "\\r", 2);  i++; continue;
        case '\t': put(jb, "\\t", 2);  i++; continue;
        default: break;
        }
        if (c < 0x20 || c == 0x7f) {
            snprintf(esc, sizeof(esc), "\\u%04x", c);
            put(jb, esc, 6);
            i++;
            continue;
        }
        ulen = utf8_len(u + i, n - i);
        if (ulen == 0) {
            /* Invalid UTF-8 byte: emit as its Latin-1 code point. */
            snprintf(esc, sizeof(esc), "\\u%04x", c);
            put(jb, esc, 6);
            i++;
            continue;
        }
        put(jb, s + i, ulen);
        i += ulen;
    }
    putc_(jb, '"');
}

static void key(struct jbuf *jb, const char *k)
{
    if (!jb->first)
        putc_(jb, ',');
    jb->first = false;
    put_escaped(jb, k, strlen(k));
    putc_(jb, ':');
}

void jb_begin(struct jbuf *jb)
{
    jb->len = 0;
    jb->first = true;
    jb->overflow = false;
    putc_(jb, '{');
}

void jb_str(struct jbuf *jb, const char *k, const char *val, size_t maxlen)
{
    key(jb, k);
    put_escaped(jb, val, maxlen);
}

void jb_int(struct jbuf *jb, const char *k, int64_t val)
{
    char num[24];
    int n = snprintf(num, sizeof(num), "%lld", (long long)val);

    key(jb, k);
    put(jb, num, (size_t)n);
}

void jb_bool(struct jbuf *jb, const char *k, bool val)
{
    key(jb, k);
    if (val)
        put(jb, "true", 4);
    else
        put(jb, "false", 5);
}

void jb_null(struct jbuf *jb, const char *k)
{
    key(jb, k);
    put(jb, "null", 4);
}

void jb_str_list(struct jbuf *jb, const char *k, const char *buf, size_t len)
{
    size_t off = 0;
    bool first = true;

    key(jb, k);
    putc_(jb, '[');
    while (off < len) {
        size_t n = strnlen(buf + off, len - off);

        if (!first)
            putc_(jb, ',');
        first = false;
        put_escaped(jb, buf + off, n);
        off += n + 1; /* skip the NUL separator */
    }
    putc_(jb, ']');
}

int jb_end(struct jbuf *jb)
{
    if (jb->overflow) {
        fprintf(stderr, "agentedr-sensor: dropped JSON line over %zu bytes\n",
                sizeof(jb->buf));
        return 0;
    }
    jb->buf[jb->len++] = '}';
    jb->buf[jb->len++] = '\n';
    if (fwrite(jb->buf, 1, jb->len, stdout) != jb->len || fflush(stdout) != 0)
        return -1;
    return 0;
}
