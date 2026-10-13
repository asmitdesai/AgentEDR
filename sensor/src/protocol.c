// SPDX-License-Identifier: Apache-2.0
#include "protocol.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <bpf/libbpf.h>

#include "agentedr.skel.h"
#include "json.h"

#define AGENTEDR_MAP_TYPES_ONLY
#include "maps.h"

static int ack(const char *cmd, bool ok, const char *error)
{
    struct jbuf jb;

    jb_begin(&jb);
    jb_str(&jb, "type", "ACK", 3);
    jb_str(&jb, "cmd", cmd, 64);
    jb_bool(&jb, "ok", ok);
    if (!ok)
        jb_str(&jb, "error", error, 256);
    return jb_end(&jb);
}

/*
 * A deliberately tiny parser for exactly one shape:
 *   [{"basename":"claude","kind":0}, ...]
 * Keys may appear in any order; other keys, nested values and string escapes
 * other than \" \\ \/ are rejected. Anything richer belongs in the engine.
 */
struct cursor { const char *p; };

static void skip_ws(struct cursor *c)
{
    while (isspace((unsigned char)*c->p))
        c->p++;
}

static bool expect(struct cursor *c, char ch)
{
    skip_ws(c);
    if (*c->p != ch)
        return false;
    c->p++;
    return true;
}

/* Parses a JSON string into out (size outsz, always NUL-terminated). */
static bool parse_string(struct cursor *c, char *out, size_t outsz)
{
    size_t n = 0;

    if (!expect(c, '"'))
        return false;
    while (*c->p != '"') {
        char ch = *c->p++;

        if (ch == '\0' || (unsigned char)ch < 0x20)
            return false;
        if (ch == '\\') {
            ch = *c->p++;
            if (ch != '"' && ch != '\\' && ch != '/')
                return false;
        }
        if (n + 1 >= outsz)
            return false;
        out[n++] = ch;
    }
    c->p++;
    out[n] = '\0';
    return true;
}

static bool parse_uint(struct cursor *c, __u32 *out)
{
    char *end;
    unsigned long v;

    skip_ws(c);
    if (!isdigit((unsigned char)*c->p))
        return false;
    v = strtoul(c->p, &end, 10);
    if (v > 0xffffffffUL)
        return false;
    c->p = end;
    *out = (__u32)v;
    return true;
}

static bool parse_matcher(struct cursor *c, struct matcher *m)
{
    bool have_name = false, have_kind = false;
    char k[16];

    memset(m, 0, sizeof(*m));
    if (!expect(c, '{'))
        return false;
    do {
        if (!parse_string(c, k, sizeof(k)) || !expect(c, ':'))
            return false;
        if (strcmp(k, "basename") == 0 && !have_name) {
            /* basename[16] holds at most 15 chars + NUL, like comm. */
            if (!parse_string(c, m->basename, sizeof(m->basename)) ||
                m->basename[0] == '\0')
                return false;
            have_name = true;
        } else if (strcmp(k, "kind") == 0 && !have_kind) {
            if (!parse_uint(c, &m->agent_kind))
                return false;
            have_kind = true;
        } else {
            return false;
        }
    } while (expect(c, ','));
    if (!expect(c, '}'))
        return false;
    m->enabled = 1;
    return have_name && have_kind;
}

static const char *set_matchers(struct agentedr_bpf *skel, const char *json)
{
    struct matcher ms[MAX_MATCHERS];
    struct cursor c = { json };
    __u32 n = 0;

    memset(ms, 0, sizeof(ms));
    if (!expect(&c, '['))
        return "expected JSON array";
    skip_ws(&c);
    if (*c.p != ']') {
        do {
            if (n == MAX_MATCHERS)
                return "too many matchers (max 16)";
            if (!parse_matcher(&c, &ms[n]))
                return "bad matcher object";
            n++;
        } while (expect(&c, ','));
    }
    if (!expect(&c, ']'))
        return "expected ']'";
    skip_ws(&c);
    if (*c.p != '\0')
        return "trailing data";

    /* Write all slots so stale matchers from a previous call are disabled.
     * Not atomic across slots; a racing exec may see a mix for an instant. */
    for (__u32 i = 0; i < MAX_MATCHERS; i++) {
        if (bpf_map__update_elem(skel->maps.agent_matchers, &i, sizeof(i),
                                 &ms[i], sizeof(ms[i]), BPF_ANY) < 0)
            return "map update failed";
    }
    return NULL;
}

int protocol_handle_line(struct agentedr_bpf *skel, char *line)
{
    char *args = line + strcspn(line, " ");
    const char *err;

    if (*args) {
        *args = '\0';
        args++;
    }

    if (strcmp(line, "PING") == 0) {
        struct jbuf jb;

        jb_begin(&jb);
        jb_str(&jb, "type", "PONG", 4);
        return jb_end(&jb);
    }
    if (strcmp(line, "SET_MATCHERS") == 0) {
        err = set_matchers(skel, args);
        return ack(line, err == NULL, err);
    }
    /* Implemented in M1. */
    if (strcmp(line, "SET_PATH_FILTER") == 0 || strcmp(line, "TAG") == 0 ||
        strcmp(line, "UNTAG") == 0)
        return ack(line, false, "not implemented");
    return ack(line, false, "unknown command");
}
