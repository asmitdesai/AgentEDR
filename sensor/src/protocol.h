/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Engine -> sensor command handling (SPEC 7.2). One plain-text command per
 * line on stdin; every command except PING gets exactly one ACK line.
 */
#ifndef AGENTEDR_PROTOCOL_H
#define AGENTEDR_PROTOCOL_H

/*
 * Protocol version reported in READY (ADR 0014). Increment it on any change
 * to event fields, event semantics, control lines or commands, and update
 * SUPPORTED_PROTOCOL in src/agentedr/supervisor.py to match (a test checks
 * that the two agree).
 *   1: M0 plus group-exit-aware EXIT (ADR 0001).
 */
#define AGENTEDR_PROTOCOL 1

struct agentedr_bpf;

/* Handle one command line (without the trailing newline). Writes the reply
 * to stdout. Returns -1 only if stdout failed. */
int protocol_handle_line(struct agentedr_bpf *skel, char *line);

#endif /* AGENTEDR_PROTOCOL_H */
