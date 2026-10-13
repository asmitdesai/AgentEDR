/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Engine -> sensor command handling (SPEC 7.2). One plain-text command per
 * line on stdin; every command except PING gets exactly one ACK line.
 */
#ifndef AGENTEDR_PROTOCOL_H
#define AGENTEDR_PROTOCOL_H

struct agentedr_bpf;

/* Handle one command line (without the trailing newline). Writes the reply
 * to stdout. Returns -1 only if stdout failed. */
int protocol_handle_line(struct agentedr_bpf *skel, char *line);

#endif /* AGENTEDR_PROTOCOL_H */
