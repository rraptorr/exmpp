/*
 * Copyright ProcessOne 2006-2010. All Rights Reserved.
 *
 * The contents of this file are subject to the Erlang Public License,
 * Version 1.1, (the "License"); you may not use this file except in
 * compliance with the License. You should have received a copy of the
 * Erlang Public License along with this software. If not, it can be
 * retrieved online at http://www.erlang.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 */

#ifndef EXMPP_TLS_H
#define	EXMPP_TLS_H 1

#include "exmpp_driver.h"

/* Control operations. */
enum {
	COMMAND_SET_MODE = 1,
	COMMAND_SET_IDENTITY,
	COMMAND_SET_PEER_VERIF,
	COMMAND_SET_TRUSTED_CERTS,
	COMMAND_SET_OPTIONS,
	COMMAND_PREPARE_HANDSHAKE,
	COMMAND_HANDSHAKE,
	COMMAND_SET_ENCRYPTED_INPUT,
	COMMAND_GET_DECRYPTED_INPUT,
	COMMAND_SET_DECRYPTED_OUTPUT,
	COMMAND_GET_ENCRYPTED_OUTPUT,
	COMMAND_GET_PEER_CERTIFICATE,
	COMMAND_GET_VERIFY_RESULT,
	COMMAND_SHUTDOWN,
	COMMAND_QUIET_SHUTDOWN,
	COMMAND_PORT_REVISION,
	COMMAND_GET_PEER_FINISHED,
	COMMAND_GET_FINISHED
};

/* Mode. */
enum {
	TLS_MODE_UNKNOWN = 0,
	TLS_MODE_SERVER,
	TLS_MODE_CLIENT
};

/* Return codes. */
enum {
	RET_OK = 0,
	RET_ERROR,
	RET_WANT_READ,
	RET_WANT_WRITE
};

struct exmpp_tls_ctx {
	long		 mode;

	/* Identity. */
	char		*certificate;
	char		*private_key;

	/* Peer verification. */
	int		 verify_peer;
	char		*expected_id;

	/* Options. */
	char		*trusted_certs;
	int		 peer_cert_required;
	int		 accept_expired_cert;
	int		 accept_revoked_cert;
	int		 accept_non_trusted_cert;
	int		 accept_corrupted_cert;
};

extern unsigned char exmpp_tls_dh1024_p[];
extern unsigned int exmpp_tls_dh1024_p_size;
extern unsigned char exmpp_tls_dh1024_g[];
extern unsigned int exmpp_tls_dh1024_g_size;

int     exmpp_tls_init_context(struct exmpp_tls_ctx *ctx);
void    exmpp_tls_free_context(struct exmpp_tls_ctx *ctx);
int	exmpp_tls_match_hostname(const char *cert_id, const char *expected_id);
int     exmpp_tls_control(struct exmpp_tls_ctx *ctx, unsigned int command, const char *buf, ErlDrvBinary **b, size_t *size);

#endif /* !defined(EXMPP_TLS_H) */
