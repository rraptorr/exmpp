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

#include <stdlib.h>
#include <string.h>

#include "exmpp_tls.h"

#if defined(_WIN32)
#define	strcasecmp(s1, s2) _stricmp(s1, s2)
#endif

/*
1024-bit MODP Group with 160-bit prime order subgroup (RFC5114)
-----BEGIN DH PARAMETERS-----
MIIBDAKBgQCxC4+WoIDgHd6S3l6uXVTsUsmfvPsGo8aaap3KUtI7YWBz4oZ1oj0Y
mDjvHi7mUsAT7LSuqQYRIySXXDzUm4O/rMvdfZDEvXCYSI6cIZpzck7/1vrlZEc4
+qMaT/VbzMChUa9fDci0vUW/N982XBpl5oz9p21NpwjfH7K8LkpDcQKBgQCk0cvV
w/00EmdlpELvuZkF+BBN0lisUH/WQGz/FCZtMSZv6h5cQVZLd35pD1UE8hMWAhe0
sBuIal6RVH+eJ0n01/vX07mpLuGQnQ0iY/gKdqaiTAh6CR9THb8KAWm2oorWYqTR
jnOvoy13nVkY0IvIhY9Nzvl8KiSFXm7rIrOy5QICAKA=
-----END DH PARAMETERS-----
 */

unsigned char exmpp_tls_dh1024_p[] = {
        0xB1,0x0B,0x8F,0x96,0xA0,0x80,0xE0,0x1D,0xDE,0x92,0xDE,0x5E,
        0xAE,0x5D,0x54,0xEC,0x52,0xC9,0x9F,0xBC,0xFB,0x06,0xA3,0xC6,
        0x9A,0x6A,0x9D,0xCA,0x52,0xD2,0x3B,0x61,0x60,0x73,0xE2,0x86,
        0x75,0xA2,0x3D,0x18,0x98,0x38,0xEF,0x1E,0x2E,0xE6,0x52,0xC0,
        0x13,0xEC,0xB4,0xAE,0xA9,0x06,0x11,0x23,0x24,0x97,0x5C,0x3C,
        0xD4,0x9B,0x83,0xBF,0xAC,0xCB,0xDD,0x7D,0x90,0xC4,0xBD,0x70,
        0x98,0x48,0x8E,0x9C,0x21,0x9A,0x73,0x72,0x4E,0xFF,0xD6,0xFA,
        0xE5,0x64,0x47,0x38,0xFA,0xA3,0x1A,0x4F,0xF5,0x5B,0xCC,0xC0,
        0xA1,0x51,0xAF,0x5F,0x0D,0xC8,0xB4,0xBD,0x45,0xBF,0x37,0xDF,
        0x36,0x5C,0x1A,0x65,0xE6,0x8C,0xFD,0xA7,0x6D,0x4D,0xA7,0x08,
        0xDF,0x1F,0xB2,0xBC,0x2E,0x4A,0x43,0x71,
};
unsigned int exmpp_tls_dh1024_p_size = sizeof(exmpp_tls_dh1024_p);

unsigned char exmpp_tls_dh1024_g[] = {
        0xA4,0xD1,0xCB,0xD5,0xC3,0xFD,0x34,0x12,0x67,0x65,0xA4,0x42,
        0xEF,0xB9,0x99,0x05,0xF8,0x10,0x4D,0xD2,0x58,0xAC,0x50,0x7F,
        0xD6,0x40,0x6C,0xFF,0x14,0x26,0x6D,0x31,0x26,0x6F,0xEA,0x1E,
        0x5C,0x41,0x56,0x4B,0x77,0x7E,0x69,0x0F,0x55,0x04,0xF2,0x13,
        0x16,0x02,0x17,0xB4,0xB0,0x1B,0x88,0x6A,0x5E,0x91,0x54,0x7F,
        0x9E,0x27,0x49,0xF4,0xD7,0xFB,0xD7,0xD3,0xB9,0xA9,0x2E,0xE1,
        0x90,0x9D,0x0D,0x22,0x63,0xF8,0x0A,0x76,0xA6,0xA2,0x4C,0x08,
        0x7A,0x09,0x1F,0x53,0x1D,0xBF,0x0A,0x01,0x69,0xB6,0xA2,0x8A,
        0xD6,0x62,0xA4,0xD1,0x8E,0x73,0xAF,0xA3,0x2D,0x77,0x9D,0x59,
        0x18,0xD0,0x8B,0xC8,0x85,0x8F,0x4D,0xCE,0xF9,0x7C,0x2A,0x24,
        0x85,0x5E,0x6E,0xEB,0x22,0xB3,0xB2,0xE5,
};
unsigned int exmpp_tls_dh1024_g_size = sizeof(exmpp_tls_dh1024_g);

int
exmpp_tls_init_context(struct exmpp_tls_ctx *ctx)
{
	// nothing to be done currently, but provided
	// for completeness
	return 0;
}

void
exmpp_tls_free_context(struct exmpp_tls_ctx *ctx)
{
	if(ctx->certificate != NULL) {
		driver_free(ctx->certificate);
	}
	if(ctx->private_key != NULL) {
		driver_free(ctx->private_key);
	}
	if(ctx->expected_id != NULL) {
		driver_free(ctx->expected_id);
	}
	if(ctx->trusted_certs != NULL) {
		driver_free(ctx->trusted_certs);
	}
}

int
exmpp_tls_match_hostname(const char *cert_id, const char *expected_id)
{
	size_t cert_id_len;
	char *id;

	cert_id_len = strlen(cert_id);

	if (cert_id_len > 2 && cert_id[0] == '*' && cert_id[1] == '.') {
		/* The certificate contains a pattern like:
		 *     *.example.org
		 * Therefore, we look for the first dot in the expected_id.
		 */
		id = strchr(expected_id, '.');
		if (id == NULL) {
			return 0;
		}

		if (strcasecmp(&cert_id[1], id) == 0) {
			return 1;
		}
	} else {
		/* The certificate requires an exact match. */
		if (strcasecmp(cert_id, expected_id) == 0) {
			return 1;
		}
	}

	return 0;
}

int
exmpp_tls_control(struct exmpp_tls_ctx *ctx, unsigned int command, const char *buf, ErlDrvBinary **b, size_t *size)
{
	int index, type, arity, type_size, flag;
	char atom[MAXATOMLEN];
	ei_x_buff *to_send;

	switch (command) {
	case COMMAND_SET_MODE:
		index = exmpp_skip_version(buf);

		/* Get the mode (client vs. server). */
		ei_decode_long(buf, &index, &ctx->mode);
		break;
	case COMMAND_SET_IDENTITY:
		index = exmpp_skip_version(buf);

		/* Get auth method. */
		ei_decode_tuple_header(buf, &index, &arity);
		ei_decode_atom(buf, &index, atom);
		if (strcmp(atom, "x509") != 0) {
			/* Only X.509 is supported. */
			to_send = exmpp_new_xbuf();
			if (to_send == NULL) {
				return -1;
			}
			ei_x_encode_tuple_header(to_send, 2);
			ei_x_encode_atom(to_send, "unsupported_auth_method");
			ei_x_encode_string(to_send, atom);

			COPY_AND_FREE_BUF(to_send, *size, *b, RET_ERROR);
			break;
		}

		/* Get certificate filename. */
		ei_get_type(buf, &index, &type, &type_size);
		ctx->certificate = driver_alloc(type_size + 1);
		if (ctx->certificate == NULL) {
			return -1;
		}
		ei_decode_string(buf, &index, ctx->certificate);

		/* Get private key filename. */
		ei_get_type(buf, &index, &type, &type_size);
		ctx->private_key = driver_alloc(type_size + 1);
		if (ctx->private_key == NULL) {
			return -1;
		}
		ei_decode_string(buf, &index, ctx->private_key);

		break;
	case COMMAND_SET_PEER_VERIF:
		index = exmpp_skip_version(buf);

		/* Check if the identity of the remote peer must be
		 * verified. */
		ei_get_type(buf, &index, &type, &type_size);
		switch (type) {
		case ERL_ATOM_EXT:
			/* The peer will be checked by TLS library. */
			ei_decode_boolean(buf, &index, &ctx->verify_peer);
			break;
		case ERL_STRING_EXT:
			/* The peer will be checked by TLS library, then
			 * the certificate will be compared to the
			 * given expected identity. */
			ctx->expected_id = driver_alloc(type_size + 1);
			if (ctx->expected_id == NULL) {
				return -1;
			}
			ei_decode_string(buf, &index, ctx->expected_id);
			ctx->verify_peer = 1;
			break;
		}
		break;
	case COMMAND_SET_TRUSTED_CERTS:
		index = exmpp_skip_version(buf);

		/* Get auth method. */
		ei_decode_tuple_header(buf, &index, &arity);
		ei_decode_atom(buf, &index, atom);
		if (strcmp(atom, "x509") != 0) {
			/* Only X.509 is supported by this port driver. */
			to_send = exmpp_new_xbuf();
			if (to_send == NULL) {
				return -1;
			}
			ei_x_encode_tuple_header(to_send, 2);
			ei_x_encode_atom(to_send, "unsupported_auth_method");
			ei_x_encode_string(to_send, atom);

			COPY_AND_FREE_BUF(to_send, *size, *b, RET_ERROR);
			break;
		}

		/* Get the filename for the trusted certificates. */
		ei_get_type(buf, &index, &type, &type_size);
		ctx->trusted_certs = driver_alloc(type_size + 1);
		if (ctx->trusted_certs == NULL) {
			return -1;
		}
		ei_decode_string(buf, &index, ctx->trusted_certs);

		break;
	case COMMAND_SET_OPTIONS:
		index = exmpp_skip_version(buf);

		/* Get auth method. */
		ei_decode_tuple_header(buf, &index, &arity);
		ei_decode_atom(buf, &index, atom);
		ei_decode_boolean(buf, &index, &flag);

		if (strcmp(atom, "peer_cert_required") == 0) {
			ctx->peer_cert_required = flag;
		} else if (strcmp(atom, "accept_expired_cert") == 0) {
			ctx->accept_expired_cert = flag;
		} else if (strcmp(atom, "accept_non_trusted_cert") == 0) {
			ctx->accept_non_trusted_cert = flag;
		} else if (strcmp(atom, "accept_revoked_cert") == 0) {
			ctx->accept_revoked_cert = flag;
		} else if (strcmp(atom, "accept_corrupted_cert") == 0) {
			ctx->accept_corrupted_cert = flag;
		} else {
			to_send = exmpp_new_xbuf();
			if (to_send == NULL) {
				return -1;
			}
			ei_x_encode_tuple_header(to_send, 2);
			ei_x_encode_atom(to_send, "unsupported_option");
			ei_x_encode_atom(to_send, atom);

			COPY_AND_FREE_BUF(to_send, *size, *b, RET_ERROR);
			break;
		}

		break;
	default:
		/* Commad not recognized. */
		to_send = exmpp_new_xbuf();
		if (to_send == NULL) {
			return -1;
		}
		ei_x_encode_tuple_header(to_send, 2);
		ei_x_encode_atom(to_send, "unknown_command");
		ei_x_encode_ulong(to_send, command);

		COPY_AND_FREE_BUF(to_send, *size, *b, RET_ERROR);
		break;
	}

	return 0;
}
