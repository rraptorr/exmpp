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

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "exmpp_tls.h"

#define	DRIVER_NAME	exmpp_tls_openssl
#define CIPHERS         "DEFAULT:!EXPORT:!LOW:!SSLv2"

#define	BUF_SIZE	1024

/* Driver data. */
struct exmpp_tls_openssl_data {
	struct exmpp_tls_ctx ctx;

	SSL_CTX		*ssl_ctx;
	SSL		*ssl;
	BIO		*bio_read;
	BIO		*bio_write;
};

static int	init_library(struct exmpp_tls_openssl_data *edd,
		    ei_x_buff **to_send, size_t *size, ErlDrvBinary **b);
static int	verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

static int	ssl_ex_index;

#ifndef OPENSSL_NO_DH
static DH *dh1024;
#endif

/*
 * ECDHE is enabled only on OpenSSL 1.0.0e and later.
 * See http://www.openssl.org/news/secadv_20110906.txt
 * for details.
 */
#if OPENSSL_VERSION_NUMBER >= 0x1000005fL && !defined(OPENSSL_NO_ECDH)
static EC_KEY *ecdh;
#endif

/* -------------------------------------------------------------------
 * Erlang port driver callbacks.
 * ------------------------------------------------------------------- */

static ErlDrvData
exmpp_tls_openssl_start(ErlDrvPort port, char *command)
{
	struct exmpp_tls_openssl_data *edd;

	/* Set binary mode. */
	set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);

	/* Allocate driver data structure. */
	edd = driver_alloc(sizeof(*edd));
	if (edd == NULL)
		return (NULL);

	memset(edd, 0, sizeof(*edd));

	if (exmpp_tls_init_context(&edd->ctx) != 0) {
		driver_free(edd);
		return NULL;
	}

	return (ErlDrvData)edd;
}

static void
exmpp_tls_openssl_stop(ErlDrvData drv_data)
{
	struct exmpp_tls_openssl_data *edd;

	edd = (struct exmpp_tls_openssl_data *)drv_data;

	if (edd->ssl != NULL)
		SSL_free(edd->ssl);
	if (edd->ssl_ctx != NULL)
		SSL_CTX_free(edd->ssl_ctx);
	exmpp_tls_free_context(&edd->ctx);

	driver_free(edd);
}

static int
exmpp_tls_openssl_control(ErlDrvData drv_data, unsigned int command,
    char *buf, int len, char **rbuf, int rlen)
{
	struct exmpp_tls_openssl_data *edd;
	int ret, index, type;
	size_t size;
	long verify_result;
	unsigned long data_len;
	unsigned char *out;
	ErlDrvBinary *b;
	ei_x_buff *to_send;
	X509 *cert;

	edd = (struct exmpp_tls_openssl_data *)drv_data;

	size = 0;
	b = NULL;

	/*
	 * We never check return codes against SSL_ERROR_WANT_WRITE because
	 * writes to BIO_mem() always succeed and OpenSSL can't tell if
	 * the data was effectively written to the socket.
	 */

	switch (command) {
	case COMMAND_PREPARE_HANDSHAKE:
		ret = init_library(edd, &to_send, &size, &b);
		if (ret != 0) {
			/* Initialization failed. */
			break;
		}

		break;
	case COMMAND_HANDSHAKE:
		/* Try handshake. */
		ret = SSL_do_handshake(edd->ssl);
		if (ret <= 0) {
			switch (SSL_get_error(edd->ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				/* OpenSSL is waiting for more data. */
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_READ;

				break;
			default:
				/* An error occured. */
				ret = ERR_get_error();

				to_send = exmpp_new_xbuf();
				if (to_send == NULL)
					return (-1);
				ei_x_encode_tuple_header(to_send, 2);
				ei_x_encode_long(to_send, ret);
				ei_x_encode_string(to_send,
				    ERR_error_string(ret, NULL));

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
			}
		}

		break;
	case COMMAND_SET_ENCRYPTED_INPUT:
		BIO_write(edd->bio_read, buf, len);

		break;
	case COMMAND_GET_DECRYPTED_INPUT:
		index = exmpp_skip_version(buf);

		/* Get data length the caller is waiting for. */
		ei_decode_ulong(buf, &index, &data_len);
		if (data_len == 0)
			data_len = BUF_SIZE;

		/* Allocate binary to copy decrypted data. */
		rlen = data_len + 1;
		size = 1;
		b = driver_alloc_binary(rlen);
		b->orig_bytes[0] = RET_OK;

		/* Copy data. */
		ret = SSL_read(edd->ssl, b->orig_bytes + size, data_len);

		/* Check for errors. */
		if (ret > 0) {
			size += ret;
			b = driver_realloc_binary(b, size);
		} else {
			driver_free_binary(b);
			b = NULL;

			switch (SSL_get_error(edd->ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				/* OpenSSL is waiting for more data. */
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_READ;

				break;
			default:
				/* An error occured. */
				to_send = exmpp_new_xbuf();
				if (to_send == NULL)
					return (-1);
				ei_x_encode_atom(to_send, "decrypt_failed");

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
			}
		}

		break;
	case COMMAND_SET_DECRYPTED_OUTPUT:
		ret = SSL_write(edd->ssl, buf, len);
		if (ret <= 0) {
			switch (SSL_get_error(edd->ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				/* OpenSSL is waiting for more data. */
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_READ;

				break;
			default:
				/* An error occured. */
				to_send = exmpp_new_xbuf();
				if (to_send == NULL)
					return (-1);
				ei_x_encode_atom(to_send, "encrypt_failed");

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
			}
		}

		break;
	case COMMAND_GET_ENCRYPTED_OUTPUT:
		/* Allocate binary to copy encrypted data. */
		size = BIO_ctrl_pending(edd->bio_write) + 1;
		b = driver_alloc_binary(size);
		b->orig_bytes[0] = RET_OK;

		BIO_read(edd->bio_write, b->orig_bytes + 1, size - 1);

		break;
	case COMMAND_GET_PEER_CERTIFICATE:
		/* Get the peer certificate. */
		cert = SSL_get_peer_certificate(edd->ssl);
		if (cert == NULL || (rlen = i2d_X509(cert, NULL)) < 0) {
			to_send = exmpp_new_xbuf();
			if (to_send == NULL)
				return (-1);
			ei_x_encode_atom(to_send, "no_certificate");

			COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
			if (cert != NULL) {
				X509_free(cert);
			}
			break;
		}

		/* Copy it to a binary. */
		size = rlen + 1;
		b = driver_alloc_binary(size);
		b->orig_bytes[0] = RET_OK;
		out = (unsigned char *)&(b->orig_bytes[1]);
		i2d_X509(cert, &out);
		X509_free(cert);

		break;
	case COMMAND_GET_VERIFY_RESULT:
		verify_result = SSL_get_verify_result(edd->ssl);

		to_send = exmpp_new_xbuf();
		if (to_send == NULL)
			return (-1);
		ei_x_encode_long(to_send, verify_result);

		COPY_AND_FREE_BUF(to_send, size, b, RET_OK);

		break;
	case COMMAND_SHUTDOWN:
		type = SSL_get_shutdown(edd->ssl);
		ret = SSL_shutdown(edd->ssl);
		if (ret == 1) {
			/* The shutdown is complete but if the peer
			 * initiated it, the output buffer contains
			 * our "close notify". */
			if (!(type & SSL_SENT_SHUTDOWN)) {
				/* Our "close notify" must be sent now. */
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_WRITE;
			}

			break;
		} else if (ret == 0) {
			/* We are waiting for the peer "close notify" */
			if (!(type & SSL_SENT_SHUTDOWN)) {
				/* Our "close notify" must be sent now. */
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_WRITE;
			} else {
				/* Ouf "close notify" was already sent. */
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_READ;
			}

			break;
		} else if (ret < 0) {
			switch (SSL_get_error(edd->ssl, ret)) {
			case SSL_ERROR_WANT_READ:
				/* OpenSSL is waiting for more data. */
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_READ;

				break;
			default:
				/* An error occured. */
				ret = ERR_get_error();

				to_send = exmpp_new_xbuf();
				if (to_send == NULL)
					return (-1);
				ei_x_encode_tuple_header(to_send, 2);
				ei_x_encode_long(to_send, ret);
				ei_x_encode_string(to_send,
				    ERR_error_string(ret, NULL));

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
			}
		}

		break;
	case COMMAND_QUIET_SHUTDOWN:
		SSL_set_shutdown(edd->ssl,
		    SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

		break;
	case COMMAND_PORT_REVISION:
		/* Store the revision in the buffer. */
		to_send = exmpp_new_xbuf();
		if (to_send == NULL)
			return (-1);
		ei_x_encode_string(to_send, "$Revision$");

		COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);

		break;
	case COMMAND_GET_PEER_FINISHED:
		size = BUF_SIZE + 1;
		b = driver_alloc_binary(size);
		b->orig_bytes[0] = RET_OK;
		ret = SSL_get_peer_finished(edd->ssl, &(b->orig_bytes[1]), BUF_SIZE);
		size = ret + 1;
		b = driver_realloc_binary(b, size);
		break;
	case COMMAND_GET_FINISHED:
		size = BUF_SIZE + 1;
		b = driver_alloc_binary(size);
		b->orig_bytes[0] = RET_OK;
		ret = SSL_get_finished(edd->ssl, &(b->orig_bytes[1]), BUF_SIZE);
		size = ret + 1;
		b = driver_realloc_binary(b, size);
		break;
	default:
		if (exmpp_tls_control(&edd->ctx, command, buf, &b, &size) < 0) {
			return -1;
		}
	}

	if (b == NULL) {
		size = 1;
		b = driver_alloc_binary(size);
		b->orig_bytes[0] = RET_OK;
	}

	*rbuf = (char *)b;

	return (size);
}

/* -------------------------------------------------------------------
 * Internal functions.
 * ------------------------------------------------------------------- */

static int
init_library(struct exmpp_tls_openssl_data *edd,
    ei_x_buff **to_send, size_t *size, ErlDrvBinary **b)
{
	int ret, verify;

	/* Create an SSL context. */
	edd->ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (edd->ssl_ctx == NULL) {
		*to_send = exmpp_new_xbuf();
		if (*to_send == NULL)
			return (-1);
		ei_x_encode_atom(*to_send,
		    "ssl_context_init_failed");

		COPY_AND_FREE_BUF(*to_send, *size, *b, RET_ERROR);

		goto err;
	}

	// SSL 2.0 is deprecated for many years
	SSL_CTX_set_options(edd->ssl_ctx, SSL_OP_NO_SSLv2);

	SSL_CTX_set_cipher_list(edd->ssl_ctx, CIPHERS);

	/*
	 * Since sessions are cached in SSL_CTX and currently new context
	 * is used for every connection, then session caching makes little
	 * sense, turn it off.
	 */
	SSL_CTX_set_session_cache_mode(edd->ssl_ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_options(edd->ssl_ctx, SSL_OP_NO_TICKET);
#ifdef SSL_MODE_RELEASE_BUFFERS
	/*
	 * This appeared in OpenSSL 1.0.0,
	 * reduces memory usage on idle connections.
	 */
	SSL_CTX_set_mode(edd->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

#ifndef OPENSSL_NO_DH
	if (dh1024 != NULL && edd->ctx.mode == TLS_MODE_SERVER) {
		SSL_CTX_set_options(edd->ssl_ctx, SSL_OP_SINGLE_DH_USE);
		SSL_CTX_set_tmp_dh(edd->ssl_ctx, dh1024);
	}
#endif
#if OPENSSL_VERSION_NUMBER >= 0x1000005fL && !defined(OPENSSL_NO_ECDH)
	if (ecdh != NULL && edd->ctx.mode == TLS_MODE_SERVER) {
		SSL_CTX_set_options(edd->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
		SSL_CTX_set_tmp_ecdh(edd->ssl_ctx, ecdh);
	}
#endif

	/* Set our certificate. */
	if (edd->ctx.certificate != NULL) {
		ret = SSL_CTX_use_certificate_chain_file(edd->ssl_ctx,
		    edd->ctx.certificate);
		if (ret != 1) {
			*to_send = exmpp_new_xbuf();
			if (*to_send == NULL)
				goto err;
			ei_x_encode_atom(*to_send,
			    "load_cert_failed");

			COPY_AND_FREE_BUF(*to_send, *size, *b, RET_ERROR);

			goto err;
		}
	}

	/* Set the private key. */
	if (edd->ctx.private_key != NULL) {
		ret = SSL_CTX_use_PrivateKey_file(edd->ssl_ctx,
		    edd->ctx.private_key, SSL_FILETYPE_PEM);
		if (ret != 1) {
			*to_send = exmpp_new_xbuf();
			if (*to_send == NULL)
				goto err;
			ei_x_encode_atom(*to_send,
			    "load_pk_failed");

			COPY_AND_FREE_BUF(*to_send, *size, *b, RET_ERROR);

			goto err;
		}
	}

	/* Prepare OpenSSL for verification. */
	verify = edd->ctx.verify_peer ?
	    SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE : SSL_VERIFY_NONE;
	verify |= edd->ctx.peer_cert_required ?
	    SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0;
	SSL_CTX_set_verify(edd->ssl_ctx, verify, verify_callback);

	/* Set trusted certificates. */
	if (edd->ctx.trusted_certs != NULL) {
		ret = SSL_CTX_load_verify_locations(edd->ssl_ctx,
		    edd->ctx.trusted_certs, NULL);
		if (ret != 1) {
			*to_send = exmpp_new_xbuf();
			if (*to_send == NULL)
				goto err;
			ei_x_encode_atom(*to_send,
			    "load_trusted_certs_failed");

			COPY_AND_FREE_BUF(*to_send, *size, *b, RET_ERROR);

			goto err;
		}
	}

	/* Create an SSL connection handle. */
	edd->ssl = SSL_new(edd->ssl_ctx);
	if (edd->ssl == NULL) {
		*to_send = exmpp_new_xbuf();
		if (*to_send == NULL)
			goto err;
		ei_x_encode_atom(*to_send,
		    "ssl_init_failed");

		COPY_AND_FREE_BUF(*to_send, *size, *b, RET_ERROR);

		goto err;
	}

	/* Associate buffers. */
	edd->bio_read = BIO_new(BIO_s_mem());
	edd->bio_write = BIO_new(BIO_s_mem());
	SSL_set_bio(edd->ssl, edd->bio_read, edd->bio_write);

	/* Set SSL state. */
	switch (edd->ctx.mode) {
	case TLS_MODE_SERVER:
		SSL_set_accept_state(edd->ssl);
		break;
	case TLS_MODE_CLIENT:
		SSL_set_connect_state(edd->ssl);
		break;
	}

	/* Add our own data to SSL. This will be used by verify_callback. */
	SSL_set_ex_data(edd->ssl, ssl_ex_index, edd);

	return (0);

err:
	if (edd->ssl != NULL) {
		SSL_free(edd->ssl);
		edd->ssl = NULL;
	}
	if (edd->ssl_ctx != NULL) {
		SSL_CTX_free(edd->ssl_ctx);
		edd->ssl_ctx = NULL;
	}

	return (-1);
}

static int
verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	SSL *ssl;
	struct exmpp_tls_openssl_data *edd;
	int err, depth, gens_count, i;
	X509 *cert;
	STACK_OF(GENERAL_NAME) *gens;
	const GENERAL_NAME *gen;
	char *dnsname;

	/* Get the port driver's private data. We need it to access
	 * verification options. */
	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
	    SSL_get_ex_data_X509_STORE_CTX_idx());
	edd = SSL_get_ex_data(ssl, ssl_ex_index);

	if (!preverify_ok) {
		/* The verification done by OpenSSL failed. We check if the
		 * error is acceptable for the user. */

		/* Get the verification error code. */
		err = X509_STORE_CTX_get_error(x509_ctx);

		/* Is this kind of error is accepted? */
		switch (err) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		case X509_V_ERR_UNABLE_TO_GET_CRL:
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		case X509_V_ERR_INVALID_CA:
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
		case X509_V_ERR_INVALID_PURPOSE:
		case X509_V_ERR_CERT_UNTRUSTED:
		case X509_V_ERR_CERT_REJECTED:
		case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
		case X509_V_ERR_AKID_SKID_MISMATCH:
		case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
		case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
			/* The peer certificate isn't trusted. */
			if (!edd->ctx.accept_non_trusted_cert)
				return (0);
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_CRL_NOT_YET_VALID:
		case X509_V_ERR_CRL_HAS_EXPIRED:
			/* The peer certificate or a CA certificate has
			 * expired. */
			if (!edd->ctx.accept_expired_cert)
				return (0);
			break;
		case X509_V_ERR_CERT_REVOKED:
			/* The peer certificate or a CA certificate was
			 * revoked. */
			if (!edd->ctx.accept_revoked_cert)
				return (0);
			break;
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			/* The verification couldn't be made because of
			 * bad data. */
			if (!edd->ctx.accept_corrupted_cert)
				return (0);
			break;
		default:
			/* Other types of error are not accepted. */
			return (0);
		}
	}

	/* Basic verification was successful. We now proceed with a more
	 * XMPP-oriented verification, only on the peer certificate and
	 * only if the caller specified an expected ID. */

	/* XXX We need an option to accept non-matching certificates. */

	/* Peer certificate is at depth 0. */
	depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	if (depth > 0 || edd->ctx.expected_id == NULL)
		return (1);

	/* Get the peer certificate. */
	cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	/* Get 'subjectAltName' extensions. */
	gens = X509_get_ext_d2i(cert, NID_subject_alt_name, 0, 0);
	if (gens) {
		gens_count = sk_GENERAL_NAME_num(gens);
		dnsname = NULL;

		/* XXX We must first check for the 'xmpp' extension. */

		/* We walk the extensions list to find the 'dNSName'
		 * extension. */
		for (i = 0; i < gens_count; ++i) {
			gen = sk_GENERAL_NAME_value(gens, i);
			if (gen->type != GEN_DNS)
				/* This one is not a 'dNSName' extension. */
				continue;

			/* We expect the OpenSSL library to construct
			 * GEN_DNS extesion objects as ASN1_IA5STRING
			 * values. Check we got the right union member. */
			if (ASN1_STRING_type(gen->d.ia5) != V_ASN1_IA5STRING)
				continue;

			dnsname = (char *)ASN1_STRING_data(gen->d.ia5);

			/* ASN1_IA5STRING may contain NUL character; check
			 * it. */
			if (ASN1_STRING_length(gen->d.ia5) != strlen(dnsname))
				continue;

			/* Safe to treat as an ASCII string possibly
			 * holding a DNS name */
			if (exmpp_tls_match_hostname(dnsname, edd->ctx.expected_id)) {
				sk_GENERAL_NAME_pop_free(gens,
				    GENERAL_NAME_free);
				return (1);
			}
		}

		if (dnsname != NULL) {
			/* A 'dNSName' extension was found but didn't
			 * match. The certificate is not acceptable. */
			/* XXX We must set the relevant X.509 error. */
			sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
			return (0);
		}

		sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	}

	/* XXX We now fallback on the commonName extension. */

	return (0);
}

/* -------------------------------------------------------------------
 * Driver declaration.
 * ------------------------------------------------------------------- */

static ErlDrvEntry tls_openssl_driver_entry = {
	NULL,				/* init */
	exmpp_tls_openssl_start,	/* start */
	exmpp_tls_openssl_stop,		/* stop */
	NULL,				/* output */
	NULL,				/* ready_input */
	NULL,				/* ready_output */
	S(DRIVER_NAME),			/* driver name */
	NULL,				/* finish */
	NULL,				/* handle */
	exmpp_tls_openssl_control,	/* control */
	NULL,				/* timeout */
	NULL				/* outputv */
};

DRIVER_INIT(DRIVER_NAME)
{
	/* Initialize OpenSSL. */
	SSL_library_init();
	SSL_load_error_strings();

	/* This index is used to store application-specific data inside
	 * SSL structs. This index is the same for each SSL instance,
	 * that's why we keep it global.
	 *
	 * See:
	 * http://www.mail-archive.com/openssl-users@openssl.org/msg52326.html
	 */
	ssl_ex_index = SSL_get_ex_new_index(0, "exmpp_tls_openssl_data",
	    NULL, NULL, NULL);

#ifndef OPENSSL_NO_DH
	// Initialize ephemeral Diffie-Hellman parameters.
	dh1024 = DH_new();
	if (dh1024 != NULL) {
		dh1024->p = BN_bin2bn(exmpp_tls_dh1024_p, exmpp_tls_dh1024_p_size, NULL);
		dh1024->g = BN_bin2bn(exmpp_tls_dh1024_g, exmpp_tls_dh1024_g_size, NULL);
		if (dh1024->p == NULL || dh1024->g == NULL) {
			DH_free(dh1024);
			dh1024 = NULL;
		}
	}
#endif

#if OPENSSL_VERSION_NUMBER >= 0x1000005fL && !defined(OPENSSL_NO_ECDH)
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
#endif

	tls_openssl_driver_entry.extended_marker = ERL_DRV_EXTENDED_MARKER;
	tls_openssl_driver_entry.major_version = ERL_DRV_EXTENDED_MAJOR_VERSION;
	tls_openssl_driver_entry.minor_version = ERL_DRV_EXTENDED_MINOR_VERSION;
#if defined(SMP_SUPPORT)
	/**
	 * To make OpenSSL thread-safe, two callbacks must be set
	 * as described in http://www.openssl.org/docs/crypto/threads.html
	 *
	 * However, OTP comes with crypto module, that links with OpenSSL
	 * and sets the needed callbacks itself. If another set of
	 * callbacks had been provided here, it would overwrite
	 * or be overwritten by those from crypto module.
	 *
	 * So instead of providing callbacks, start crypto module
	 * from Erlang code before loading this driver. As a result
	 * crypto module will install the needed callbacks and
	 * this driver also can be made thread safe.
	 */
	if (CRYPTO_get_locking_callback() != NULL &&
	    CRYPTO_get_id_callback() != NULL) {
		tls_openssl_driver_entry.driver_flags = ERL_DRV_FLAG_USE_PORT_LOCKING;
	}
#endif

	return &tls_openssl_driver_entry;
}
