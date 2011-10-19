#include <string.h>
#include <gnutls/gnutls.h>

#include "exmpp_tls.h"

#define	DRIVER_NAME	exmpp_tls_gnutls
#define MIN_GNUTLS_VER  "2.12.0"
#define PRIORITY        "NORMAL:-COMP-NULL:+COMP-DEFLATE:+COMP-NULL"

#define	BUF_SIZE	4096

static gnutls_priority_t priority;

static gnutls_dh_params_t dh_params;

/* Driver data. */
struct exmpp_tls_gnutls_data {
	struct exmpp_tls_ctx ctx;

	gnutls_session_t session;
	gnutls_certificate_credentials_t credentials;

	char            *input_buf;
	int             input_buf_size;
	char            *output_buf;
	int             output_buf_size;
};

static ssize_t
exmpp_gnutls_pull(gnutls_transport_ptr_t ptr, void *buf, size_t size)
{
	struct exmpp_tls_gnutls_data *edd;
	edd = (struct exmpp_tls_gnutls_data *)ptr;

	if (edd->input_buf_size == 0) {
		gnutls_transport_set_errno(edd->session, EAGAIN);
		return -1;
	}

	size = size > edd->input_buf_size ? edd->input_buf_size : size;
	memcpy(buf, edd->input_buf, size);
	edd->input_buf_size -= size;
	if (edd->input_buf_size == 0) {
		driver_free(edd->input_buf);
		edd->input_buf = NULL;
	} else {
		memmove(edd->input_buf, edd->input_buf + size, edd->input_buf_size);
		edd->input_buf = driver_realloc(edd->input_buf, edd->input_buf_size);
	}

	return size;
}

static ssize_t
exmpp_gnutls_push(gnutls_transport_ptr_t ptr, const void *buf, size_t size)
{
	struct exmpp_tls_gnutls_data *edd;
	edd = (struct exmpp_tls_gnutls_data *)ptr;

	if (edd->output_buf_size == 0) {
		edd->output_buf = driver_alloc(size);
		edd->output_buf_size = size;
		memcpy(edd->output_buf, buf, size);
	} else {
		edd->output_buf = driver_realloc(edd->output_buf, edd->output_buf_size + size);
		memcpy(edd->output_buf + edd->output_buf_size, buf, size);
		edd->output_buf_size += size;
	}

	return size;
}

static int
exmpp_gnutls_verify(gnutls_session_t session)
{
	unsigned int status;
	struct exmpp_tls_gnutls_data *edd;

	gnutls_certificate_verify_peers2(session, &status);
	if (status & GNUTLS_CERT_INVALID) {
		edd = (struct exmpp_tls_gnutls_data*) gnutls_session_get_ptr(session);
		if ((status & GNUTLS_CERT_REVOKED) && !edd->ctx.accept_revoked_cert) {
			return status;
		}
		if ((status & (GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INSECURE_ALGORITHM))
		    && !edd->ctx.accept_non_trusted_cert) {
			return status;
		}
		if ((status & (GNUTLS_CERT_NOT_ACTIVATED | GNUTLS_CERT_EXPIRED)) && !edd->ctx.accept_expired_cert) {
			return status;
		}
	}

	return 0;
}

static int
exmpp_gnutls_mutex_init(void **mutex)
{
	*mutex = erl_drv_mutex_create("exmpp_tls_gnutls_mutex");
	if (*mutex == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}
	return GNUTLS_E_SUCCESS;
}

static int
exmpp_gnutls_mutex_lock(void **mutex)
{
	erl_drv_mutex_lock((ErlDrvMutex*)*mutex);
	return GNUTLS_E_SUCCESS;
}

static int
exmpp_gnutls_mutex_unlock(void **mutex)
{
	erl_drv_mutex_unlock((ErlDrvMutex*)*mutex);
	return GNUTLS_E_SUCCESS;
}

static int
exmpp_gnutls_mutex_deinit(void **mutex)
{
	erl_drv_mutex_destroy((ErlDrvMutex*)*mutex);
	return GNUTLS_E_SUCCESS;
}

static int
exmpp_tls_gnutls_init(void)
{
	gnutls_datum_t prime, generator;

	if (gnutls_check_version(MIN_GNUTLS_VER) == NULL) {
		return -1;
	}

	gnutls_global_set_mem_functions(driver_alloc, driver_alloc, NULL,
					driver_realloc, driver_free);
	gnutls_global_set_mutex(exmpp_gnutls_mutex_init, exmpp_gnutls_mutex_deinit,
				exmpp_gnutls_mutex_lock, exmpp_gnutls_mutex_unlock);
	if (gnutls_global_init() != GNUTLS_E_SUCCESS) {
		return -1;
	}

	if (gnutls_priority_init(&priority, PRIORITY, NULL) != GNUTLS_E_SUCCESS) {
		gnutls_global_deinit();
		return -1;
	}

	if (gnutls_dh_params_init(&dh_params) == GNUTLS_E_SUCCESS) {
		prime.data = exmpp_tls_dh1024_p;
		prime.size = exmpp_tls_dh1024_p_size;
		generator.data = exmpp_tls_dh1024_g;
		generator.size = exmpp_tls_dh1024_g_size;
		if (gnutls_dh_params_import_raw(dh_params, &prime, &generator) != GNUTLS_E_SUCCESS) {
			gnutls_dh_params_deinit(dh_params);
			dh_params = NULL;
		}
	}

	return 0;
}

static void
exmpp_tls_gnutls_finish(void)
{
	if (dh_params != NULL) {
		gnutls_dh_params_deinit(dh_params);
	}
	gnutls_priority_deinit(priority);
	gnutls_global_deinit();
}

static ErlDrvData
exmpp_tls_gnutls_start(ErlDrvPort port, char *command)
{
	struct exmpp_tls_gnutls_data *edd;

	/* Set binary mode. */
	set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);

	/* Allocate driver data structure. */
	edd = driver_alloc(sizeof(*edd));
	if (edd == NULL) {
		return NULL;
	}

	memset(edd, 0, sizeof(*edd));

	if (exmpp_tls_init_context(&edd->ctx) != 0) {
		driver_free(edd);
		return NULL;
	}

	return (ErlDrvData)edd;
}

static void
exmpp_tls_gnutls_stop(ErlDrvData drv_data)
{
	struct exmpp_tls_gnutls_data *edd;

	edd = (struct exmpp_tls_gnutls_data *)drv_data;
	if (edd->session != NULL) {
		gnutls_deinit(edd->session);
	}
	if (edd->credentials != NULL) {
		gnutls_certificate_free_credentials(edd->credentials);
	}
	if (edd->input_buf != NULL) {
		driver_free(edd->input_buf);
	}
	if (edd->output_buf != NULL) {
		driver_free(edd->output_buf);
	}
	exmpp_tls_free_context(&edd->ctx);

	driver_free(edd);
}

static int
exmpp_tls_gnutls_control(ErlDrvData drv_data, unsigned int command,
    char *buf, int len, char **rbuf, int rlen)
{
	struct exmpp_tls_gnutls_data *edd;
	int ret, index;
	size_t size;
	unsigned long data_len;
	ErlDrvBinary *b;
	ei_x_buff *to_send;
	gnutls_datum_t cb;
	const gnutls_datum_t *cert;
	unsigned int list_size;

	edd = (struct exmpp_tls_gnutls_data *)drv_data;

	size = 0;
	b = NULL;

	switch (command) {
	case COMMAND_PREPARE_HANDSHAKE:
		switch (edd->ctx.mode) {
		case TLS_MODE_SERVER:
			gnutls_init(&edd->session, GNUTLS_SERVER);
			break;
		case TLS_MODE_CLIENT:
			gnutls_init(&edd->session, GNUTLS_CLIENT);
			break;
		}

		gnutls_session_set_ptr(edd->session, edd);

		gnutls_priority_set(edd->session, priority);
		gnutls_transport_set_ptr(edd->session, edd);
		gnutls_transport_set_pull_function(edd->session, exmpp_gnutls_pull);
		gnutls_transport_set_push_function(edd->session, exmpp_gnutls_push);

		gnutls_certificate_allocate_credentials(&edd->credentials);
		if (edd->ctx.certificate != NULL && edd->ctx.private_key != NULL) {
			ret = gnutls_certificate_set_x509_key_file(edd->credentials, edd->ctx.certificate,
								   edd->ctx.private_key, GNUTLS_X509_FMT_PEM);
			if (ret != GNUTLS_E_SUCCESS) {
				return -1;
			}
		}
		if (edd->ctx.trusted_certs != NULL) {
			ret = gnutls_certificate_set_x509_trust_file(edd->credentials, edd->ctx.trusted_certs,
								     GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				return -1;
			}
			gnutls_certificate_send_x509_rdn_sequence(edd->session, 1);
		}
		if (edd->ctx.verify_peer) {
			gnutls_certificate_set_verify_function(edd->credentials, exmpp_gnutls_verify);
		}
		if (edd->ctx.mode == TLS_MODE_SERVER && dh_params != NULL) {
			gnutls_certificate_set_dh_params(edd->credentials, dh_params);
		}
		gnutls_credentials_set(edd->session, GNUTLS_CRD_CERTIFICATE, edd->credentials);

		if (edd->ctx.verify_peer && edd->ctx.mode == TLS_MODE_SERVER) {
			if (edd->ctx.peer_cert_required) {
				gnutls_certificate_server_set_request(edd->session, GNUTLS_CERT_REQUIRE);
			} else {
				gnutls_certificate_server_set_request(edd->session, GNUTLS_CERT_REQUEST);
			}
		}
		break;
	case COMMAND_HANDSHAKE:
		ret = gnutls_handshake(edd->session);
		if (ret != GNUTLS_E_SUCCESS) {
			switch (ret) {
			case GNUTLS_E_AGAIN:
			case GNUTLS_E_INTERRUPTED:
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_READ;
				break;
			default:
				to_send = exmpp_new_xbuf();
				if (to_send == NULL) {
					return -1;
				}
				ei_x_encode_tuple_header(to_send, 2);
				ei_x_encode_long(to_send, ret);
				ei_x_encode_string(to_send, gnutls_strerror(ret));

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
				break;
			}
		}
		break;
	case COMMAND_SET_ENCRYPTED_INPUT:
		if (edd->input_buf_size == 0) {
			edd->input_buf = driver_alloc(len);
			memcpy(edd->input_buf, buf, len);
			edd->input_buf_size = len;
		} else {
			edd->input_buf = driver_realloc(edd->input_buf, edd->input_buf_size + len);
			memcpy(edd->input_buf + edd->input_buf_size, buf, len);
			edd->input_buf_size += len;
		}
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

		ret = gnutls_record_recv(edd->session, b->orig_bytes + size, data_len);
		if (ret > 0) {
			size += ret;
			b = driver_realloc_binary(b, size);
		} else {
			driver_free_binary(b);
			b = NULL;

			switch (ret) {
			case GNUTLS_E_INTERRUPTED:
			case GNUTLS_E_AGAIN:
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_READ;

				break;
			default:
				to_send = exmpp_new_xbuf();
				if (to_send == NULL) {
					return -1;
				}
				ei_x_encode_atom(to_send, "decrypt_failed");

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
			}
		}
		break;
	case COMMAND_SET_DECRYPTED_OUTPUT:
		ret = gnutls_record_send(edd->session, buf, len);
		if (ret <= 0) {
			switch (ret) {
			case GNUTLS_E_INTERRUPTED:
			case GNUTLS_E_AGAIN:
				size = 1;
				b = driver_alloc_binary(size);
				b->orig_bytes[0] = RET_WANT_READ;

				break;
			default:
				to_send = exmpp_new_xbuf();
				if (to_send == NULL) {
					return -1;
				}
				ei_x_encode_atom(to_send, "encrypt_failed");

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
			}
		}
		break;
	case COMMAND_GET_ENCRYPTED_OUTPUT:
		size = edd->output_buf_size + 1;
		b = driver_alloc_binary(size);
		b->orig_bytes[0] = RET_OK;

		if (edd->output_buf_size != 0) {
			memcpy(b->orig_bytes + 1, edd->output_buf, edd->output_buf_size);
			edd->output_buf_size = 0;
			driver_free(edd->output_buf);
			edd->output_buf = NULL;
		}

		break;
	case COMMAND_GET_PEER_CERTIFICATE:
		cert = gnutls_certificate_get_peers(edd->session, &list_size);
		if (cert != NULL) {
			size = cert->size + 1;
			b = driver_alloc_binary(size);
			b->orig_bytes[0] = RET_OK;
			memcpy(b->orig_bytes + 1, cert->data, size);
		} else {
			to_send = exmpp_new_xbuf();
			if (to_send == NULL) {
				return -1;
			}
			ei_x_encode_atom(to_send, "no_certificate");

			COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
		}
		break;
	case COMMAND_GET_VERIFY_RESULT:
		break;
	case COMMAND_SHUTDOWN:
		ret = gnutls_bye(edd->session, GNUTLS_SHUT_RDWR);
		if (ret != GNUTLS_E_SUCCESS) {
			switch (ret) {
			case GNUTLS_E_INTERRUPTED:
			case GNUTLS_E_AGAIN:
				size = 1;
				b = driver_alloc_binary(size);
				if (edd->output_buf_size != 0) {
					b->orig_bytes[0] = RET_WANT_WRITE;
				} else if (gnutls_record_get_direction(edd->session) == 0) {
					b->orig_bytes[0] = RET_WANT_READ;
				} else {
					b->orig_bytes[0] = RET_WANT_WRITE;
				}
				break;
			default:
				to_send = exmpp_new_xbuf();
				if (to_send == NULL) {
					return -1;
				}
				ei_x_encode_tuple_header(to_send, 2);
				ei_x_encode_long(to_send, ret);
				ei_x_encode_string(to_send, gnutls_strerror(ret));

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
				break;
			}
		} else if (edd->output_buf_size != 0) {
			size = 1;
			b = driver_alloc_binary(size);
			b->orig_bytes[0] = RET_WANT_WRITE;
		}
		break;
	case COMMAND_QUIET_SHUTDOWN:
		break;
	case COMMAND_PORT_REVISION:
		/* Store the revision in the buffer. */
		to_send = exmpp_new_xbuf();
		if (to_send == NULL) {
			return -1;
		}
		ei_x_encode_string(to_send, "$Revision$");

		COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
		break;
	case COMMAND_GET_PEER_FINISHED:
	case COMMAND_GET_FINISHED:
		ret = gnutls_session_channel_binding(edd->session, GNUTLS_CB_TLS_UNIQUE, &cb);
		if (ret == GNUTLS_E_SUCCESS) {
			size = cb.size + 1;
			b = driver_alloc_binary(size);
			b->orig_bytes[0] = RET_OK;
			memcpy(b->orig_bytes + 1, cb.data, size);
		} else {
			to_send = exmpp_new_xbuf();
			if (to_send == NULL) {
				return -1;
			}
			ei_x_encode_tuple_header(to_send, 2);
			ei_x_encode_long(to_send, ret);
			ei_x_encode_string(to_send, gnutls_strerror(ret));

			COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
		}
		break;
	default:
		if(exmpp_tls_control(&edd->ctx, command, buf, &b, &size) < 0) {
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
 * Driver declaration.
 * ------------------------------------------------------------------- */

static ErlDrvEntry tls_gnutls_driver_entry = {
	exmpp_tls_gnutls_init,          /* init */
	exmpp_tls_gnutls_start, 	/* start */
	exmpp_tls_gnutls_stop,	        /* stop */
	NULL,				/* output */
	NULL,				/* ready_input */
	NULL,				/* ready_output */
	S(DRIVER_NAME),		        /* driver name */
	exmpp_tls_gnutls_finish,	/* finish */
	NULL,				/* handle */
	exmpp_tls_gnutls_control,	/* control */
	NULL,				/* timeout */
	NULL				/* outputv */
};

DRIVER_INIT(DRIVER_NAME)
{
	tls_gnutls_driver_entry.extended_marker = ERL_DRV_EXTENDED_MARKER;
	tls_gnutls_driver_entry.major_version = ERL_DRV_EXTENDED_MAJOR_VERSION;
	tls_gnutls_driver_entry.minor_version = ERL_DRV_EXTENDED_MINOR_VERSION;
#if defined(SMP_SUPPORT)
	tls_gnutls_driver_entry.driver_flags = ERL_DRV_FLAG_USE_PORT_LOCKING;
#endif
	return &tls_gnutls_driver_entry;
}
