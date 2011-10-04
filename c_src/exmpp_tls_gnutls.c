#include <string.h>
#include <gnutls/gnutls.h>

#include "exmpp_tls.h"

#define	DRIVER_NAME	exmpp_tls_gnutls
#define MIN_GNUTLS_VER  "2.12.0"
#define PRIORITY        "NORMAL:-COMP-NULL:+COMP-DEFLATE:+COMP-NULL"

#define	BUF_SIZE	4096

static gnutls_priority_t priority;

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

static unsigned char dh1024_p[] = {
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
static unsigned char dh1024_g[] = {
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
static gnutls_dh_params_t dh_params;

/* Driver data. */
struct exmpp_tls_gnutls_data {
	int		 mode;

	/* Identity. */
	char		*certificate;
	char		*private_key;

	/* Peer verification. */
	int		 verify_peer;
	char		*expected_id;

	/* Options. */
	char             *trusted_certs;
	int		 peer_cert_required;
	int		 accept_expired_cert;
	int		 accept_revoked_cert;
	int		 accept_non_trusted_cert;

	gnutls_session_t *session;
	gnutls_certificate_credentials_t *credentials;

	char            *input_buf;
	int             input_buf_size;
	char            *output_buf;
	int             output_buf_size;
};

#define	COPY_AND_FREE_BUF(to_send, size, b, ret)			\
	(size) = (to_send)->index + 1;					\
	(b) = driver_alloc_binary((size));				\
	(b)->orig_bytes[0] = (ret);					\
	memcpy((b)->orig_bytes + 1, (to_send)->buff,			\
	    (to_send)->index);						\
	exmpp_free_xbuf((to_send));

static ssize_t
exmpp_gnutls_pull(gnutls_transport_ptr_t ptr, void *buf, size_t size)
{
	struct exmpp_tls_gnutls_data *edd;
	edd = (struct exmpp_tls_gnutls_data *)ptr;

	if (edd->input_buf_size == 0) {
		gnutls_transport_set_errno(*edd->session, EAGAIN);
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
		if ((status & GNUTLS_CERT_REVOKED) && !edd->accept_revoked_cert) {
			return status;
		}
		if ((status & (GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_SIGNER_NOT_CA | GNUTLS_CERT_INSECURE_ALGORITHM))
		    && !edd->accept_non_trusted_cert) {
			return status;
		}
		if ((status & (GNUTLS_CERT_NOT_ACTIVATED | GNUTLS_CERT_EXPIRED)) && !edd->accept_expired_cert) {
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
		prime.data = dh1024_p;
		prime.size = sizeof(dh1024_p);
		generator.data = dh1024_g;
		generator.size = sizeof(dh1024_g);
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
	if (edd == NULL)
		return NULL;

	edd->mode = TLS_MODE_UNKNOWN;
	edd->certificate = edd->private_key = NULL;
	edd->verify_peer = 0;
	edd->expected_id = NULL;
	edd->trusted_certs = NULL;
	edd->peer_cert_required = 0;
	edd->accept_expired_cert = 0;
	edd->accept_revoked_cert = 0;
	edd->accept_non_trusted_cert = 0;
	edd->session = NULL;
	edd->credentials = NULL;
	edd->input_buf = edd->output_buf = NULL;
	edd->input_buf_size = edd->output_buf_size = 0;

	return (ErlDrvData)edd;
}

static void
exmpp_tls_gnutls_stop(ErlDrvData drv_data)
{
	struct exmpp_tls_gnutls_data *edd;

	edd = (struct exmpp_tls_gnutls_data *)drv_data;
	if (edd->certificate != NULL) {
		driver_free(edd->certificate);
	}
	if (edd->private_key != NULL) {
		driver_free(edd->private_key);
	}
	if (edd->expected_id != NULL) {
		driver_free(edd->expected_id);
	}
	if (edd->trusted_certs) {
		driver_free(edd->trusted_certs);
	}
	if (edd->session != NULL) {
		gnutls_deinit(*edd->session);
		driver_free(edd->session);
	}
	if (edd->credentials != NULL) {
		gnutls_certificate_free_credentials(*edd->credentials);
		driver_free(edd->credentials);
	}
	if (edd->input_buf != NULL) {
		driver_free(edd->input_buf);
	}
	if (edd->output_buf != NULL) {
		driver_free(edd->output_buf);
	}

	driver_free(edd);
}

static int
exmpp_tls_gnutls_control(ErlDrvData drv_data, unsigned int command,
    char *buf, int len, char **rbuf, int rlen)
{
	struct exmpp_tls_gnutls_data *edd;
	int ret, index, arity, type, type_size, flag;
	char atom[MAXATOMLEN];
	size_t size;
	long mode;
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
	case COMMAND_SET_MODE:
		index = exmpp_skip_version(buf);

		/* Get the mode (client vs. server). */
		ei_decode_long(buf, &index, &mode);
		edd->mode = mode;

		break;
	case COMMAND_SET_IDENTITY:
		index = exmpp_skip_version(buf);

		/* Get auth method. */
		ei_decode_tuple_header(buf, &index, &arity);
		ei_decode_atom(buf, &index, atom);
		if (strcmp(atom, "x509") != 0) {
			/* Only X.509 is supported by this port driver. */
			to_send = exmpp_new_xbuf();
			if (to_send == NULL)
				return (-1);
			ei_x_encode_tuple_header(to_send, 2);
			ei_x_encode_atom(to_send, "unsupported_auth_method");
			ei_x_encode_string(to_send, atom);

			COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);

			break;
		}

		/* Get certificate filename. */
		ei_get_type(buf, &index, &type, &type_size);
		edd->certificate = driver_alloc(type_size + 1);
		if (edd->certificate == NULL)
			return (-1);
		ei_decode_string(buf, &index, edd->certificate);

		/* Get private key filename. */
		ei_get_type(buf, &index, &type, &type_size);
		edd->private_key = driver_alloc(type_size + 1);
		if (edd->private_key == NULL)
			return (-1);
		ei_decode_string(buf, &index, edd->private_key);

		break;
	case COMMAND_SET_PEER_VERIF:
		index = exmpp_skip_version(buf);

		/* Check if the identity of the remote peer must be
		 * verified. */
		ei_get_type(buf, &index, &type, &type_size);
		switch (type) {
		case ERL_ATOM_EXT:
			ei_decode_boolean(buf, &index, &(edd->verify_peer));
			break;
		case ERL_STRING_EXT:
			edd->expected_id = driver_alloc(type_size + 1);
			if (edd->expected_id == NULL)
				return (-1);
			ei_decode_string(buf, &index, edd->expected_id);
			edd->verify_peer = 1;
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
			if (to_send == NULL)
				return (-1);
			ei_x_encode_tuple_header(to_send, 2);
			ei_x_encode_atom(to_send, "unsupported_auth_method");
			ei_x_encode_string(to_send, atom);

			COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);

			break;
		}

		/* Get the filename for the trusted certificates. */
		ei_get_type(buf, &index, &type, &type_size);
		edd->trusted_certs = driver_alloc(type_size + 1);
		if (edd->trusted_certs == NULL)
			return (-1);
		ei_decode_string(buf, &index, edd->trusted_certs);
		break;
	case COMMAND_SET_OPTIONS:
		index = exmpp_skip_version(buf);

		/* Get auth method. */
		ei_decode_tuple_header(buf, &index, &arity);
		ei_decode_atom(buf, &index, atom);
		ei_decode_boolean(buf, &index, &flag);

		if (strcmp(atom, "peer_cert_required") == 0) {
			edd->peer_cert_required = flag;
		} else if (strcmp(atom, "accept_expired_cert") == 0) {
			edd->accept_expired_cert = flag;
		} else if (strcmp(atom, "accept_non_trusted_cert") == 0) {
			edd->accept_non_trusted_cert = flag;
		} else if (strcmp(atom, "accept_revoked_cert") == 0){ 
			edd->accept_revoked_cert = flag;
		} else if (strcmp(atom, "accept_corrupted_cert") == 0) {
			// ignore
		} else {
			to_send = exmpp_new_xbuf();
			if (to_send == NULL)
				return (-1);
			ei_x_encode_tuple_header(to_send, 2);
			ei_x_encode_atom(to_send, "unsupported_option");
			ei_x_encode_atom(to_send, atom);

			COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);

			break;
		}
		break;
	case COMMAND_PREPARE_HANDSHAKE:
		edd->session = driver_alloc(sizeof(*edd->session));
		if (edd->session == NULL) {
			return -1;
		}
		switch (edd->mode) {
		case TLS_MODE_SERVER:
			gnutls_init(edd->session, GNUTLS_SERVER);
			break;
		case TLS_MODE_CLIENT:
			gnutls_init(edd->session, GNUTLS_CLIENT);
			break;
		}

		gnutls_session_set_ptr(*edd->session, edd);

		gnutls_priority_set(*edd->session, priority);
		gnutls_transport_set_ptr(*edd->session, edd);
		gnutls_transport_set_pull_function(*edd->session, exmpp_gnutls_pull);
		gnutls_transport_set_push_function(*edd->session, exmpp_gnutls_push);

		edd->credentials = driver_alloc(sizeof(*edd->credentials));
		if (edd->credentials == NULL) {
			return -1;
		}
		gnutls_certificate_allocate_credentials(edd->credentials);
		if (edd->certificate != NULL && edd->private_key != NULL) {
			ret = gnutls_certificate_set_x509_key_file(*edd->credentials, edd->certificate,
								   edd->private_key, GNUTLS_X509_FMT_PEM);
			if (ret != GNUTLS_E_SUCCESS) {
				return -1;
			}
		}
		if (edd->trusted_certs != NULL) {
			ret = gnutls_certificate_set_x509_trust_file(*edd->credentials, edd->trusted_certs,
								     GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				return -1;
			}
			gnutls_certificate_send_x509_rdn_sequence(*edd->session, 1);
		}
		if (edd->verify_peer) {
			gnutls_certificate_set_verify_function(*edd->credentials, exmpp_gnutls_verify);
		}
		if (edd->mode == TLS_MODE_SERVER && dh_params != NULL) {
			gnutls_certificate_set_dh_params(*edd->credentials, dh_params);
		}
		gnutls_credentials_set(*edd->session, GNUTLS_CRD_CERTIFICATE, *edd->credentials);

		if (edd->verify_peer && edd->mode == TLS_MODE_SERVER) {
			if (edd->peer_cert_required) {
				gnutls_certificate_server_set_request(*edd->session, GNUTLS_CERT_REQUIRE);
			} else {
				gnutls_certificate_server_set_request(*edd->session, GNUTLS_CERT_REQUEST);
			}
		}
		break;
	case COMMAND_HANDSHAKE:
		ret = gnutls_handshake(*edd->session);
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
				if (to_send == NULL)
					return -1;
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

		ret = gnutls_record_recv(*edd->session, b->orig_bytes + size, data_len);
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
				if (to_send == NULL)
					return (-1);
				ei_x_encode_atom(to_send, "decrypt_failed");

				COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
			}
		}
		break;
	case COMMAND_SET_DECRYPTED_OUTPUT:
		ret = gnutls_record_send(*edd->session, buf, len);
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
				if (to_send == NULL)
					return (-1);
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
		cert = gnutls_certificate_get_peers(*edd->session, &list_size);
		if (cert != NULL) {
			size = cert->size + 1;
			b = driver_alloc_binary(size);
			b->orig_bytes[0] = RET_OK;
			memcpy(b->orig_bytes + 1, cert->data, size);
		} else {
			to_send = exmpp_new_xbuf();
			if (to_send == NULL)
				return (-1);
			ei_x_encode_atom(to_send, "no_certificate");

			COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
		}
		break;
	case COMMAND_GET_VERIFY_RESULT:
		break;
	case COMMAND_SHUTDOWN:
		ret = gnutls_bye(*edd->session, GNUTLS_SHUT_RDWR);
		if (ret != GNUTLS_E_SUCCESS) {
			switch (ret) {
			case GNUTLS_E_INTERRUPTED:
			case GNUTLS_E_AGAIN:
				size = 1;
				b = driver_alloc_binary(size);
				if (edd->output_buf_size != 0) {
					b->orig_bytes[0] = RET_WANT_WRITE;
				} else if (gnutls_record_get_direction(*edd->session) == 0) {
					b->orig_bytes[0] = RET_WANT_READ;
				} else {
					b->orig_bytes[0] = RET_WANT_WRITE;
				}
				break;
			default:
				to_send = exmpp_new_xbuf();
				if (to_send == NULL)
					return (-1);
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
		if (to_send == NULL)
			return (-1);
		ei_x_encode_string(to_send, "$Revision$");

		COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
		break;
	case COMMAND_GET_PEER_FINISHED:
	case COMMAND_GET_FINISHED:
		ret = gnutls_session_channel_binding(*edd->session, GNUTLS_CB_TLS_UNIQUE, &cb);
		if (ret == GNUTLS_E_SUCCESS) {
			size = cb.size + 1;
			b = driver_alloc_binary(size);
			b->orig_bytes[0] = RET_OK;
			memcpy(b->orig_bytes + 1, cb.data, size);
		} else {
			to_send = exmpp_new_xbuf();
			if (to_send == NULL)
				return (-1);
			ei_x_encode_tuple_header(to_send, 2);
			ei_x_encode_long(to_send, ret);
			ei_x_encode_string(to_send, gnutls_strerror(ret));

			COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
		}
		break;
	default:
		/* Commad not recognized. */
		to_send = exmpp_new_xbuf();
		if (to_send == NULL)
			return (-1);
		ei_x_encode_tuple_header(to_send, 2);
		ei_x_encode_atom(to_send, "unknown_command");
		ei_x_encode_ulong(to_send, command);

		COPY_AND_FREE_BUF(to_send, size, b, RET_ERROR);
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
