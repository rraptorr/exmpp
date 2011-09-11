#include <string.h>
#include <gnutls/gnutls.h>

#include "exmpp_tls.h"

#define	DRIVER_NAME	exmpp_tls_gnutls

/* Driver data. */
struct exmpp_tls_gnutls_data {
	int		 mode;

	/* Identity. */
	char		*certificate;
	char		*private_key;

	gnutls_session_t *session;
	gnutls_certificate_credentials_t *credentials;
};

#define	COPY_AND_FREE_BUF(to_send, size, b, ret)			\
	(size) = (to_send)->index + 1;					\
	(b) = driver_alloc_binary((size));				\
	(b)->orig_bytes[0] = (ret);					\
	memcpy((b)->orig_bytes + 1, (to_send)->buff,			\
	    (to_send)->index);						\
	exmpp_free_xbuf((to_send));

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
	gnutls_global_set_mem_functions(driver_alloc, driver_alloc, NULL,
					driver_realloc, driver_free);
	gnutls_global_set_mutex(exmpp_gnutls_mutex_init, exmpp_gnutls_mutex_deinit,
				exmpp_gnutls_mutex_lock, exmpp_gnutls_mutex_unlock);
	if (gnutls_global_init() == GNUTLS_E_SUCCESS) {
		return 0;
	} else {
		return -1;
	}
}

static void
exmpp_tls_gnutls_finish(void)
{
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
	edd->session = NULL;
	edd->credentials = NULL;

	return (ErlDrvData)edd;
}

static void
exmpp_tls_gnutls_stop(ErlDrvData drv_data)
{
	struct exmpp_tls_gnutls_data *edd;

	edd = (struct exmpp_tls_gnutls_data *)drv_data;
	if (edd->certificate != NULL)
		driver_free(edd->certificate);
	if (edd->private_key != NULL)
		driver_free(edd->private_key);
	if (edd->session != NULL) {
		gnutls_deinit(*edd->session);
		driver_free(edd->session);
	}
	if (edd->credentials != NULL) {
		gnutls_certificate_free_credentials(*edd->credentials);
		driver_free(edd->credentials);
	}

	driver_free(edd);
}

static int
exmpp_tls_gnutls_control(ErlDrvData drv_data, unsigned int command,
    char *buf, int len, char **rbuf, int rlen)
{
	struct exmpp_tls_gnutls_data *edd;
	int index, arity, type, type_size;
	char atom[MAXATOMLEN];
	size_t size;
	long mode;
	ErlDrvBinary *b;
	ei_x_buff *to_send;

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
		break;
	case COMMAND_SET_TRUSTED_CERTS:
		break;
	case COMMAND_SET_OPTIONS:
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

		if (edd->certificate != NULL && edd->private_key != NULL) {
			edd->credentials = driver_alloc(sizeof(*edd->credentials));
			if (edd->credentials == NULL) {
				return -1;
			}
			gnutls_certificate_allocate_credentials(edd->credentials);
			gnutls_certificate_set_x509_key_file(*edd->credentials, edd->certificate, edd->private_key, GNUTLS_X509_FMT_PEM);
			gnutls_credentials_set(*edd->session, GNUTLS_CRD_CERTIFICATE, edd->credentials);
		}
		break;
	case COMMAND_HANDSHAKE:
		break;
	case COMMAND_SET_ENCRYPTED_INPUT:
		break;
	case COMMAND_GET_DECRYPTED_INPUT:
		break;
	case COMMAND_SET_DECRYPTED_OUTPUT:
		break;
	case COMMAND_GET_ENCRYPTED_OUTPUT:
		break;
	case COMMAND_GET_PEER_CERTIFICATE:
		break;
	case COMMAND_GET_VERIFY_RESULT:
		break;
	case COMMAND_SHUTDOWN:
		break;
	case COMMAND_QUIET_SHUTDOWN:
		break;
	case COMMAND_PORT_REVISION:
		break;
	case COMMAND_GET_PEER_FINISHED:
		break;
	case COMMAND_GET_FINISHED:
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
