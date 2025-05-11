#include <assert.h>
#include <err.h>
#include <sysexits.h>

#include <inttypes.h>
#include <stdlib.h>

#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_utils.h"

#include "tp.h"
#include "tp_count.h"
#include "tp_handle.h"
#include "tp_socket.h"
#include "tp_picoquic.h"

#define TP_PICOQUIC_ALPN		"tp_picoquic"
#define TP_PICOQUIC_CLIENT_MAXCONN	1
#define TP_PICOQUIC_SERVER_MAXCONN	1

#if 1
#define TP_PICOQUIC_CONGESTION_ALG	picoquic_cubic_algorithm
#else
#define TP_PICOQUIC_CONGESTION_ALG	picoquic_bbr_algorithm
#endif

#define TP_PICOQUIC_STREAM_ID	1

struct tp_picoquic_ctx {
	enum {
		tp_picoquic_status_active,
		tp_picoquic_status_done
	} tpctx_status;
};

struct tp_picoquic_stream_ctx {
	uint64_t tpsc_id;
	struct tp_count tpsc_count;
	size_t tpsc_total;
	size_t tpsc_bytes;
};

static struct tp_picoquic_stream_ctx *
tp_picoquic_stream_ctx_new(uint64_t id)
{
	struct tp_picoquic_stream_ctx *tpsc;

	tpsc = malloc(sizeof(*tpsc));
	if (tpsc == NULL)
		return NULL;
	tpsc->tpsc_id = id;
	tpsc->tpsc_total = 0;
	tpsc->tpsc_bytes = 0;
	tp_count_init(&tpsc->tpsc_count, "picoquic");
#ifdef DEBUG
	fprintf(stderr, "stream ctx %p: create\n", tpsc);
#endif /* DEBUG */

	return tpsc;
}

static void
tp_picoquic_stream_ctx_destroy(struct tp_picoquic_stream_ctx *tpsc)
{

	if (tpsc == NULL)
		return;
	free(tpsc);
#ifdef DEBUG
	fprintf(stderr, "stream ctx %p: free\n", tpsc);
#endif /* DEBUG */
}

struct tp_picoquic_name_resolve_arg {
	picoquic_quic_t *tpnra_quic;
	picoquic_cnx_t *tpnra_cnx;
	struct sockaddr_storage tpnra_ss;
};

static int
tp_picoquic_name_resolve_cb(const struct addrinfo *res, void *arg)
{
	struct tp_picoquic_name_resolve_arg *tpnra = arg;
	const char *sni = TP_PICOQUIC_DEFAULT_SNI;	/* XXX */

	if (res->ai_addrlen > sizeof(tpnra->tpnra_ss))
		return -1;

	tpnra->tpnra_cnx = picoquic_create_cnx(tpnra->tpnra_quic,
	    picoquic_null_connection_id, picoquic_null_connection_id,
	    res->ai_addr, picoquic_current_time(), 0, sni, TP_PICOQUIC_ALPN, 1);
	if (tpnra->tpnra_cnx == NULL)
		return -1;
	memcpy(&tpnra->tpnra_ss, res->ai_addr, res->ai_addrlen);

	return 0;
}

static picoquic_cnx_t *
tp_picoquic_create_cnx(picoquic_quic_t *quic, const char *dststr,
    const char *servstr, struct sockaddr_storage *ss)
{
	struct tp_picoquic_name_resolve_arg tpnra = { quic, NULL };
	int error;

	error = tp_name_resolve(SOCK_DGRAM, dststr, servstr,
	    tp_picoquic_name_resolve_cb, &tpnra);
	if (error == -1)
		return NULL;
	*ss = tpnra.tpnra_ss;
	return tpnra.tpnra_cnx;
}

static int
tp_picoquic_client_cb(picoquic_cnx_t *cnx, uint64_t stream_id,
    uint8_t *bytes, size_t len, picoquic_call_back_event_t event,
    void *cb_ctx, void *stream_ctx)
{
	struct tp_picoquic_ctx *tpctx = cb_ctx;
	struct tp_picoquic_stream_ctx *tpsc = stream_ctx;
	int error = 0;

#ifdef DEBUG
	fprintf(stderr, "%" PRIu64 ": event: %u\n",
	    stream_id, (unsigned)event);
#endif /* DEBUG */

	switch (event) {
	case picoquic_callback_stream_data:
	case picoquic_callback_stream_fin:
		assert(tpctx != NULL);
		if (tpsc != NULL)
			tp_count_inc(&tpsc->tpsc_count, len);
		else {
			tpsc = tp_picoquic_stream_ctx_new(stream_id);
			if (tpsc == NULL ||
			    picoquic_set_app_stream_ctx(cnx, stream_id, tpsc) != 0) {
				tp_picoquic_stream_ctx_destroy(tpsc);
				(void)picoquic_reset_stream(cnx, stream_id, 0x0U);
				break;
			}
			fprintf(stderr, "open stream\n");
		}
		if (event == picoquic_callback_stream_fin) {
			fprintf(stderr, "fin\n");
			assert(tpsc != NULL);
			tp_count_final_stats(&tpsc->tpsc_count);
			tp_picoquic_stream_ctx_destroy(tpsc);
			tpctx->tpctx_status = tp_picoquic_status_done;
			error = picoquic_close(cnx, 0);
		}
		break;
	case picoquic_callback_prepare_to_send:
		break;
	case picoquic_callback_stream_reset:
	case picoquic_callback_stop_sending:
		picoquic_reset_stream(cnx, stream_id, 0x1U);
		/* XXX: should set callback??? */
		fprintf(stderr, "reset\n");
		break;
	case picoquic_callback_stateless_reset:
	case picoquic_callback_close:
	case picoquic_callback_application_close:
		picoquic_set_callback(cnx, NULL, NULL);
		tp_picoquic_stream_ctx_destroy(tpsc);
		fprintf(stderr, "connection closed\n");
		break;
	case picoquic_callback_version_negotiation:
		break;
	case picoquic_callback_stream_gap:
		break;
	case picoquic_callback_almost_ready:
		break;
	case picoquic_callback_ready:
		fprintf(stderr, "callback ready\n");
		break;
	default:
		fprintf(stderr, "%" PRIu64 ": unexpected event: %u\n",
		    stream_id, (unsigned)event);
		break;
	}
 
	return error;
}

static int
tp_picoquic_client_loop_cb(picoquic_quic_t *quic,
    picoquic_packet_loop_cb_enum cb_mode, void *ctx, void *arg)
{
	struct tp_picoquic_ctx *tpctx = ctx;
	int error = 0;

#ifdef DEBUG
	fprintf(stderr, "loop event: %u\n", (unsigned)cb_mode);
#endif /* DEBUG */

	switch (cb_mode) {
	case picoquic_packet_loop_ready:
		fprintf(stderr, "ready for packet handling\n");
		break;
	case picoquic_packet_loop_after_receive:
		assert(tpctx != NULL);
		if (tpctx->tpctx_status == tp_picoquic_status_done)
			error = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
		break;
	case picoquic_packet_loop_after_send:
		break;
	case picoquic_packet_loop_port_update:
		break;
	default:
		error = PICOQUIC_ERROR_UNEXPECTED_ERROR;
		break;
	}
	return error;
}

static int
tp_picoquic_client(const char *dststr, const char *servstr,
    int argc, char * const argv[])
{
	picoquic_quic_t *quic;
	picoquic_cnx_t *cnx;
	struct tp_picoquic_ctx tpctx = { tp_picoquic_status_active };
	struct sockaddr_storage ss;
	int error;

	quic = picoquic_create(TP_PICOQUIC_CLIENT_MAXCONN,
	    NULL, NULL, /* no client certificate and key */
	    NULL, TP_PICOQUIC_ALPN,
	    tp_picoquic_client_cb, NULL, /* no arg. for now. */
	    NULL, NULL, NULL, picoquic_current_time(),
	    NULL, NULL, NULL, 0);
	if (quic == NULL)
		errx(EX_SOFTWARE, "cannot initialize QUIC");
		/*NOTREACHED*/

	picoquic_set_default_congestion_algorithm(quic, TP_PICOQUIC_CONGESTION_ALG);
	picoquic_set_key_log_file_from_env(quic);
#ifdef notyet
	picoquic_set_qlog(quic, dir);
	picoquic_set_log_level(quic, 1);
#endif /* notyet */

	cnx = tp_picoquic_create_cnx(quic, dststr, servstr, &ss);
	if (cnx == NULL)
		errx(EX_SOFTWARE, "cannot create QUIC connection");
		/*NOTREACHED*/

	picoquic_set_callback(cnx, tp_picoquic_client_cb, &tpctx);
	error = picoquic_start_client_cnx(cnx);
	if (error == -1)
		errx(EX_SOFTWARE, "cannot activate QUIC connection");
		/*NOTREACHED*/

	picoquic_connection_id_t icid = picoquic_get_initial_cnxid(cnx);
	printf("Initial connection ID: ");
	for (uint8_t i = 0; i < icid.id_len; i++)
		printf("%02x", icid.id[i]);
	printf("\n");

	error = picoquic_packet_loop(quic, 0, ss.ss_family, 0, 0, 0,
	    tp_picoquic_client_loop_cb, &tpctx);

	picoquic_free(quic);

	return 0;
}

static void
tp_picoquic_server_send(struct tp_picoquic_stream_ctx *tpsc, uint8_t *bytes, size_t len)
{
	size_t left;
	uint8_t *buf;
	int is_fin, is_still_active;

	assert(tpsc->tpsc_total > tpsc->tpsc_bytes);
	left = tpsc->tpsc_total - tpsc->tpsc_bytes;
	if (left < len)
		len = left;
	tpsc->tpsc_bytes += len;
	is_fin = (tpsc->tpsc_total == tpsc->tpsc_bytes);
	is_still_active = ! is_fin;

	buf = picoquic_provide_stream_data_buffer(bytes, len,
	    is_fin, is_still_active);
	/* XXX: write something meaningful... */
	buf[0] = '\0';
#ifdef DEBUG
	fprintf(stderr, "write %zu bytes\n", len);
#endif /* DEBUG */
}

static int
tp_picoquic_server_cb(picoquic_cnx_t *cnx, uint64_t stream_id,
    uint8_t *bytes, size_t len, picoquic_call_back_event_t event,
    void *cb_ctx, void *stream_ctx)
{
	struct tp_picoquic_stream_ctx *tpsc = stream_ctx;
	int error = 0;

#ifdef DEBUG
	fprintf(stderr, "%" PRIu64 ": event: %u\n",
	    stream_id, (unsigned)event);
#endif /* DEBUG */

	switch (event) {
	case picoquic_callback_stream_data:
		break;
	case picoquic_callback_stream_fin:
		fprintf(stderr, "fin\n");
		break;
	case picoquic_callback_prepare_to_send:
		assert(bytes != NULL);
		tp_picoquic_server_send(tpsc, bytes, len);
		if (tpsc->tpsc_total == tpsc->tpsc_bytes) {
			tp_picoquic_stream_ctx_destroy(tpsc);
			error = picoquic_close(cnx, 0);
		}
		break;
	case picoquic_callback_stream_reset:
	case picoquic_callback_stop_sending:
		picoquic_reset_stream(cnx, stream_id, 0x1U);
		tp_picoquic_stream_ctx_destroy(tpsc);
		/* XXX: should set callback??? */
		break;
	case picoquic_callback_stateless_reset:
	case picoquic_callback_close:
	case picoquic_callback_application_close:
		picoquic_set_callback(cnx, NULL, NULL);
		tp_picoquic_stream_ctx_destroy(tpsc);
		picoquic_close(cnx, 0);
		fprintf(stderr, "connection closed\n");
		break;
	case picoquic_callback_version_negotiation:
		perror("server should never receive negotiation...");
		break;
	case picoquic_callback_stream_gap:
		break;
	case picoquic_callback_almost_ready:
		break;
	case picoquic_callback_ready:
		assert(tpsc == NULL);
		tpsc = tp_picoquic_stream_ctx_new(TP_PICOQUIC_STREAM_ID);
		if (tpsc == NULL) {
			(void)picoquic_close(cnx, 0);
			break;
		}
		tpsc->tpsc_total = TP_DATASIZE;
		error = picoquic_mark_active_stream(cnx, tpsc->tpsc_id, 1, tpsc);
		if (error != 0) {
			tp_picoquic_stream_ctx_destroy(tpsc);
			fprintf(stderr, "cannot open stream\n");
			break;
		}
		fprintf(stderr, "open stream\n");
		break;
	default:
		fprintf(stderr, "%" PRIu64 ": unexpected event: %u\n",
		    stream_id, (unsigned)event);
		break;
	}

	return error;
}

static int
tp_picoquic_server(const char *dststr, const char *servstr, const char *filename,
    int argc, char * const argv[])
{
	picoquic_quic_t *quic;
	const char *cert;
	const char *key;
	int port, error;
#ifdef HAVE_UDP_GSO
	int do_not_use_gso = 0;
#else /* HAVE_UDP_GSO */
	int do_not_use_gso = 1;
#endif /* ! HAVE_UDP_GSO */

	if (argc < 2)
		errx(EX_USAGE, "missing certificate or key file for QUIC TLS");
	cert = argv[0];
	key = argv[1];
	argc -= 2;
	argv += 2;

	if (argc != 0)
		errx(EX_USAGE, "extra argument(s)");

	quic = picoquic_create(TP_PICOQUIC_SERVER_MAXCONN,
	    cert, key, NULL, TP_PICOQUIC_ALPN,
	    tp_picoquic_server_cb, NULL /* ctx */, NULL, NULL, NULL,
	    picoquic_current_time(),
	    NULL, NULL, NULL, 0);
	if (quic == NULL)
		errx(EX_SOFTWARE, "cannot initialize QUIC");

#define	COOKIE_MODE_FORCE_CHECK_TOKEN	(1 << 0)
#define COOKIE_MODE_PROVIDE_TOKEN	(1 << 1)
	picoquic_set_cookie_mode(quic, 0);
	picoquic_set_default_congestion_algorithm(quic, TP_PICOQUIC_CONGESTION_ALG);
#ifdef notyet
	picoquic_set_mtu_max(quic, 16384);	/* XXX */
	picoquic_set_qlog(quic, dir);
	picoquic_set_log_level(quic, 1);
	picoquic_set_key_log_file_from_env(quic);
#endif /* notyet */

	port = atoi(servstr);
	error = picoquic_packet_loop(quic, port, 0, 0,
	    tp_socket_buffer_recv_size(), /* XXX: ineffective for sending */
	    do_not_use_gso, NULL, NULL);

	picoquic_free(quic);

	fprintf(stderr, "done\n");

	return error;
}

void
tp_picoquic_init(void)
{

	(void)tp_handle_register("picoquic", tp_picoquic_client, tp_picoquic_server);
}
