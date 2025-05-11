#include <err.h>
#include <sysexits.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#if 0
#define DEBUG /* DPRINTF() */
#endif /* 0 */
#include "tp.h"
#include "tp_count.h"
#include "tp_handle.h"

#include "msquic.h"

const uint64_t IdleTimeoutMs = 10000;

const QUIC_API_TABLE *MsQuic;
const QUIC_REGISTRATION_CONFIG RegConfig = { "tp_msquic", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
HQUIC Registration;
const QUIC_BUFFER Alpn = { sizeof("tp_msquic") - 1, (uint8_t *)"tp_msquic" };
HQUIC Configuration;

#define TP_MSQUIC_MSS	(TP_MSS - 54)

#if 1
#define TP_MSQUIC_DEFAULT_CC_ALG	QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC
#else
#define TP_MSQUIC_DEFAULT_CC_ALG	QUIC_CONGESTION_CONTROL_ALGORITHM_BBR
#endif

struct tp_msquic_stream_context {
	struct tp_count tmsc_recv_count;
	struct tp_count tmsc_sent_count;
	size_t tmsc_total;
	size_t tmsc_bytes;
	QUIC_BUFFER tmsc_qbuf;
	uint8_t tmsc_buf[1];
};

static struct tp_msquic_stream_context *
tp_msquic_stream_context_new(void)
{
	struct tp_msquic_stream_context *tmsc;
	size_t size;

	size = offsetof(struct tp_msquic_stream_context, tmsc_buf[TP_MSQUIC_MSS]);
	tmsc = malloc(size);
	if (tmsc == NULL)
		return NULL;
	tmsc->tmsc_total = 0;
	tmsc->tmsc_bytes = 0;
	tp_count_init(&tmsc->tmsc_recv_count, "msquic recv");
	tp_count_init(&tmsc->tmsc_sent_count, "msquic sent");
	DPRINTF("stream ctx %p: create %zu bytes", tmsc, size);
	return tmsc;
}

static void
tp_msquic_stream_context_destroy(struct tp_msquic_stream_context *tmsc)
{

	if (tmsc == NULL)
		return;
	DPRINTF("stream ctx %p: free", tmsc);
	free(tmsc);
}

static QUIC_STATUS
tp_msquic_stream_send(HQUIC s, struct tp_msquic_stream_context *tmsc)
{
	size_t len;
	QUIC_STATUS Status;
	QUIC_BUFFER *buf;
	uint16_t flags = 0;

	assert(tmsc != NULL);
	assert(tmsc->tmsc_total > tmsc->tmsc_bytes);
	len = tmsc->tmsc_total - tmsc->tmsc_bytes;
	if (len > TP_MSQUIC_MSS)
		len = TP_MSQUIC_MSS;
	else
		flags |= QUIC_SEND_FLAG_FIN;

	buf = &tmsc->tmsc_qbuf;
	buf->Length = len;
	buf->Buffer = tmsc->tmsc_buf;

	Status = MsQuic->StreamSend(s, buf, 1, flags, tmsc);
	if (QUIC_FAILED(Status)) {
		/* may fail when socket sending buffer is already full. */
		tp_count_inc(&tmsc->tmsc_sent_count, (ssize_t)-1);
		warn("stream %p: StreamSend failed: 0x%x\n", s, Status);
		goto bad;
	}
	tmsc->tmsc_bytes += len;
	tp_count_inc(&tmsc->tmsc_sent_count, len);
	DPRINTF("stream %p: send %zu bytes, left %zu bytes",
	    s, len, tmsc->tmsc_total - tmsc->tmsc_bytes);
  bad:
	return Status;
}

static QUIC_STATUS
tp_msquic_stream_receive(HQUIC s, struct tp_msquic_stream_context *tmsc,
    const QUIC_BUFFER *bufs, unsigned int bufcount)
{
	unsigned int i;

	for (i = 0; i < bufcount; i++) {
		/* XXX: should free memory... */
		tp_count_inc(&tmsc->tmsc_recv_count, bufs[i].Length);
	}
	return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
tp_msquic_stream_callback(HQUIC s, void *ctx, QUIC_STREAM_EVENT *ev)
{
	struct tp_msquic_stream_context *tmsc = ctx;

	DPRINTF("stream %p: context %p, event 0x%x", s, ctx, ev->Type);

	switch (ev->Type) {
	case QUIC_STREAM_EVENT_START_COMPLETE:
		DPRINTF("stream %p: start complete", s);
		return tp_msquic_stream_send(s, tmsc);
	case QUIC_STREAM_EVENT_SEND_COMPLETE:
		assert(ev->SEND_COMPLETE.ClientContext == tmsc);
		DPRINTF("stream %p: send complete", s);
		if (tmsc->tmsc_bytes < tmsc->tmsc_total)
			return tp_msquic_stream_send(s, tmsc);
		else
			tp_count_final_stats(&tmsc->tmsc_sent_count);
#if 0
		/* XXX: will be closed automatically by FIN??? */
		MsQuic->StreamClose(s);
#endif /* 0 */
		break;
	case QUIC_STREAM_EVENT_RECEIVE:
		DPRINTF("stream %p: receive %u", s, ev->RECEIVE.BufferCount);
		return tp_msquic_stream_receive(s, tmsc,
		    ev->RECEIVE.Buffers, ev->RECEIVE.BufferCount);
	case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
		fprintf(stderr, "stream %p: peer send abort\n", s);
		break;
	case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
		fprintf(stderr, "stream %p: peer send shutdown\n", s);
		break;
	case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
		fprintf(stderr, "stream %p: shutdown complete\n", s);
		if (! ev->SHUTDOWN_COMPLETE.AppCloseInProgress)
			MsQuic->StreamClose(s);
		tp_count_final_stats(&tmsc->tmsc_recv_count);
		tp_count_final_stats(&tmsc->tmsc_sent_count);
		tp_msquic_stream_context_destroy(ctx);
		break;
	default:
		break;
	}
	return QUIC_STATUS_SUCCESS;
}

static void
tp_msquic_connection_shutdown(HQUIC c, void *ctx, QUIC_CONNECTION_EVENT *ev)
{

	if (ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE)
		fprintf(stderr, "connection %p: properly shutdown on idle\n", c);
	else
		fprintf(stderr, "connection %p: shutdown by transport: 0x%x\n",
		    c, ev->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
}

static void
tp_msquic_connection_shutdown_by_peer(HQUIC c, void *ctx, QUIC_CONNECTION_EVENT *ev)
{

	fprintf(stderr, "connection %p: shutdown by peer: error code=0x%llu\n",
	    c, ev->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
}

static void
tp_msquic_connection_shutdown_complete(HQUIC c, void *ctx, QUIC_CONNECTION_EVENT *ev)
{

	fprintf(stderr, "connection %p: shutdown completed\n", c);
	if (! ev->SHUTDOWN_COMPLETE.AppCloseInProgress)
		MsQuic->ConnectionClose(c);
	/* XXX: in case of a server side, is it okay to always close??? */
}

/* XXX: only client can start stream in QUIC...??? */
static QUIC_STATUS
tp_msquic_connection_start_stream(HQUIC c)
{
	struct tp_msquic_stream_context *tmsc;
	QUIC_STATUS Status;
	HQUIC s;

	tmsc = tp_msquic_stream_context_new();
	if (tmsc == NULL) {
		warn("cannot allocate stream context");
		Status = QUIC_STATUS_OUT_OF_MEMORY;
		goto out;
	}

	Status = MsQuic->StreamOpen(c, QUIC_STREAM_OPEN_FLAG_NONE, tp_msquic_stream_callback, tmsc, &s);
	if (QUIC_FAILED(Status)) {
		warn("StreamOpen failed: 0x%x", Status);
		goto out;
	}

	Status = MsQuic->StreamStart(s, QUIC_STREAM_START_FLAG_NONE);
	if (QUIC_FAILED(Status)) {
		warn("StreamStart failed: 0x%x", Status);
		goto out;
	}
	tmsc->tmsc_total = 1; /* should send data for creating stream at peer. */

  out:
	if (QUIC_FAILED(Status)) {
		tp_msquic_stream_context_destroy(tmsc);	/* XXX: should free by stream callback??? */
		if (s != NULL)
			MsQuic->StreamClose(s);		/* XXX: should close by stream callback??? */
		MsQuic->ConnectionShutdown(c, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
	}
	return Status;
}

static QUIC_STATUS
tp_msquic_connection_accept_stream(HQUIC c, QUIC_CONNECTION_EVENT *ev)
{
	struct tp_msquic_stream_context *tmsc;
	HQUIC s = ev->PEER_STREAM_STARTED.Stream;

	tmsc = tp_msquic_stream_context_new();
	if (tmsc == NULL) {
		warn("cannot allocate stream context");
		MsQuic->StreamShutdown(s, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
		return QUIC_STATUS_OUT_OF_MEMORY;
	}
	tmsc->tmsc_total = TP_DATASIZE;	/* send from server only. */
	MsQuic->SetCallbackHandler(s, tp_msquic_stream_callback, tmsc);
	tp_msquic_stream_send(s, tmsc);
	return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
tp_msquic_client_connection_callback(HQUIC c, void *ctx, QUIC_CONNECTION_EVENT *ev)
{
	QUIC_STATUS Status;

	fprintf(stderr, "client connection: 0x%x, ctx: %p\n", ev->Type, ctx);

	Status = QUIC_STATUS_SUCCESS;
	switch (ev->Type) {
	case QUIC_CONNECTION_EVENT_CONNECTED:
		fprintf(stderr, "connection %p: connected\n", c);
		Status = tp_msquic_connection_start_stream(c);
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
		tp_msquic_connection_shutdown(c, ctx, ev);
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
		tp_msquic_connection_shutdown_by_peer(c, ctx, ev);
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
		tp_msquic_connection_shutdown_complete(c, ctx, ev);
		break;
	case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
		fprintf(stderr, "connection %p: Resumption ticket received (%u bytes):\n",
		    c, ev->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
		for (uint32_t i = 0; i < ev->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++)
		    fprintf(stderr, "%.2X", (uint8_t)ev->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
		fprintf(stderr ,"\n");
		/* XXX: should save ticket in the future. */
		break;
	case QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS:
		fprintf(stderr, "connection %p: peer needs streams\n", c);
		break;
	default:
		break;
	}
	return Status;
}

static int
tp_msquic_client(const char *dststr, const char *servstr, const char *filename,
    int argc, char * const argv[])
{
	QUIC_STATUS Status;
	QUIC_SETTINGS Settings;
	bool Unsecure = true;

	/* intialize MS QUIC */
	Status = MsQuicOpen2(&MsQuic);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot initialize MS QUIC: 0x%x\n",
		    Status);
		/*NOTREACHED*/

	Status = MsQuic->RegistrationOpen(&RegConfig, &Registration);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot open MS QUIC configuration: 0x%x\n",
		    Status);
		/*NOTREACHED*/

	/* configurations */
	memset(&Settings, 0, sizeof(Settings));
	Settings.IdleTimeoutMs = IdleTimeoutMs;
	Settings.IsSet.IdleTimeoutMs = TRUE;
	Settings.CongestionControlAlgorithm = TP_MSQUIC_DEFAULT_CC_ALG;
	Settings.IsSet.CongestionControlAlgorithm = TRUE;

	Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1,
	    &Settings, sizeof(Settings), NULL, &Configuration);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot open configuration: 0x%x\n", Status);
		/*NOTREACHED*/

	QUIC_CREDENTIAL_CONFIG CredConfig;
	memset(&CredConfig, 0, sizeof(CredConfig));
	CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
	CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
	if (Unsecure)
		CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
	Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot load credential: 0x%x\n", Status);
		/*NOTREACHED*/

	/* start client */
	HQUIC Connection;
	Status = MsQuic->ConnectionOpen(Registration, tp_msquic_client_connection_callback,
	    NULL, &Connection);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot open connection: 0x%x\n", Status);
		/*NOTREACHED*/

	fprintf(stderr, "connection %p: connecting to %s:%s\n",
	    Connection, dststr, servstr);

	Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC,
	    dststr, atoi(servstr));
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot connect to a server: 0x%x\n", Status);
		/*NOTREACHED*/

	MsQuic->ConfigurationClose(Configuration);
	MsQuic->RegistrationClose(Registration); /* block until done */
	MsQuicClose(MsQuic);

	return 0;
}

static QUIC_STATUS
tp_msquic_server_connection_callback(HQUIC c, void *ctx, QUIC_CONNECTION_EVENT *ev)
{
	QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

	fprintf(stderr, "connection callback\n");

	switch (ev->Type) {
	case QUIC_CONNECTION_EVENT_CONNECTED:
		fprintf(stderr, "connected %p\n", c);
		MsQuic->ConnectionSendResumptionTicket(c, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
		tp_msquic_connection_shutdown(c, ctx, ev);
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
		tp_msquic_connection_shutdown_by_peer(c, ctx, ev);
		break;
	case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
		tp_msquic_connection_shutdown_complete(c, ctx, ev);
		break;
	case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
		fprintf(stderr, "connection %p: local address changed\n", c);
		break;
	case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
		fprintf(stderr, "connection %p: peer address changed\n", c);
		break;
	case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
		fprintf(stderr, "connection %p: stream started: %p\n",
		    c, ev->PEER_STREAM_STARTED.Stream);
		Status = tp_msquic_connection_accept_stream(c, ev);
		break;
	case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
		fprintf(stderr, "connection %p: stream available\n", c);
		break;
	case QUIC_CONNECTION_EVENT_RESUMED:
		fprintf(stderr, "connection %p: resumed\n", c);
		break;
	default:
		fprintf(stderr, "connection %p: unknown event received: %d\n",
		    c, ev->Type);
		break;
	}
	return Status;
}

static QUIC_STATUS
tp_msquic_listen_callback(HQUIC Listener, void *ctx, QUIC_LISTENER_EVENT *ev)
{
	QUIC_STATUS Status;

	(void)Listener;

	fprintf(stderr, "Listener event: %u: ctx: %p\n", ev->Type, ctx);

	switch (ev->Type) {
	case QUIC_LISTENER_EVENT_NEW_CONNECTION:
		MsQuic->SetCallbackHandler(ev->NEW_CONNECTION.Connection,
		    tp_msquic_server_connection_callback, NULL);
		Status = MsQuic->ConnectionSetConfiguration(ev->NEW_CONNECTION.Connection, Configuration);
		break;
	default:
		Status = QUIC_STATUS_NOT_SUPPORTED;
		fprintf(stderr, "not supported event: %u\n", ev->Type);
		break;
	}

	return Status;
}

static int
tp_msquic_server_config(const char *cert, const char *key)
{
	QUIC_SETTINGS Settings;

	memset(&Settings, 0, sizeof(Settings));
	Settings.IdleTimeoutMs = IdleTimeoutMs;
	Settings.IsSet.IdleTimeoutMs = TRUE;
	Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
	Settings.IsSet.ServerResumptionLevel = TRUE;
	Settings.PeerBidiStreamCount = 1;
	Settings.IsSet.PeerBidiStreamCount = TRUE;
	Settings.CongestionControlAlgorithm = TP_MSQUIC_DEFAULT_CC_ALG;
	Settings.IsSet.CongestionControlAlgorithm = TRUE;
#if 0
	Settings.SendBufferingEnabled = 1;
	Settings.IsSet.SendBufferingEnabled = TRUE;
	Settings.MaxAckDelayMs = 100;
	Settings.IsSet.MaxAckDelayMs = TRUE;
	Settings.MaximumMtu = 65535;
	Settings.IsSet.MaximumMtu = TRUE;
	Settings.MinimumMtu = 65535;
	Settings.IsSet.MinimumMtu = TRUE;
#endif /* 0 */

	QUIC_CERTIFICATE_FILE CertFile;
	memset(&CertFile, 0, sizeof(CertFile));
	CertFile.CertificateFile = cert;
	CertFile.PrivateKeyFile = key;

	QUIC_CREDENTIAL_CONFIG CredConfig;
	memset(&CredConfig, 0, sizeof(CredConfig));
	CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
	CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
	CredConfig.CertificateFile = &CertFile;
	
	QUIC_STATUS Status;
	Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1,
	    &Settings, sizeof(Settings), NULL, &Configuration);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot open configuration: 0x%x\n", Status);
		/*NOTREACHED*/

	Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot load credential: 0x%0x\n", Status);
		/*NOTREACHED*/

	return 0;
}

static int
tp_msquic_server(const char *dststr, const char *servstr, const char *filename,
    int argc, char * const argv[])
{
	const char *cert;
	const char *key;
#ifdef HAVE_UDP_GSO
	int do_not_use_gso = 0;
#else /* HAVE_UDP_GSO */
	int do_not_use_gso = 1;
#endif /* ! HAVE_UDP_GSO */
	QUIC_ADDR Address;
	QUIC_STATUS Status;
	HQUIC Listener;

	if (argc < 2)
		errx(EX_USAGE, "missing certificate or key file for QUIC TLS");
	cert = argv[0];
	key = argv[1];
	argc -= 2;
	argv += 2;

	if (argc != 0)
		errx(EX_USAGE, "extra argument(s)");

	(void)do_not_use_gso;

	Status = MsQuicOpen2(&MsQuic);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot initialize MS QUIC: 0x%x\n",
		    Status);
		/*NOTREACHED*/

	Status = MsQuic->RegistrationOpen(&RegConfig, &Registration);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot open MS QUIC configuration: 0x%x\n",
		    Status);
		/*NOTREACHED*/

	tp_msquic_server_config(cert, key);

	Listener = NULL;
	Status = MsQuic->ListenerOpen(Registration, tp_msquic_listen_callback, filename /* XXX */, &Listener);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot open MS QUIC listenr: 0x%x\n", Status);
		/*NOTREACHED*/

	memset(&Address, 0, sizeof(Address));
	QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
	QuicAddrSetPort(&Address, atoi(servstr));

	Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address);
	if (QUIC_FAILED(Status))
		err(EX_SOFTWARE, "cannot start MS QUIC listenr: 0x%x\n", Status);
		/*NOTREACHED*/

	fprintf(stderr, "press any key to exit\n");

	getchar();

	fprintf(stderr, "done\n");

	MsQuic->ListenerClose(Listener);

	return 0;
}

void
tp_msquic_init(void)
{

	(void)tp_handle_register("msquic", tp_msquic_client, tp_msquic_server);
}
