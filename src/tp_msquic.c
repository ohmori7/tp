#include <err.h>
#include <sysexits.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "tp_handle.h"

#include "msquic.h"

const uint64_t IdleTimeoutMs = 10000;

const QUIC_API_TABLE *MsQuic;
const QUIC_REGISTRATION_CONFIG RegConfig = { "tp_msquic", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
HQUIC Registration;
const QUIC_BUFFER Alpn = { sizeof("tp_msquic") - 1, (uint8_t *)"tp_msquic" };
HQUIC Configuration;

static QUIC_STATUS
tp_msquic_stream_send(HQUIC s, void *ctx)
{

	return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS
tp_msquic_stream_callback(HQUIC s, void *ctx, QUIC_STREAM_EVENT *ev)
{

	fprintf(stderr, "stream %p: event 0x%x\n", s, ev->Type);

	switch (ev->Type) {
	case QUIC_STREAM_EVENT_START_COMPLETE:
		fprintf(stderr, "stream %p: start complete\n", s);
		return tp_msquic_stream_send(s, ctx);
	case QUIC_STREAM_EVENT_SEND_COMPLETE:
		fprintf(stderr, "stream %p: send complete\n", s);
		return tp_msquic_stream_send(s, ctx);
	case QUIC_STREAM_EVENT_RECEIVE:
		fprintf(stderr, "stream %p: receive\n", s);
		break;
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

static QUIC_STATUS
tp_msquic_connection_send_start(HQUIC c, void *ctx)
{
	QUIC_STATUS Status;
	HQUIC s;

	Status = MsQuic->StreamOpen(c, QUIC_STREAM_OPEN_FLAG_NONE, tp_msquic_stream_callback, ctx, &s);
	if (QUIC_FAILED(Status)) {
		warn("StreamOpen failed: 0x%x", Status);
		goto out;
	}

	Status = MsQuic->StreamStart(s, QUIC_STREAM_START_FLAG_NONE);
	if (QUIC_FAILED(Status)) {
		warn("StreamStart failed: 0x%x", Status);
		goto out;
	}

  out:
	if (QUIC_FAILED(Status)) {
		if (s != NULL)
			MsQuic->StreamClose(s);
		MsQuic->ConnectionShutdown(c, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
	}
	return Status;
}

static QUIC_STATUS
tp_msquic_client_connection_callback(HQUIC c, void *ctx, QUIC_CONNECTION_EVENT *ev)
{

	fprintf(stderr, "client connection: 0x%x\n", ev->Type);

	switch (ev->Type) {
	case QUIC_CONNECTION_EVENT_CONNECTED:
		fprintf(stderr, "connection %p: connected\n", c);
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
		break;
	case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
		fprintf(stderr, "connection %p: stream %p: started\n",
		    c, ev->PEER_STREAM_STARTED.Stream);
		MsQuic->SetCallbackHandler(ev->PEER_STREAM_STARTED.Stream,
		    tp_msquic_stream_callback, ctx);
		break;
	default:
		break;
	}
	return QUIC_STATUS_SUCCESS;
}

static int
tp_msquic_client(const char *dststr, const char *servstr,
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

	fprintf(stderr, "connection callback\n");

	switch (ev->Type) {
	case QUIC_CONNECTION_EVENT_CONNECTED:
		fprintf(stderr, "connected %p\n", c);
		MsQuic->ConnectionSendResumptionTicket(c, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
		tp_msquic_connection_send_start(c, ctx);
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
	case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
		fprintf(stderr, "connection %p: stream started: %p\n",
		    c, ev->PEER_STREAM_STARTED.Stream);
		MsQuic->SetCallbackHandler(ev->PEER_STREAM_STARTED.Stream,
		    tp_msquic_stream_callback, ctx);
		break;
	case QUIC_CONNECTION_EVENT_RESUMED:
		fprintf(stderr, "connection %p: resumed\n", c);
		break;
	case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED:
		fprintf(stderr, "connection %p: local address changed\n", c);
		break;
	case QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED:
		fprintf(stderr, "connection %p: peer address changed\n", c);
		break;
	case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE:
		fprintf(stderr, "connection %p: stream available\n", c);
		break;
	default:
		fprintf(stderr, "connection %p: unknown event received: %d\n",
		    c, ev->Type);
		break;
	}

	return 0;
}

static QUIC_STATUS
tp_msquic_listen_callback(HQUIC Listener, void *ctx, QUIC_LISTENER_EVENT *ev)
{
	QUIC_STATUS Status;

	(void)Listener, (void)ctx;

	fprintf(stderr, "Listener event: %u\n", ev->Type);

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
tp_msquic_server(const char *dststr, const char *servstr,
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
	Status = MsQuic->ListenerOpen(Registration, tp_msquic_listen_callback, NULL, &Listener);
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
