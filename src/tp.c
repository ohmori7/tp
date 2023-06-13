#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <sysexits.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tp.h"
#include "tp_count.h"

struct tp {
	enum tp_proto tp_proto;
	int tp_sock;
	struct tp_count tp_recv, tp_sent;
	size_t tp_buflen;
	uint8_t tp_buf[TP_MSS];
};

static struct tp_protomap {
	const char *tpp_s;
	enum tp_proto tpp_proto;
} tp_protomaps[] = {
	{ "udp",	TP_UDP },
	{ "tcp",	TP_TCP },
	{ "tls",	TP_TLS },
	{ "sctp",	TP_SCTP },
	{ "quic",	TP_QUIC },
	{ NULL, 0 },
};

int
tp_proto_aton(const char *protostr)
{
	const struct tp_protomap *tpp;

	for (tpp = tp_protomaps; tpp->tpp_s != NULL; tpp++)
		if (strcmp(tpp->tpp_s, protostr) == 0)
			return tpp->tpp_proto;
	return -1;
}

static int
tp_socket_type(enum tp_proto proto)
{

	switch (proto) {
	case TP_UDP:
		return SOCK_DGRAM;
		break;
	case TP_TCP:
	case TP_TLS:
		return SOCK_STREAM;
		break;
	case TP_SCTP:
	case TP_QUIC:
	default:
		errx(EX_SOFTWARE, "unknown protocol: %u", proto);
		/*NOTREACHED*/
	}
}

void *
tp_buf(struct tp *tp)
{

	return tp->tp_buf;
}

static struct tp *
tp_init(enum tp_proto proto)
{
	struct tp *tp;

	tp = malloc(sizeof(*tp));
	if (tp == NULL)
		return NULL;
	tp->tp_proto = proto;
	tp->tp_sock = -1;
	tp_count_init(&tp->tp_recv, "recv");
	tp_count_init(&tp->tp_sent, "sent");
	tp->tp_buflen = sizeof(tp->tp_buf);
	return tp;
}

void
tp_free(struct tp *tp)
{

	if (tp->tp_sock != -1)
		(void)close(tp->tp_sock);
	free(tp);
}

int
tp_name_resolve(int socktype, const char *addrstr, const char *srvstr,
    int (*cb)(const struct addrinfo *, void *), void *arg)
{
	struct addrinfo hints, *res, *res0;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = socktype;
	error = getaddrinfo(addrstr, srvstr, &hints, &res0);
	if (error != 0)
		errx(EX_DATAERR, "%s", gai_strerror(error));
		/*NOTREACHED*/

	error = -1;
	for (res = res0; res != NULL; res = res->ai_next)
		if ((error = (*cb)(res, arg)) == 0)
			break;
	return error;
}

struct tp_socket_cb_arg {
	int (*tsca_cb)(int, const struct sockaddr *, socklen_t);
	const char *tsca_cbname;
	int tsca_sock;
	const char *tsca_cause;
};

static int
tp_socket_cb(const struct addrinfo *res, void *arg)
{
	struct tp_socket_cb_arg *tsca = arg;
	int s, error;

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s == -1) {
		tsca->tsca_cause = "socket";
		return -1;
	}
	error = (*tsca->tsca_cb)(s, res->ai_addr, res->ai_addrlen);
	if (error == -1) {
		(void)close(s);
		tsca->tsca_cause = tsca->tsca_cbname;
		return -1;
	}
	tsca->tsca_sock = s;
	return 0;
}

static struct tp *
tp_socket(const char *protostr, const char *addrstr, const char *srvstr,
    int (*cb)(int, const struct sockaddr *, socklen_t), const char *cbname)
{
	struct tp_socket_cb_arg tsca = { cb, cbname, -1, NULL };
	struct tp *tp;
	int error;

	error = tp_name_resolve(tp_socket_type(tp_proto_aton(protostr)),
	    addrstr, srvstr, tp_socket_cb, &tsca);
	if (error == -1)
		err(EX_OSERR, "%s", tsca.tsca_cause);
		/*NOTEACHED*/

	tp = tp_init(tp_proto_aton(protostr));
	if (tp == NULL)
		err(EX_OSERR, "cannot create socket structure");
		/*NOTEACHED*/
	tp->tp_sock = tsca.tsca_sock;

	return tp;
}

struct tp *
tp_connect(const char *protostr, const char *dststr, const char *dsrvstr)
{

	return tp_socket(protostr, dststr, dsrvstr, connect, "connect");
}

struct tp *
tp_listen(const char *protostr, const char *addrstr, const char *srvstr)
{
	struct tp *tp;
	int error;

	tp = tp_socket(protostr, addrstr, srvstr, bind, "bind");
	if (tp == NULL)
		return NULL;

	error = listen(tp->tp_sock, 5 /* XXX */);
	if (error == -1)
		err(EX_OSERR, "listen failed");

	return tp;
}

struct tp *
tp_accept(struct tp *ltp)
{
	struct tp *tp;
	struct sockaddr_storage ss;
	socklen_t sslen;
	int s;

	s = accept(ltp->tp_sock, (struct sockaddr*)&ss, &sslen);
	if (s == -1) {
		perror("accept failed");
		return NULL;
	}
	tp = tp_init(ltp->tp_proto);
	if (tp == NULL) {
		(void)close(s);
		return NULL;
	}
	tp->tp_sock = s;

	return tp;
}

ssize_t
tp_write(struct tp *tp, void *data, size_t datalen)
{
	ssize_t len;

  again:
	len = write(tp->tp_sock, data, datalen);
	if (len != (ssize_t)-1)
		switch (errno) {
		case EINTR:
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif /* EAGAIN != EWOULDBLOCK */
			goto again;
		}
	return len;
}

ssize_t
tp_send(struct tp *tp)
{
	ssize_t len;

	len = tp->tp_buflen;
	if (tp->tp_sent.tpc_total_bytes + len > TP_DATASIZE)
		len = TP_DATASIZE - tp->tp_sent.tpc_total_bytes;

	len = send(tp->tp_sock, tp->tp_buf, len, 0);
	if (len == 0)
		return (ssize_t)-1;

	tp_count_inc(&tp->tp_sent, len);

	if (tp->tp_sent.tpc_total_bytes >= TP_DATASIZE) {
		tp_count_finalize(&tp->tp_sent);
		tp_count_final_stats(&tp->tp_sent);
		return (ssize_t)-1;	/* done */
	}

	if (len == (ssize_t)-1)
		switch (errno) {
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif /* EAGAIN != EWOULDBLOCK */
			return 0;
		default:
			perror("send failed");
			break;
		}
	return len;
}

ssize_t
tp_recv(struct tp *tp)
{
	ssize_t len;

	len = recv(tp->tp_sock, tp->tp_buf, tp->tp_buflen, 0);
	if (len == 0) {
		fprintf(stderr, "connection closed\n");
		tp_count_finalize(&tp->tp_recv);
		tp_count_final_stats(&tp->tp_recv);
		return (ssize_t)-1;
	}

	tp_count_inc(&tp->tp_recv, len);

	if (len == (ssize_t)-1)
		switch (errno) {
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif /* EAGAIN != EWOULDBLOCK */
			return 0;
		default:
			perror("recv failed");
			break;
		}

	return len;
}
