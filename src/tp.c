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
	struct sockaddr *tp_sa;
	struct tp_count tp_recv, tp_sent;
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

static struct sockaddr *
tp_sockaddr_dup(const struct sockaddr *sa0, socklen_t salen)
{
	struct sockaddr *sa;

	sa = malloc(salen);
	memcpy(sa, sa0, salen);

	return sa;
}

static struct tp *
tp_init(enum tp_proto proto, struct sockaddr *sa, socklen_t salen)
{
	struct tp *tp;

	tp = malloc(sizeof(*tp));
	if (tp == NULL)
		return NULL;
	tp->tp_proto = proto;
	tp->tp_sock = -1;
	tp->tp_sa = tp_sockaddr_dup(sa, salen);
	if (tp->tp_sa == NULL) {
		tp_free(tp);
		return NULL;
	}
	tp_count_init(&tp->tp_recv, "recv");
	tp_count_init(&tp->tp_sent, "sent");
	return tp;
}

void
tp_free(struct tp *tp)
{

	if (tp->tp_sock != -1)
		(void)close(tp->tp_sock);
	if (tp->tp_sa != NULL)
		free(tp->tp_sa);
	free(tp);
}

static struct tp *
tp_socket(const char *protostr, const char *addrstr, const char *srvstr,
    int (*fn)(int, const struct sockaddr *, socklen_t))
{
	struct tp *tp;
	struct addrinfo hints, *res, *res0;
	const char *cause;
	int s, error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = tp_socket_type(tp_proto_aton(protostr));
	error = getaddrinfo(addrstr, srvstr, &hints, &res0);
	if (error)
		errx(EX_DATAERR, "%s", gai_strerror(error));
		/*NOTREACHED*/

	s = -1;
	cause = NULL;
	for (res = res0; res != NULL; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}
		error = fn(s, res->ai_addr, res->ai_addrlen);
		if (error == -1) {
			cause = "connect";
			(void)close(s);
			s = -1;
			continue;
		}
		/* XXX: options. */
		break;
	}
	if (s == -1)
		err(EX_OSERR, "%s", cause);
		/*NOTEACHED*/

	tp = tp_init(tp_proto_aton(protostr),
		res->ai_addr, res->ai_addrlen);
	if (tp == NULL)
		err(EX_OSERR, "cannot create socket structure");
		/*NOTEACHED*/
	tp->tp_sock = s;

	freeaddrinfo(res0);

	return tp;
}

struct tp *
tp_connect(const char *protostr, const char *dststr, const char *dsrvstr)
{

	return tp_socket(protostr, dststr, dsrvstr, connect);
}

struct tp *
tp_listen(const char *protostr, const char *addrstr, const char *srvstr)
{
	struct tp *tp;
	int error;

	tp = tp_socket(protostr, addrstr, srvstr, bind);
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
	tp = tp_init(ltp->tp_proto, (struct sockaddr *)&ss, sslen);
	if (tp == NULL) {
		(void)close(s);
		return NULL;
	}
	tp->tp_sock = s;

	return tp;
}

ssize_t
tp_send(struct tp *tp)
{
	char buf[TP_MSS];
	ssize_t len;

	len = send(tp->tp_sock, buf, sizeof(buf), 0);
	if (len == 0)
		return (ssize_t)-1;

	tp_count_inc(&tp->tp_sent, len);

	if (len == (ssize_t)-1)
		switch (errno) {
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif /* EAGAIN != EWOULDBLOCK */
			return 0;
		default:
			err(EX_OSERR, "send failed");
			break;
		}
	return len;
}

ssize_t
tp_recv(struct tp *tp)
{
	char buf[TP_MSS];
	ssize_t len;

	len = recv(tp->tp_sock, buf, sizeof(buf), 0);
	if (len == 0) {
		perror("connection closed");
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
