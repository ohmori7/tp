#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "tp.h"

static struct tp_protomap {
	const char *tpp_s;
	enum tp_proto tpp_proto;
} tp_protomaps[] = {
	{ "udp",	TP_UDP },
	{ "tcp",	TP_TCP },
	{ "sctp",	TP_SCTP },
	{ "quic",	TP_QUIC },
	{ NULL, 0 },
};

static int
tp_socket_type_aton(const char *protostr)
{
	const struct tp_protomap *tpp;

	for (tpp = tp_protomaps; tpp->tpp_s != NULL; tpp++)
		if (strcmp(tpp->tpp_s, protostr) == 0)
			return tpp->tpp_proto;
	return -1;
}

static int
tp_socket_type(const char *protostr)
{

	switch (tp_socket_type_aton(protostr)) {
	case TP_UDP:
		return SOCK_DGRAM;
		break;
	case TP_TCP:
		return SOCK_STREAM;
		break;
	case TP_SCTP:
	case TP_QUIC:
	default:
		errx(EXIT_FAILURE, "unknown protocol: %s", protostr);
		/*NOTREACHED*/
	}
}

static int
tp_socket(const char *protostr, const char *addrstr, const char *srvstr,
    int (*fn)(int, const struct sockaddr *, socklen_t))
{
	struct addrinfo hints, *res, *res0;
	const char *cause;
	int s, error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = tp_socket_type(protostr);
	error = getaddrinfo(addrstr, srvstr, &hints, &res0);
	if (error)
		errx(EXIT_FAILURE, "%s", gai_strerror(error));
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
		err(EXIT_FAILURE, "%s", cause);
		/*NOTEACHED*/

	freeaddrinfo(res0);

	return s;
}

int
tp_connect(const char *protostr, const char *dststr, const char *dsrvstr)
{

	return tp_socket(protostr, dststr, dsrvstr, connect);
}

int
tp_bind(const char *protostr, const char *addrstr, const char *srvstr)
{

	return tp_socket(protostr, addrstr, srvstr, bind);
}
