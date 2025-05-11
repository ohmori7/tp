#include <sys/param.h>
/* XXX: better to automatically detect by cmake or automake... */
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(linux)
#define HAVE_TCP_INFO
#define HAVE_TCP_CONGESTION
#endif

#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_TCP_INFO
#if defined(linux)
#include <linux/tcp.h>
#endif /* linux */
#endif /* HAVE_TCP_INFO */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
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
	void *tp_ctx;
	int tp_fd;
	const char *tp_filename;
	ssize_t (*tp_recv)(struct tp *, int, void *, size_t, int);
	ssize_t (*tp_send)(struct tp *, int, const void *, size_t, int);
	struct tp_count tp_count_recv, tp_count_sent;
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

static ssize_t
_tp_recv(struct tp *tp, int sock, void *data, size_t datalen, int flags)
{

	return recv(sock, data, datalen, flags);
}

static ssize_t
_tp_send(struct tp *tp, int sock, const void *data, size_t datalen, int flags)
{

	return send(sock, data, datalen, flags);
}

static struct tp *
tp_init(enum tp_proto proto, const char *filename)
{
	struct tp *tp;

	tp = malloc(sizeof(*tp));
	if (tp == NULL)
		return NULL;
	tp->tp_proto = proto;
	tp->tp_sock = -1;
	tp->tp_ctx = NULL;
	tp->tp_fd = -1;
	tp->tp_filename = filename;	/* XXX: should do strdup()??? */
	tp->tp_recv = _tp_recv;
	tp->tp_send = _tp_send;
	tp->tp_filename = filename;
	tp_count_init(&tp->tp_count_recv, "recv");
	tp_count_init(&tp->tp_count_sent, "sent");
	tp->tp_buflen = sizeof(tp->tp_buf);
	return tp;
}

void
tp_free(struct tp *tp)
{

	if (tp->tp_sock != -1)
		(void)close(tp->tp_sock);
	if (tp->tp_fd != -1)
		(void)close(tp->tp_fd);
	free(tp);
}

void
tp_set_context(struct tp *tp, void *ctx)
{

	tp->tp_ctx = ctx;
}

void *
tp_get_context(struct tp *tp)
{

	return tp->tp_ctx;
}

void
tp_set_recv(struct tp *tp, ssize_t (*cb)(struct tp *, int, void *, size_t, int))
{

	tp->tp_recv = cb;
}

void
tp_set_send(struct tp *tp, ssize_t (*cb)(struct tp *, int, const void *, size_t, int))
{

	tp->tp_send = cb;
}

int
tp_set_cc(struct tp *tp)
{
#ifdef HAVE_TCP_CONGESTION
	const char *ccstr = "bbr";
	int error;

	error = setsockopt(tp->tp_sock, IPPROTO_TCP, TCP_CONGESTION, ccstr, strlen(ccstr));
	if (error == -1)
		perror("setsockopt");
	return error;
#else /* HAVE_TCP_CONGESTION */
	return -1;
#endif /* ! HAVE_TCP_CONGESTION */
}

int
tp_get_info(struct tp *tp)
{
#ifdef HAVE_TCP_INFO
	struct tcp_info ti;
	socklen_t tilen;
	int error;

	tilen = sizeof(ti);
	error = getsockopt(tp->tp_sock, IPPROTO_TCP, TCP_INFO, &ti, &tilen);
	if (error == -1)
		perror("getsockopt");
	return error;
#else /* HAVE_TCP_INFO */
	/* XXX: should set errno. */
	return -1;
#endif /* ! HAVE_TCP_INFO */
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
tp_socket(const char *protostr, const char *addrstr, const char *srvstr, const char *filename,
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

	tp = tp_init(tp_proto_aton(protostr), filename);
	if (tp == NULL)
		err(EX_OSERR, "cannot create socket structure");
		/*NOTEACHED*/
	tp->tp_sock = tsca.tsca_sock;

	return tp;
}

struct tp *
tp_connect(const char *protostr, const char *dststr, const char *dsrvstr, const char *filename)
{
	struct tp *tp;

	tp = tp_socket(protostr, dststr, dsrvstr, filename, connect, "connect");
	if (tp == NULL)
		goto bad;
	if (tp->tp_filename != NULL) {
		tp->tp_fd = open(tp->tp_filename, O_CREAT | O_TRUNC | O_WRONLY);
		if (tp->tp_fd == -1) {
			perror("file open failed");
			goto bad;
		}
	}
	return tp;
  bad:
	if (tp != NULL)
		tp_free(tp);
	return NULL;
}

static int
_tp_bind(int s, const struct sockaddr *sa, socklen_t salen)
{
	int error, on = 1;

	error = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (error != 0)
		perror("setsockopt(SO_REUSEADDR)");

	return bind(s, sa, salen);
}

struct tp *
tp_listen(const char *protostr, const char *addrstr, const char *srvstr, const char *filename)
{
	struct tp *tp;
	int error;

	tp = tp_socket(protostr, addrstr, srvstr, filename, _tp_bind, "bind");
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
		goto bad;
	}
	tp = tp_init(ltp->tp_proto, ltp->tp_filename);
	if (tp == NULL)
		goto bad;
	tp->tp_sock = s;
	if (tp->tp_filename != NULL) {
		tp->tp_fd = open(tp->tp_filename, O_RDONLY);
		if (tp->tp_fd == -1) {
			perror("file open failed");
			goto bad;
		}
	}

	return tp;
  bad:
	if (s != -1)
		(void)close(s);
	return NULL;
}

ssize_t
tp_write(struct tp *tp, const void *data, size_t datalen)
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

	if (tp->tp_fd != -1) {
		len = read(tp->tp_fd, tp->tp_buf, tp->tp_buflen);
		if (len == 0)
			return (ssize_t)-1;
	} else {
		len = tp->tp_buflen;
		if (tp->tp_count_sent.tpc_total_bytes + len > TP_DATASIZE)
			len = TP_DATASIZE - tp->tp_count_sent.tpc_total_bytes;
	}

	len = (*tp->tp_send)(tp, tp->tp_sock, tp->tp_buf, len, 0);
	if (len == 0)
		return (ssize_t)-1;

	tp_count_inc(&tp->tp_count_sent, len);

	if (tp->tp_fd == -1 && tp->tp_count_sent.tpc_total_bytes >= TP_DATASIZE) {
		tp_count_final_stats(&tp->tp_count_sent);
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
tp_recv(struct tp *tp, off_t off)
{
	ssize_t len;

	assert(tp->tp_buflen >= off);
	len = (*tp->tp_recv)(tp, tp->tp_sock, tp->tp_buf + off,
	    tp->tp_buflen - off, 0);
	if (len == 0) {
		fprintf(stderr, "connection closed\n");
		tp_count_final_stats(&tp->tp_count_recv);
		return (ssize_t)-1;
	}

	tp_count_inc(&tp->tp_count_recv, len);

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
	else if (tp->tp_fd != -1)
		if (write(tp->tp_fd, tp->tp_buf + off, len) == (ssize_t)-1)
			perror("file write failed");

	return len;
}
