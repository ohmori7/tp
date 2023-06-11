#include <err.h>
#include <sysexits.h>
#include <stdio.h>

#include "tp.h"
#include "tp_handle.h"

static int
tp_tcp_client(const char *dststr, const char *srvstr,
    int argc, char * const argv[])
{
	const char *protostr = "tcp";
	struct tp *tp;

	fprintf(stderr, "connect to %s.%s using %s\n", dststr, srvstr, protostr);

	tp = tp_connect(protostr, dststr, srvstr);
	if (tp == NULL)
		errx(EX_OSERR, "cannot connect to the server");
		/*NOTREACHED*/

	for (;;)
		if (tp_send(tp) == -1)
			break;

	return 0;
}

static int
tp_tcp_server(const char *dststr, const char *srvstr,
    int argc, char * const argv[])
{
	const char *protostr = "tcp";
	struct tp *ltp, *tp;

	fprintf(stderr, "waiting on %s.%s using %s\n", dststr, srvstr, protostr);

	ltp = tp_listen(protostr, dststr, srvstr);
	if (ltp == NULL)
		errx(EX_OSERR, "cannot prepare for socket");
		/*NOTREACHED*/

	for (;;) {
		tp = tp_accept(ltp);
		if (tp == NULL)
			continue;

		fprintf(stderr, "connected\n");

		while (tp_recv(tp) != (ssize_t)-1)
			;

		fprintf(stderr, "disconnected\n");

		tp_free(tp);
	}

	return 0;
}

void
tp_tcp_init(void)
{

	(void)tp_handle_register("tcp", tp_tcp_client, tp_tcp_server);
}
