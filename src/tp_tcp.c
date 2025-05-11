#include <err.h>
#include <sysexits.h>
#include <stdio.h>

#include "tp.h"
#include "tp_option.h"
#include "tp_handle.h"

static int
tp_tcp_client(struct tp_option *to, int argc, char * const argv[])
{
	struct tp *tp;

	fprintf(stderr, "connect to %s.%s using %s\n",
	    to->to_addrname, to->to_servicename, to->to_protoname);

	tp = tp_connect(to);
	if (tp == NULL)
		errx(EX_OSERR, "cannot connect to the server");
		/*NOTREACHED*/

	while (tp_recv(tp, 0) != (ssize_t)-1)
		;

	return 0;
}

static int
tp_tcp_server(struct tp_option *to, int argc, char * const argv[])
{
	struct tp *ltp, *tp;

	fprintf(stderr, "waiting on %s.%s using %s\n",
	    to->to_addrname, to->to_servicename, to->to_protoname);

	ltp = tp_listen(to);
	if (ltp == NULL)
		errx(EX_OSERR, "cannot prepare for socket");
		/*NOTREACHED*/

	for (;;) {
		tp = tp_accept(ltp);
		if (tp == NULL)
			continue;

		fprintf(stderr, "connected\n");

		while (tp_send(tp) != (ssize_t)-1)
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
