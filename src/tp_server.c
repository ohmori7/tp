#include <sys/socket.h>	/* XXX: send() */
#include <err.h>
#include <sysexits.h>
#include <stdio.h>

#include "tp.h"

int
tp_server_main(const char *protostr, const char *dststr, const char *srvstr)
{
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
