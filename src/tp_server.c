#include <sys/socket.h>	/* XXX: send() */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "tp.h"

int
tp_server_main(const char *protostr, const char *dststr, const char *srvstr)
{
	struct tp *ltp, *tp;

	ltp = tp_listen(protostr, dststr, srvstr);
	if (ltp == NULL)
		errx(EXIT_FAILURE, "cannot prepare for socket");
		/*NOTREACHED*/

	for (;;) {
		tp = tp_accept(ltp);
		if (tp == NULL)
			continue;
		while (tp_recv(tp) != (ssize_t)-1)
			;
		tp_free(tp);
		fprintf(stderr, "done");
	}

	return 0;
}
