#include <sys/socket.h>	/* XXX: send() */
#include <err.h>
#include <stdlib.h>

#include <errno.h>	/* XXX */

#include "tp.h"

int
tp_client_main(const char *protostr, const char *dststr, const char *srvstr)
{
	char buf[TP_SEGSIZE - TP_IPHDRLEN - TP_UDPHDRLEN];
	int s;
	ssize_t len;

	s = tp_connect(protostr, dststr, srvstr);
	if (s == -1)
		errx(EXIT_FAILURE, "cannot connect to the server");

	for (;;) {
		len = send(s, buf, sizeof(buf), 0);
		if (len == (ssize_t)-1)
			switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif /* EAGAIN != EWOULDBLOCK */
				break;
			default:
				err(EXIT_FAILURE, "send failed");
				break;
			}
	}

	return 0;
}
