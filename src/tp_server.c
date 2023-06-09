#include <sys/socket.h>	/* XXX: send() */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>	/* XXX */

#include "tp.h"

int
tp_server_main(const char *protostr, const char *dststr, const char *srvstr)
{
	char buf[TP_SEGSIZE - TP_IPHDRLEN - TP_UDPHDRLEN];
	int s, error;

	s = tp_bind(protostr, dststr, srvstr);
	if (s == -1)
		errx(EXIT_FAILURE, "cannot prepare for socket");
		/*NOTREACHED*/

	error = listen(s, 5 /* XXX */);
	if (error == -1)
		err(EXIT_FAILURE, "listen failed");

	for (;;) {
		int as;
		struct sockaddr_storage ss;
		socklen_t sslen;

		as = accept(s, (struct sockaddr *)&ss, &sslen);
		if (as == -1)
			continue;

		for (;;) {
			ssize_t len;

			len = recv(as, buf, sizeof(buf), 0);
			if (len == (ssize_t)-1)
				switch (errno) {
				case EAGAIN:
#if EAGAIN != EWOULDBLOCK
				case EWOULDBLOCK:
#endif /* EAGAIN != EWOULDBLOCK */
					break;
				default:
					perror("recv failed");
					goto out;
					break;
				}
		}
  out:
		/* XXX: i don't know, but requires on macOS compilation. */
		;
	}

	return 0;
}
