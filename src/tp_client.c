#include <sys/types.h>
#include <err.h>
#include <sysexits.h>

#include <stdio.h>

#include "tp.h"

int
tp_client_main(const char *protostr, const char *dststr, const char *srvstr)
{
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
