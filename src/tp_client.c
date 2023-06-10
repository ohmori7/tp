#include <sys/types.h>
#include <err.h>
#include <stdlib.h>

#include "tp.h"

int
tp_client_main(const char *protostr, const char *dststr, const char *srvstr)
{
	struct tp *tp;

	tp = tp_connect(protostr, dststr, srvstr);
	if (tp == NULL)
		errx(EXIT_FAILURE, "cannot connect to the server");

	for (;;)
		if (tp_send(tp) == -1)
			break;

	return 0;
}
