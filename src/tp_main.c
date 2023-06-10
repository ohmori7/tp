#include <sys/types.h>	/* XXX: ssize_t... */

#include "tp.h"

#define	TP_DEFAULT_PROTO	"tcp"
#define	TP_DEFAULT_ADDR		"127.0.0.1"
#define	TP_DEFAULT_SERVICE	"12345"

int
main(int argc, char * const argv[])
{
	const char *protostr = TP_DEFAULT_PROTO;
	const char *addrstr = TP_DEFAULT_ADDR;
	const char *servstr = TP_DEFAULT_SERVICE;

	/* XXX */
	if (argc == 1)
		tp_server_main(protostr, addrstr, servstr);
	else
		tp_client_main(protostr, addrstr, servstr);

	return 0;
}
