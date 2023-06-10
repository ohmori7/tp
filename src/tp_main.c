#include <sys/types.h>	/* XXX: ssize_t... */
#include <unistd.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "tp.h"

#define	TP_DEFAULT_PROTO	"tcp"
#define	TP_DEFAULT_ADDR		"127.0.0.1"
#define	TP_DEFAULT_SERVICE	"12345"

/* XXX: NetBSD and macOS (OpenBSD/FreeBSD as well?) */
#define HAVE_GETPROGNAME

#ifndef HAVE_GETPROGNAME
static const char *progname;

void
setprogname(const char *name)
{
	const char *cp;
	int ch;

	if (progname != NULL)
		return;

	progname = cp = name;
	while ((ch = *cp++) != '\0')
		if (ch == '/')	/* XXX: UNIX-like OS dependent */
			progname = cp;
}

const char *
getprogname(void)
{

	return progname;
}
#endif /* ! HAVE_GET_PROGNAME */

static void
usage(const char *errfmt, ...)
{

	if (errfmt != NULL) {
		va_list ap;

		fprintf(stderr, "ERROR: ");
		va_start(ap, errfmt);
		vfprintf(stderr, errfmt, ap);
		va_end(ap);
	}
	fprintf(stderr, "\
Usage:\
	%s: [-h] [-c <destination>] [-p <port>] [-t <transport>] [-B <local IP address>]\n\
",
	    getprogname());
	exit(EXIT_FAILURE);
}

int
main(int argc, char * const argv[])
{
	const char *protostr = TP_DEFAULT_PROTO;
	const char *addrstr = TP_DEFAULT_ADDR;
	const char *servstr = TP_DEFAULT_SERVICE;
	int ch;
	bool cflag;

#ifndef HAVE_GETPROGNAME
	setprogname(argv[0]);
#endif /* ! HAVE_GETPROGNAME */

	cflag = false;
	while ((ch = getopt(argc, argv, "c:hp:t:B:")) != -1) {
		switch (ch) {
		case 'c':
			cflag = true;
			addrstr = optarg;
			break;
		case 'p':
			servstr = optarg;
			break;
		case 't':
			protostr = optarg;
			break;
		case 'B':
			addrstr = optarg;	/* XXX */
			break;
		case '?':
		case 'h':
		default:
			usage(NULL);
			/*NOTREACHED*/
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage("extra argument: %s\n", argv[0]);
		/*NOTREACHED*/

	if (cflag)
		tp_server_main(protostr, addrstr, servstr);
	else
		tp_client_main(protostr, addrstr, servstr);

	return 0;
}
