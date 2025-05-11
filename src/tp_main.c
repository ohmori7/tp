#include <err.h>
#include <signal.h>
#include <sysexits.h>
#include <unistd.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "tp.h"
#include "tp_clock.h"
#include "tp_handle.h"
#include "tp_tcp.h"
#include "tp_tls.h"
#include "tp_picoquic.h"
#include "tp_msquic.h"

#define	TP_DEFAULT_PROTO	"tcp"
#define	TP_DEFAULT_ADDR		"127.0.0.1"
#define	TP_DEFAULT_SERVICE	"12345"

#ifdef Linux
/* XXX: NetBSD and macOS (OpenBSD/FreeBSD as well?) */
#define HAVE_GETPROGNAME
#endif /* Linux */

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

void
sigint(int sig)
{

	fprintf(stderr, "caught signal %d\n", sig);
	exit(EX_USAGE);
}

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
Usage:\n\
	%s: [-h] [-c <destination>] [-p <port>] [-B <local IP address>] [<transport>]\n\
\n\
Examples:\n\
	%s\n\
	%s -c localhost\n\
	%s picoquic certificate key\n\
	%s -c localhost picoquic\n\
",
	    getprogname(),
	    getprogname(),
	    getprogname(),
	    getprogname(),
	    getprogname()
	    );
	exit(EX_USAGE);
}

int
main(int argc, char * const argv[])
{
	const char *protostr = TP_DEFAULT_PROTO;
	const char *addrstr = TP_DEFAULT_ADDR;
	const char *servstr = TP_DEFAULT_SERVICE;
	const char *filename = NULL;
	struct tp_handle *th;
	int ch, error;
	bool cflag;

#ifndef HAVE_GETPROGNAME
	setprogname(argv[0]);
#endif /* ! HAVE_GETPROGNAME */

	cflag = false;
	while ((ch = getopt(argc, argv, "c:f:hp:t:B:")) != -1) {
		switch (ch) {
		case 'c':
			cflag = true;
			addrstr = optarg;
			break;
		case 'f':
			filename = optarg;
			break;
		case 'p':
			servstr = optarg;
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

	if (argc > 0) {
		protostr = argv[0];
		argc--;
		argv++;
	}

	tp_clock_init();

	tp_tcp_init();
	tp_tls_init();
	tp_picoquic_init();
	tp_msquic_init();

	th = tp_handle_lookup_by_name(protostr);
	if (th == NULL)
		usage("unknown protocol: %s\n", protostr);
		/*NOTREACHED*/

	/* XXX: this doesn't work on macOS... */
	(void)signal(SIGINT, sigint);

	if (cflag)
		error = tp_handle_client(th, addrstr, servstr, filename, argc, argv);
	else
		error = tp_handle_server(th, addrstr, servstr, filename, argc, argv);

	return error;
}
