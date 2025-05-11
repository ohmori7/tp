#include <err.h>
#include <signal.h>
#include <sysexits.h>
#include <unistd.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "tp.h"
#include "tp_option.h"
#include "tp_clock.h"
#include "tp_handle.h"
#include "tp_tcp.h"
#include "tp_tls.h"
#include "tp_picoquic.h"
#include "tp_msquic.h"

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
	struct tp_option to;
	struct tp_handle *th;
	int ch, error;
	bool cflag;

#ifndef HAVE_GETPROGNAME
	setprogname(argv[0]);
#endif /* ! HAVE_GETPROGNAME */

	cflag = false;
	tp_option_init(&to);
	while ((ch = getopt(argc, argv, "c:f:hp:t:B:")) != -1) {
		switch (ch) {
		case 'c':
			cflag = true;
			to.to_addrname = optarg;
			break;
		case 'f':
			to.to_filename = optarg;
			break;
		case 'p':
			to.to_servicename = optarg;
			break;
		case 'B':
			to.to_addrname = optarg;	/* XXX */
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
		to.to_protoname = argv[0];
		argc--;
		argv++;
	}

	tp_clock_init();

	tp_tcp_init();
	tp_tls_init();
	tp_picoquic_init();
	tp_msquic_init();

	th = tp_handle_lookup_by_name(to.to_protoname);
	if (th == NULL)
		usage("unknown protocol: %s\n", to.to_protoname);
		/*NOTREACHED*/

	/* XXX: this doesn't work on macOS... */
	(void)signal(SIGINT, sigint);

	if (cflag)
		error = tp_handle_client(th, &to, argc, argv);
	else
		error = tp_handle_server(th, &to, argc, argv);

	return error;
}
