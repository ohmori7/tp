#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tp.h"
#include "tp_handle.h"

struct tp_handle {
	TAILQ_ENTRY(tp_handle) th_link;
	enum tp_proto th_proto;
	const char *th_protostr;
	int (*th_client_main)(const char *, const char *, int, char * const []);
	int (*th_server_main)(const char *, const char *, int, char * const []);
};

static TAILQ_HEAD(, tp_handle) tp_handle_list =
    TAILQ_HEAD_INITIALIZER(tp_handle_list);

struct tp_handle *
tp_handle_register(const char *protostr,
    int (*client)(const char *, const char *, int, char * const []),
    int (*server)(const char *, const char *, int, char * const []))
{
	struct tp_handle *th;

	th = malloc(sizeof(*th));
	if (th == NULL)
		return NULL;

	th->th_protostr = protostr;
	th->th_client_main = client;
	th->th_server_main = server;
	TAILQ_INSERT_HEAD(&tp_handle_list, th, th_link);

	return th;
}

struct tp_handle *
tp_handle_lookup_by_name(const char *protostr)
{
	struct tp_handle *th;

	TAILQ_FOREACH(th, &tp_handle_list, th_link)
		if (strcmp(th->th_protostr, protostr) == 0)
			return th;
	return NULL;
}

int
tp_handle_client(struct tp_handle *th, const char *addrstr, const char *servstr,
    int argc, char * const argv[])
{

	return (*th->th_client_main)(addrstr, servstr, argc, argv);
}

int
tp_handle_server(struct tp_handle *th, const char *addrstr, const char *servstr,
    int argc, char * const argv[])
{

	return (*th->th_server_main)(addrstr, servstr, argc, argv);
}
