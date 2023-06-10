#include <stdio.h>

#include "tp_count.h"

void
tp_count_init(struct tp_count *tpc, const char *desc)
{

	tpc->tpc_desc = desc;
	tpc->tpc_count = 0;
	tpc->tpc_bytes = 0;
	tpc->tpc_errors = 0;
	tpc->tpc_interval = TP_COUNT_DEFAULT_INTERVAL;
}

void
tp_count_inc(struct tp_count *tpc, size_t bytes)
{

	if (bytes == (ssize_t)-1) {
		tpc->tpc_errors++;
		return;
	}

	tpc->tpc_count++;
	tpc->tpc_bytes += bytes;

	if (tpc->tpc_count % tpc->tpc_interval == 0)
		fprintf(stderr, "%s %zu (%zu bytes, %zu errors)\n",
		    tpc->tpc_desc, tpc->tpc_count, tpc->tpc_bytes, tpc->tpc_errors);
}
