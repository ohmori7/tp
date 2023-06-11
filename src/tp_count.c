#include <err.h>
#include <sysexits.h>

#include <stdio.h>

#include "tp.h"
#include "tp_count.h"
#include "tp_clock.h"

struct tp_count_value {
	const char *tpcv_prefix;
	size_t tpcv_value;
};

static struct tp_count_value
tp_count_value(size_t v)
{
	static const char *prefixes[] = { "", "K", "M", "G", "T", "P" };
	struct tp_count_value tpcv;
	int i;

#define TP_COUNT_FACTOR	10
	for (i = 0; i < TP_ARRAY_SIZE(prefixes); i++, v >>= TP_COUNT_FACTOR)
		if (v >> TP_COUNT_FACTOR < 100)
			break;
	tpcv.tpcv_prefix = prefixes[i];
	tpcv.tpcv_value = v;
	return tpcv;
}

static void
tp_count_update(struct tp_count *tpc, struct timespec lasttime)
{

	tpc->tpc_count = tpc->tpc_bytes = tpc->tpc_errors = 0;
	tpc->tpc_lasttime = lasttime;
}

void
tp_count_stats(struct tp_count *tpc)
{
	struct timespec now, time;
	struct tp_count_value bytes, bps;

	if (tpc->tpc_count % tpc->tpc_interval != 0)
		return;

	bytes = tp_count_value(tpc->tpc_bytes);
	if (tp_clock_get(&now) == -1)
		err(EX_OSERR, "tp_clock_get() failed");
	time = tp_clock_sub(now, tpc->tpc_lasttime);
	bps = tp_count_value((tpc->tpc_bytes / time.tv_sec) << 3);

	fprintf(stderr, "%s %zu packets, %zu %sbps (%zu %sbytes, %zu errors) for %lld.%09lld secs\n",
	    tpc->tpc_desc, tpc->tpc_count,
	    bps.tpcv_value, bps.tpcv_prefix,
	    bytes.tpcv_value, bytes.tpcv_prefix,
	    tpc->tpc_errors,
	    (long long)time.tv_sec, (long long)time.tv_nsec);

	tp_count_update(tpc, now);
}

void
tp_count_finalize(struct tp_count *tpc)
{
	struct timespec now;

	if (tp_clock_get(&now) == -1)
		err(EX_OSERR, "tp_clock_get() failed");
	tp_count_update(tpc, now);
}

void
tp_count_final_stats(struct tp_count *tpc)
{
	struct timespec time;
	struct tp_count_value bytes, bps;

	bytes = tp_count_value(tpc->tpc_total_bytes);
	time = tp_clock_sub(tpc->tpc_lasttime, tpc->tpc_firsttime);
	bps = tp_count_value((tpc->tpc_total_bytes / time.tv_sec) << 3);

	fprintf(stderr, "%s %zu packets, %zu %sbps (%zu %sbytes, %zu errors) for %lld.%09lld secs\n",
	    tpc->tpc_desc, tpc->tpc_total_count,
	    bps.tpcv_value, bps.tpcv_prefix,
	    bytes.tpcv_value, bytes.tpcv_prefix,
	    tpc->tpc_total_errors,
	    (long long)time.tv_sec, (long long)time.tv_nsec);
}

void
tp_count_init(struct tp_count *tpc, const char *desc)
{

	tpc->tpc_desc = desc;
	tpc->tpc_count = 0;
	tpc->tpc_bytes = 0;
	tpc->tpc_errors = 0;
	tpc->tpc_interval = TP_COUNT_DEFAULT_INTERVAL;
	if (tp_clock_get(&tpc->tpc_firsttime) == -1)
		err(EX_OSERR, "cannot get clock");
	tpc->tpc_lasttime = tpc->tpc_firsttime;
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
	tpc->tpc_total_count++;
	tpc->tpc_total_bytes += bytes;

	tp_count_stats(tpc);
}
