#include <sys/types.h>
#include <assert.h>
#include <err.h>
#include <sysexits.h>
#include <time.h>

#include "tp.h"
#include "tp_clock.h"

#define TP_COUNT_CLOCKID_INVALID	((clockid_t)-1)
static clockid_t tp_clock_id = TP_COUNT_CLOCKID_INVALID;

void
tp_clock_init(void)
{
	static const clockid_t clockids[] = {
	    CLOCK_MONOTONIC_RAW,
	    CLOCK_MONOTONIC,
	    CLOCK_REALTIME,
	    };
	struct timespec ts;
	int i;

	assert(tp_clock_id == TP_COUNT_CLOCKID_INVALID);
	for (i = 0; i < TP_ARRAY_SIZE(clockids); i++)
		if (clock_gettime(clockids[i], &ts) != -1) {
			tp_clock_id = clockids[i];
			return;
		}
	err(EX_OSERR, "clock_gettime faield");
}

int
tp_clock_get(struct timespec *ts)
{

	assert(tp_clock_id != TP_COUNT_CLOCKID_INVALID);
	return clock_gettime(tp_clock_id, ts);
}

struct timespec
tp_clock_sub(const struct timespec a, const struct timespec b)
{
	struct timespec ts;

	ts = a;
	ts.tv_sec -= b.tv_sec;
	ts.tv_nsec -= b.tv_nsec;
	while (ts.tv_nsec < 0) {
		ts.tv_sec -= 1;
		ts.tv_nsec += 1000000000LL;
	}
	return ts;
}
