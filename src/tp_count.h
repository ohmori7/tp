#include <sys/time.h>	/* XXX: for struct timespec. */

struct tp_count {
	const char *tpc_desc;
	size_t tpc_count;
	size_t tpc_bytes;
	size_t tpc_errors;
	size_t tpc_total_count;
	size_t tpc_total_bytes;
	size_t tpc_total_errors;
#define TP_COUNT_DEFAULT_INTERVAL	500000	/* unit in packet */
	size_t tpc_interval;
	struct timespec tpc_firsttime;
	struct timespec tpc_lasttime;
};

void tp_count_init(struct tp_count *, const char *);
void tp_count_finalize(struct tp_count *);
void tp_count_final_stats(struct tp_count *);
void tp_count_inc(struct tp_count *, size_t);
