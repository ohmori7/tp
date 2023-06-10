struct tp_count {
	const char *tpc_desc;
	size_t tpc_count;
	size_t tpc_bytes;
	size_t tpc_errors;
#define TP_COUNT_DEFAULT_INTERVAL	500000	/* unit in packet */
	size_t tpc_interval;
};

void tp_count_init(struct tp_count *, const char *);
void tp_count_inc(struct tp_count *, size_t);
