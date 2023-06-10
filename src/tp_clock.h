void tp_clock_init(void);
int tp_clock_get(struct timespec *);
struct timespec tp_clock_sub(const struct timespec, const struct timespec);
