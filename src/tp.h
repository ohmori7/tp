#define TP_ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))

enum tp_proto {
	TP_UDP,
	TP_TCP,
	TP_TLS,
	TP_SCTP,
	TP_QUIC,
};

struct tp;

#define TP_MTU		1500
#define TP_IPHDRLEN	20
#define	TP_THDRLEN	20
#define TP_MSS		(1500 - TP_IPHDRLEN - TP_THDRLEN)

#define TP_DATASIZE	(1024ULL << 10 << 10)	/* 1GB */

int tp_proto_aton(const char *);

void *tp_buf(struct tp *);

void tp_set_context(struct tp *, void *);
void *tp_get_context(struct tp *);
void tp_set_recv(struct tp *, ssize_t (*)(struct tp *, int, void *, size_t, int));
void tp_set_send(struct tp *, ssize_t (*)(struct tp *, int, const void *, size_t, int));
void tp_free(struct tp *);

struct addrinfo; /* XXX: in netdb.h though.. */
int tp_name_resolve(int, const char *, const char *,
    int (*)(const struct addrinfo *, void *), void *);

struct tp *tp_connect(const char *, const char *, const char *);
struct tp *tp_listen(const char *, const char *, const char *);

struct tp *tp_accept(struct tp *);

ssize_t tp_write(struct tp *, const void *, size_t);
ssize_t tp_send(struct tp *);
ssize_t tp_recv(struct tp *);

int tp_client_main(const char *, const char *, const char *);
int tp_server_main(const char *, const char *, const char *);
