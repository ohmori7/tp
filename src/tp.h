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

void tp_free(struct tp *);

struct tp *tp_connect(const char *, const char *, const char *);
struct tp *tp_listen(const char *, const char *, const char *);

struct tp *tp_accept(struct tp *);

ssize_t tp_send(struct tp *);
ssize_t tp_recv(struct tp *);

int tp_client_main(const char *, const char *, const char *);
int tp_server_main(const char *, const char *, const char *);
