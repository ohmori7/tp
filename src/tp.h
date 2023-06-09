enum tp_proto {
	TP_UDP,
	TP_TCP,
	TP_SCTP,
	TP_QUIC,
};

#define TP_SEGSIZE	1500
#define TP_IPHDRLEN	20
#define	TP_UDPHDRLEN	20

int tp_connect(const char *, const char *, const char *);
int tp_bind(const char *, const char *, const char *);

int tp_client_main(const char *, const char *, const char *);
int tp_server_main(const char *, const char *, const char *);
