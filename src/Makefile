#
PICOTLSDIR=	../../picotls
PICOTLSLDADD=	-L$(PICOTLSDIR) -lpicotls-core -lpicotls-openssl\
		-lpicotls-fusion	\
		-L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
#		-lpicotls-minicrypto
PICODIR=	../../picoquick/picoquic
PICOLIBDIR=	../../picoquick
PICOLDADD=	-L$(PICOLIBDIR) -lpicoquic-core $(PICOTLSLDADD)
#
PROG=	tp
LIB=	tp
CPPFLAGS=	-I$(PICODIR)
CFLAGS=	-Wall -O2 -Werror
LDFLAGS=	$(PICOLDADD)
SRCDIR=	../src
SRCS=	tp.c tp_clock.c tp_count.c tp_client.c tp_server.c tp_main.c
SRCS+=	tp_picoquic.c

#
#LIBX=	lib$(LIB).a
OBJS=	$(SRCS:%.c=%.o)

all:	$(PROG)

.c.o:
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $<

#$(LIBX): $(OBJS)
#	ar r $@ $(OBJS)

$(PROG): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	$(RM) $(OBJS) $(LIBX) $(PROG)
