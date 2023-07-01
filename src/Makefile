#
PICOTLSDIR=	../../picotls
PICOTLSINCDIR=	$(PICOTLSDIR)/include
PICOTLSLDADD=	-L$(PICOTLSDIR) -lpicotls-core -lpicotls-openssl\
		-lpicotls-fusion	\
		-L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
#
OPENSSLINCDIR=	 /usr/local/Cellar/openssl@1.1/1.1.1u/include/
#		-lpicotls-minicrypto
PICODIR=	../../picoquick/picoquic
PICOLIBDIR=	../../picoquick
PICOLDADD=	-L$(PICOLIBDIR) -lpicoquic-core $(PICOTLSLDADD)
#
PROG=	tp
LIB=	tp
CPPFLAGS=	-I$(PICODIR) -I$(PICOTLSINCDIR) -I$(OPENSSLINCDIR)
CFLAGS=	-Wall -O2 -Werror -g
LDFLAGS=	$(PICOLDADD)
SRCDIR=	../src
SRCS=	tp.c tp_clock.c tp_count.c tp_socket.c tp_handle.c tp_main.c
SRCS+=	tp_tcp.c tp_tls.c tp_picoquic.c

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
