#
PICOTLSDIR=	../../picotls
PICOTLSINCDIR=	$(PICOTLSDIR)/include
PICOTLSLDADD=	-L$(PICOTLSDIR) -lpicotls-core -lpicotls-openssl\
		-lpicotls-fusion	\
		-L/usr/local/Cellar/openssl@3/3.5.0/lib -lssl -lcrypto
#		-L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto
#
#OPENSSLINCDIR=	 /usr/local/Cellar/openssl@1.1/1.1.1u/include/
OPENSSLINCDIR=	 /usr/local/Cellar/openssl@3/3.5.0/include
#		-lpicotls-minicrypto
PICODIR=	../../picoquick/picoquic
PICOLIBDIR=	../../picoquick
PICOLDADD=	-L$(PICOLIBDIR) -lpicoquic-core $(PICOTLSLDADD)
#
MSQUICDIR=	../../msquic
MSQUICINCDIR=	$(MSQUICDIR)/src/inc
MSQUICLIBDIR=	$(MSQUICDIR)/build/obj/Release
#MSQUICLDADD=	-L$(MSQUICLIBDIR) -lmsquic -lcore -lplatform
MSQUICLDADD=	-L$(MSQUICLIBDIR) -lcore -lmsquic_platform
MSQUICLDADD+=	-framework Foundation -framework AppKit	# recent macOS
MSQUICLDADD+=	-framework Security
MSQUICLDADD+=	$(MSQUICDIR)/build/_deps/opensslquic-build/submodules/quictls/libssl.a

PROG=	tp
LIB=	tp
CPPFLAGS=	-I$(PICODIR) -I$(PICOTLSINCDIR) -I$(OPENSSLINCDIR)
CPPFLAGS+=	-I$(MSQUICINCDIR)
CFLAGS=	-Wall -O2 -Werror -g
LDFLAGS=	$(PICOLDADD)
LDFLAGS+=	$(MSQUICLDADD)
SRCDIR=	../src
SRCS=	tp.c tp_option.c tp_clock.c tp_count.c tp_socket.c tp_handle.c tp_main.c
SRCS+=	tp_tcp.c tp_tls.c tp_picoquic.c
SRCS+=	tp_msquic.c

#
#LIBX=	lib$(LIB).a
OBJS=	$(SRCS:%.c=%.o)

all:	$(PROG)

tp_msquic.o:	tp_msquic.c
	$(CC) -c $(CPPFLAGS) -Wall $<

.c.o:
	$(CC) -c $(CPPFLAGS) $(CFLAGS) $<

#$(LIBX): $(OBJS)
#	ar r $@ $(OBJS)

$(PROG): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

.PHONY: clean
clean:
	$(RM) $(OBJS) $(LIBX) $(PROG)
