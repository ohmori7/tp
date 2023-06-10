PROG=	tp
LIB=	tp
CFLAGS=	-Wall -O2 -Werror
SRCDIR=	../src
SRCS=	tp.c tp_count.c tp_client.c tp_server.c tp_main.c

#
#LIBX=	lib$(LIB).a
OBJS=	$(SRCS:%.c=%.o)

all:	$(PROG)

.c.o:
	$(CC) -c $(CPPFALGS) $(CFLAGS) $<

#$(LIBX): $(OBJS)
#	ar r $@ $(OBJS)

$(PROG): $(OBJS)

.PHONY: clean
clean:
	$(RM) $(OBJS) $(LIBX) $(PROG)
