#include "tp_socket.h"

#include <sys/socket.h>
#include <assert.h>
#include <unistd.h>

#include <stdio.h>

#ifdef DEBUG
#define DPRINTF(a, ...)							\
	fprintf(stderr, "%s: %d: " a "\n", __FILE__, __LINE__, __VA_ARGS__)
#else /* DEBUG */
#define DPRINTF(a, ...)
#endif /* ! DEBUG */

static int tp_socket_buf_size_recv = 0;
static int tp_socket_buf_size_send = 0;

static int
tp_socket_buffer_size(int optname, int *sizep)
{
	int s, size, delta, next, error;
	socklen_t sizelen;

	if (*sizep != 0)
		return 0;

	/* XXX: socket buffers are the same for family and protcol??? */
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		perror("socket");
		return -1;
	}

	sizelen = sizeof(size);
	error = getsockopt(s, SOL_SOCKET, optname, &size, &sizelen);
	if (error == -1) {
		perror("getsockopt");
		goto out;
	}

	delta = size;
	while ((next = size + delta) > size) {
		error = setsockopt(s, SOL_SOCKET, optname, &next, sizelen);
		DPRINTF("socket buffer: try %d bytes (%s)",
		    next, (error == -1) ? "fail" : "succeed");
		if (error == -1)
			delta >>= 1;
		else {
			size = next;
			delta <<= 1;
		}
	}
	DPRINTF("socket buffer: increased to %d bytes", size);

	*sizep = size;
  out:
	(void)close(s);
	return error;
}

int
tp_socket_buffer_recv_size(void)
{

	(void)tp_socket_buffer_size(SO_RCVBUF, &tp_socket_buf_size_recv);
	return tp_socket_buf_size_recv;
}

int
tp_socket_buffer_send_size(void)
{

	(void)tp_socket_buffer_size(SO_SNDBUF, &tp_socket_buf_size_send);
	return tp_socket_buf_size_send;
}

static int
_tp_socket_buffer_maximize(int s, int optname, int *sizep)
{
	socklen_t sizelen;
	int error;

	sizelen = sizeof(*sizep);
	error = tp_socket_buffer_size(optname, sizep);
	if (error == -1)
		return -1;
	error = setsockopt(s, SOL_SOCKET, optname, sizep, sizelen);
	if (error == -1)
		perror("setsockopt");
	return error;
}

int
tp_socket_buffer_maximize(int s)
{
	int error;

	error = _tp_socket_buffer_maximize(s, SO_RCVBUF, &tp_socket_buf_size_recv);
	if (error == -1)
		return -1;
	error = _tp_socket_buffer_maximize(s, SO_SNDBUF, &tp_socket_buf_size_send);
	return error;
}
