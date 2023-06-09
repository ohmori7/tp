#include "tp.h"

int
main(int argc, char * const argv[])
{

	/* XXX */
	if (argc == 1)
		tp_server_main("tcp", "127.0.0.1", "12345");
	else
		tp_client_main("tcp", "127.0.0.1", "12345");

	return 0;
}
