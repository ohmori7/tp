#include <stddef.h>

#include "tp_option.h"

#define	TP_OPTION_DEFAULT_ADDR		"127.0.0.1"
#define	TP_OPTION_DEFAULT_SERVICE	"12345"
#define	TP_OPTION_DEFAULT_PROTO		"tcp"

void
tp_option_init(struct tp_option *to)
{

	to->to_protoname = TP_OPTION_DEFAULT_PROTO;
	to->to_addrname = TP_OPTION_DEFAULT_ADDR;
	to->to_servicename = TP_OPTION_DEFAULT_SERVICE;
	to->to_filename = NULL;
	to->to_ccname = NULL;
}
