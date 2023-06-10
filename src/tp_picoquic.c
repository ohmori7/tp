#include <err.h>
#include <sysexits.h>

#include "picoquic.h"

struct tp_picoquic_stream_ctx {
	int tppsc_dummy;
};

static int
tp_picoquic_server_cb(picoquic_cnx_t* cnx, uint64_t sid,
    uint8_t *bytes, size_t len, picoquic_call_back_event_t event,
    void *cb_ctx, void *stream_ctx)
{

	return 0;
}

int
tp_picoquic_server_main(const char *cert, const char *key)
{
	struct tp_picoquic_stream_ctx ctx = { 0 };
	picoquic_quic_t *quic;

#define TP_PICOQUIC_MAXCONN	1
#define TP_PICOQUIC_ALPN	"tp_picoquic"
	quic = picoquic_create(TP_PICOQUIC_MAXCONN,
	    cert, key, NULL, TP_PICOQUIC_ALPN,
	    tp_picoquic_server_cb, &ctx, NULL, NULL, NULL,
	    picoquic_current_time(),
	    NULL, NULL, NULL, 0);
	if (quic == NULL)
		errx(EX_SOFTWARE, "cannot initialize QUIC");

	return 0;
}
