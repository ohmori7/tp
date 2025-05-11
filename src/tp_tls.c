#if 1
#define PTLS_WITHOUT_FUSION
#endif

#include <assert.h>
#include <err.h>
#include <sysexits.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/engine.h>
#if ! defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif /* ! LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER >= 0x30000000L */

#include "picotls.h"
#include "picotls/openssl.h"
#if (! defined(_WINDOWS) || defined(_WINDOWS64)) && ! defined(PTLS_WITHOUT_FUSION)
#include "picotls/fusion.h"
#endif /* (! _WINDOWS || _WINDOWS64) && ! PTLS_WITHOUT_FUSION */

#include "tp.h"
#include "tp_handle.h"
#include "tp_tls.h"

/* picoquic/tls_api.h can be a reference. */

#if ! defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
OSSL_PROVIDER *openssl_default_provider = NULL;
#endif /* ! LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER >= 0x30000000L */

static const ptls_key_exchange_algorithm_t *tp_tls_keyex_algs_all[] = {
	&ptls_openssl_secp256r1,
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
	&ptls_openssl_x25519,
#endif /* PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 */
	NULL
};

static const ptls_key_exchange_algorithm_t *tp_tls_keyex_algs_secp256r1[] = {
	&ptls_openssl_secp256r1,
	NULL
};

#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
#define tp_tls_keyex_algs_x25519	(&tp_tls_keyex_algs_all[1])
#endif /* PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 */

static bool tp_tls_openssl_is_init = false;

#if (! defined(_WINDOWS) || defined(_WINDOWS64)) && ! defined(PTLS_WITHOUT_FUSION)
ptls_cipher_suite_t tp_tls_fusion_aes128gcmsha256 =
    { PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_fusion_aes128gcm, &ptls_openssl_sha256 };
ptls_cipher_suite_t tp_tls_fusion_aes256gcmsha384 =
    { PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_fusion_aes256gcm, &ptls_openssl_sha384 };
#endif /* (! _WINDOWS || _WINDOWS64) && ! PTLS_WITHOUT_FUSION */

static void tp_tls_ptls_context_free(ptls_context_t *);

static void
tp_tls_openssl_init(void)
{

	/* currently, multiple calls may not occur. */
	assert(! tp_tls_openssl_is_init);
	if (tp_tls_openssl_is_init)
		return;

	/* XXX: no possibilities of errors??? */
	OpenSSL_add_all_algorithms();
#if ! defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	openssl_default_provider = OSSL_PROVIDER_load(NULL, "default");
#else /* ! LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER >= 0x30000000L */
	ERR_load_crypto_strings();
#if ! defined(OPENSSL_NO_ENGINE)
	ENGINE_load_builtin_engines();
	ENGINE_register_all_ciphers();
	ENGINE_register_all_digests();
#endif /* ! OPENSSL_NO_ENGINE */
#endif /* ! LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER >= 0x30000000L */
	tp_tls_openssl_is_init = true;
}

static void
tp_tls_openssl_finish(void)
{

	if (! tp_tls_openssl_is_init)
		return;
	tp_tls_openssl_is_init = false;

#if ! defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (openssl_default_provider != NULL) {
		(void)OSSL_PROVIDER_unload(openssl_default_provider);
		openssl_default_provider = NULL;
	}
#else /* ! LIBRESSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER >= 0x30000000L */
#if !defined(OPENSSL_NO_ENGINE)
        /* Free allocations from engines ENGINEs */
        ENGINE_cleanup();
#endif /* ! OPENSSL_NO_ENGINE */
        ERR_free_strings();
#endif /* OPENSSL_NO_ENGINE */
        EVP_cleanup();
}

static int
tp_tls_openssl_key_exchange_set(ptls_context_t *ctx, int keyexid)
{

	assert(ctx != NULL);
	switch (keyexid) {
	case 0:
		ctx->key_exchanges = tp_tls_keyex_algs_all;
		break;
	case 20:
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
		ctx->key_exchanges = tp_tls_keyex_algs_x25519;
		break;
#else /* PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 */
		return -1;
#endif /* ! PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 */
	case 128:
		/* XXX: no 128??? same as 256??? */
		/*FALLTHROUGH*/
	case 256:
		ctx->key_exchanges = tp_tls_keyex_algs_secp256r1;
		break;
	default:
		return -1;
	}
	return 0;
}

static int
tp_tls_cipher_suite_list_set(ptls_cipher_suite_t **suites, int id)
{
	int n = 0;

#if (!defined(_WINDOWS) || defined(_WINDOWS64)) && ! defined(PTLS_WITHOUT_FUSION) &&	\
    ! defined(TP_TLS_SAVE_MEMORY)
	if (ptls_fusion_is_supported_by_cpu()) {
		if (id == 0 || id == 128)
			suites[n++] = &tp_tls_fusion_aes128gcmsha256;
		if (id == 0 || id == 256)
			suites[n++] = &tp_tls_fusion_aes256gcmsha384;
	}
#endif /* ! _WINDOWS || _WINDOWS64 && ! PTLS_WITHOUT_FUSION && ! TP_TLS_SAVE_MEMORY */
	if (n == 0) {
		if (id == 0 || id == 128)
			suites[n++] = &ptls_openssl_aes128gcmsha256;
		if (id == 0 || id == 256)
			suites[n++] = &ptls_openssl_aes256gcmsha384;
	}
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
	if (id == 0 || id == 20)
		suites[n++] = &ptls_openssl_chacha20poly1305sha256;
#endif /* PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 */

	return n;
}

static int
tp_tls_cipher_suite_set(ptls_context_t *ctx, int id)
{
	ptls_cipher_suite_t *suites[4];
	int n;

	assert(ctx != NULL);
	n = tp_tls_cipher_suite_list_set(suites, id);
	if (n == 0)
		return -1;

	while (n < TP_ARRAY_SIZE(suites))
		suites[n++] = NULL;
	if (ctx->cipher_suites == NULL) {
		ctx->cipher_suites = malloc(sizeof(suites));
		if (ctx->cipher_suites == NULL)
			return -1;
	}
	memcpy(ctx->cipher_suites, suites, sizeof(suites));
	return 0;
}

void
tp_tls_cipher_suite_unset(ptls_context_t *ctx)
{

	if (ctx->cipher_suites == NULL)
		return;
	free(ctx->cipher_suites);
	ctx->cipher_suites = NULL;
}

static int
tp_tls_signer_set(ptls_context_t *ctx, EVP_PKEY *pkey)
{
	ptls_openssl_sign_certificate_t *signer;
	int error;

	assert(pkey != NULL);
	signer = malloc(sizeof(*signer));
	if (signer == NULL)
		return -1;
	error = ptls_openssl_init_sign_certificate(signer, pkey);
	if (error != 0)
		goto bad;
        ctx->sign_certificate = &signer->super;

	return 0;
  bad:
	free(signer);
	return error;
}

static void
tp_tls_signer_unset(ptls_context_t *ctx)
{
	ptls_openssl_sign_certificate_t *cert;

	cert = (ptls_openssl_sign_certificate_t *)ctx->sign_certificate;
	if (cert == NULL)
		return;
	ptls_openssl_dispose_sign_certificate(cert);
	free(cert);
	ctx->sign_certificate = NULL;
}

static int
tp_tls_private_key_set(ptls_context_t *ctx, const char *filename)
{
	BIO *bio;
	EVP_PKEY *pkey;
	int error;

	bio = BIO_new_file(filename, "rb");
	if (bio == NULL)
		return -1;
	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (pkey == NULL) {
		error = -1;
		fprintf(stderr, "cannot load PEM private key file\n");
		goto bad;
	}
	error = tp_tls_signer_set(ctx, pkey);
  bad:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	BIO_free(bio);
	return error;
}

static void
tp_tls_private_key_unset(ptls_context_t *ctx)
{

	tp_tls_signer_unset(ctx);
}

static int
tp_tls_certificate_verifier_set(ptls_context_t *ctx, const char *root)
{
	ptls_openssl_verify_certificate_t *verifier;
	X509_STORE *store;
	X509_LOOKUP *lookup;
	int error;

	verifier = malloc(sizeof(*verifier));
	if (verifier == NULL)
		return -1;
	if (root == NULL)
		store = NULL;
	else {
		store = X509_STORE_new();
		if (store == NULL)
			goto bad;
		lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
		error = X509_LOOKUP_load_file(lookup, root, X509_FILETYPE_PEM);
		if (error != 1) {
			fprintf(stderr, "cannot load load X509 store: %s: %d\n",
			    root, error);
			goto bad;
		}
	}

#ifdef PTLS_OPENSSL_VERIFY_CERTIFICATE_ENABLE_OVERRIDE
	ptls_openssl_init_verify_certificate(verifier, store, NULL);
#else
	ptls_openssl_init_verify_certificate(verifier, store);
#endif

#if OPENSSL_VERSION_NUMBER > 0x10100000L
	if (store != NULL)
		X509_STORE_free(store);
#endif /* OPENSSL_VERSION_NUMBER > 0x10100000L */

	ctx->verify_certificate = &verifier->super;

	return 0;
  bad:
	if (verifier != NULL)
		free(verifier);
	if (store != NULL)
		X509_STORE_free(store);
	return -1;
}

static void
tp_tls_certificate_verifier_unset(ptls_context_t *ctx)
{
	ptls_verify_certificate_t *verifier;

	verifier = ctx->verify_certificate;
	if (verifier == NULL)
		return;
	/* XXX: do not need to free store??? */
	ptls_openssl_dispose_verify_certificate((ptls_openssl_verify_certificate_t*)verifier);
	free(verifier);
	ctx->verify_certificate = NULL;
}

static ptls_context_t *
tp_tls_ptls_context_alloc(const char *cert, const char *key, const char *root)
{
	ptls_context_t *ctx;
	int keyexid = 0;
	int cipher_suite_id = 0;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	memset(ctx, 0, sizeof(*ctx));

	tp_tls_openssl_init();

	ctx->random_bytes = ptls_openssl_random_bytes;

	if (tp_tls_openssl_key_exchange_set(ctx, keyexid) != 0)
		goto bad;

	if (tp_tls_cipher_suite_set(ctx, cipher_suite_id) != 0)
		goto bad;

	ctx->send_change_cipher_spec = 0;
	ctx->hkdf_label_prefix__obsolete = NULL;
	/* we here do not use traffic key update callback. */
	ctx->get_time = &ptls_get_time;

	if (cert != NULL) {
		assert(key != NULL);
		if (ptls_load_certificates(ctx, cert) != 0) {
			fprintf(stderr, "cannot load certificate: %s\n", cert);
			goto bad;
		}
		if (tp_tls_private_key_set(ctx, key) != 0) {
			fprintf(stderr, "cannot load key: %s\n", key);
			goto bad;
		}
	}

	/*
	 * we here do not use client hello callback
	 * because we do not care ALPN.
	 */
	/* no session ticket here for TCP. */

	/*
	 * currently, our server do not necessarily verify certificate,
	 * but it does not work without this because picotls server transit
	 * to handshake finish state immediately if no verifier is set
	 * and the client seems not to support it.
	 */
	if (tp_tls_certificate_verifier_set(ctx, root) == -1) {
		fprintf(stderr, "cannot set certificate verifier\n");
		goto bad;
	}

	ctx->omit_end_of_early_data = 1;

	return ctx;
  bad:
	tp_tls_ptls_context_free(ctx);
	return NULL;
}

static void
tp_tls_ptls_context_free(ptls_context_t *ctx)
{

	/* XXX: should may be once... */
	tp_tls_openssl_finish();

	if (ctx == NULL)
		return;
	tp_tls_cipher_suite_unset(ctx);
	tp_tls_private_key_unset(ctx);
	tp_tls_certificate_verifier_unset(ctx);
	free(ctx);
}

static void
tp_tls_buf_trim(ptls_buffer_t *buf, size_t len)
{

	assert(len <= buf->off);
	buf->off -= len;
	memmove(buf->base, buf->base + len, buf->off);
}

static int
tp_tls_handshake(struct tp *tp, ptls_t *ptls, off_t *offp, size_t *leftlenp)
{
	ptls_buffer_t encbuf;
	off_t off;
	size_t len;
	size_t eatenlen;
	ssize_t nlen;
	int error;

	fprintf(stderr, "TLS handshake start\n");

	ptls_buffer_init(&encbuf, "", 0);

	off = 0;
	len = eatenlen = 0;
	error = 0;
	for (;;) {
		eatenlen = len;	/* strange specification... */
		error = ptls_handshake(ptls, &encbuf, tp_buf(tp) + off, &eatenlen, NULL);
		off += eatenlen;
		len -= eatenlen;
		if (len == 0)
			off = 0;
		if (error != 0 && error != PTLS_ERROR_IN_PROGRESS) {
			fprintf(stderr, "handshake error: %d\n", error);
			goto out;
		}
		/* XXX: this may be insufficient... */
		while (encbuf.off != 0) {
			ssize_t wlen;

			wlen = tp_write(tp, encbuf.base, encbuf.off);
			if (wlen == (ssize_t)-1 || wlen == 0) {
				fprintf(stderr, "write failed\n");
				goto out;
			}
			tp_tls_buf_trim(&encbuf, wlen);
		}
		if (ptls_handshake_is_complete(ptls))
			break;

		nlen = tp_recv(tp, off + len);
		if (nlen == (ssize_t)-1)
			goto out;
		len += nlen;
	}
	fprintf(stderr, "TLS handshake finish\n");
	*offp = off;
	*leftlenp = len;
  out:
	ptls_buffer_dispose(&encbuf);
	return error;
}

static int
tp_tls_recv(struct tp *tp, ptls_t *ptls, off_t off, size_t leftlen)
{
	ptls_buffer_t rbuf;
	ssize_t len;
	size_t consumedlen;
	int error;

	ptls_buffer_init(&rbuf, "", 0);

	error = 0;
	for (;;) {
		consumedlen = leftlen;
		error = ptls_receive(ptls, &rbuf, tp_buf(tp) + off, &consumedlen);
		switch (error) {
		case 0:
			off += consumedlen;
			leftlen -= consumedlen;
			if (leftlen == 0)
				off = 0;
			len = tp_recv(tp, off);
			if (len == (ssize_t)-1)
				goto out;
			rbuf.off = 0;
			break;
		default:
			fprintf(stderr, "ptls_receive failed: %d\n", error);
			goto out;
		}
	}
  out:
	ptls_buffer_dispose(&rbuf);
	return error;
}

static ssize_t
tp_tls_send(struct tp *tp, int sock, const void *data, size_t datalen, int flags)
{
	ptls_t *ptls;
	ptls_buffer_t encbuf;
	ssize_t len;
	size_t leftlen;
	off_t off;
	int error;

	ptls_buffer_init(&encbuf, "", 0);

	ptls = tp_get_context(tp);
	error = ptls_send(ptls, &encbuf, data, datalen);
	if (error != 0) {
		fprintf(stderr, "ptls_send failed: %d\n", error);
		goto out;
	}

	off = 0;
	leftlen = encbuf.off;
	do {
		len = tp_write(tp, encbuf.base + off, leftlen);
		if (len == (ssize_t)-1) {
			datalen = len;
			break;
		}
		off += len;
	} while ((leftlen -= len) != 0);
  out:
	ptls_buffer_dispose(&encbuf);

	return datalen;
}

static int
tp_tls_server_send_to_client(struct tp *tp, ptls_context_t *ctx)
{
	ptls_t *ptls;
	off_t off;
	size_t leftlen;
	int error;

	ptls = ptls_server_new(ctx);
	if (ptls == NULL) {
		fprintf(stderr, "cannot initialize picotls");
		return -1;
	}
	ptls_set_server_name(ptls, TP_TLS_DEFAULT_SNI, 0);

	tp_set_context(tp, ptls);
	tp_set_send(tp, tp_tls_send);

	/* clear openssl error. */
	ERR_clear_error();

	error = tp_tls_handshake(tp, ptls, &off, &leftlen);
	if (error != 0)
		goto out;

	while (tp_send(tp) != (ssize_t)-1)
		;

  out:
	ptls_free(ptls);

	return error;
}

int
tp_tls_server(const char *dststr, const char *servstr, const char *filename,
    int argc, char * const argv[])
{
	const char *protostr = "tls";
	const char *cert;
	const char *key;
	struct tp *ltp, *tp;
	ptls_context_t *ctx;

	if (argc < 2)
		errx(EX_USAGE, "missing certificate or key file for TLS");
	cert = argv[0];
	key = argv[1];
	argc -= 2;
	argv += 2;

	if (argc != 0)
		errx(EX_USAGE, "extra argument(s)");

	fprintf(stderr, "waiting on %s.%s using %s\n", dststr, servstr, protostr);

	ltp = tp_listen(protostr, dststr, servstr, filename);
	if (ltp == NULL)
		errx(EX_OSERR, "cannot prepare for socket");
		/*NOTREACHED*/

	ctx = tp_tls_ptls_context_alloc(cert, key, NULL);
	if (ctx == NULL)
		errx(EX_SOFTWARE, "cannot allocate picotls context");

	for (;;) {
		tp = tp_accept(ltp);
		if (tp == NULL)
			continue;
		fprintf(stderr, "connected\n");
		tp_tls_server_send_to_client(tp, ctx);
		fprintf(stderr, "disconnected\n");
		tp_free(tp);
	}

	tp_tls_ptls_context_free(ctx);

	fprintf(stderr, "done\n");

	return 0;
}

static int
tp_tls_client(const char *dststr, const char *servstr, const char *filename,
    int argc, char * const argv[])
{
	const char *protostr = "tls";
	const char *cert;
	struct tp *tp;
	ptls_context_t *ctx;
	ptls_t *ptls;
	off_t off;
	size_t leftlen;
	int error;

	if (argc < 1)
		errx(EX_USAGE, "missing server certificate file for TLS");
	cert = argv[0];
	argc -= 1;
	argv += 1;

	if (argc != 0)
		errx(EX_USAGE, "extra argument(s)");

	fprintf(stderr, "connect to %s.%s using %s\n", dststr, servstr, protostr);

	tp = tp_connect(protostr, dststr, servstr, filename);
	if (tp == NULL)
		errx(EX_OSERR, "cannot connect to the server");
		/*NOTREACHED*/

	ctx = tp_tls_ptls_context_alloc(NULL, NULL, cert);
	if (ctx == NULL)
		errx(EX_SOFTWARE, "cannot allocate picotls context");

	ptls = ptls_client_new(ctx);
	if (ptls == NULL) {
		fprintf(stderr, "cannot initialize picotls");
		return -1;
	}
	ptls_set_server_name(ptls, TP_TLS_DEFAULT_SNI, 0);

	/* clear openssl error. */
	ERR_clear_error();

	error = tp_tls_handshake(tp, ptls, &off, &leftlen);
	if (error != 0)
		goto out;

	error = tp_tls_recv(tp, ptls, off, leftlen);
	if (error != 0)
		goto out;

  out:
	tp_tls_ptls_context_free(ctx);

	return error;
}

void
tp_tls_init(void)
{

	(void)tp_handle_register("tls", tp_tls_client, tp_tls_server);
}
