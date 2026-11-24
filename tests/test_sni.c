/* Copyright (c) 2026 LiteSpeed Technologies Inc.  See LICENSE. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <netinet/in.h>
#include <sys/uio.h>
#else
#include "vc_compat.h"
#endif
#include <openssl/ssl.h>
#include "lsquic.h"


struct lookup_ctx
{
    const char *lc_hostname;
    unsigned lc_calls;
};


struct packet
{
    struct packet *pa_next;
    size_t pa_size;
    unsigned char pa_data[65536];
};


static int
save_packets (void *ctx, const struct lsquic_out_spec *specs, unsigned count)
{
    struct packet **tail = ctx, *packet;
    unsigned i;
    size_t j;

    while (*tail)
        tail = &(*tail)->pa_next;
    for (i = 0; i < count; ++i)
    {
        packet = calloc(1, sizeof(*packet));
        assert(packet);
        for (j = 0; j < specs[i].iovlen; ++j)
        {
            assert(packet->pa_size + specs[i].iov[j].iov_len
                                                <= sizeof(packet->pa_data));
            memcpy(packet->pa_data + packet->pa_size, specs[i].iov[j].iov_base,
                                                    specs[i].iov[j].iov_len);
            packet->pa_size += specs[i].iov[j].iov_len;
        }
        *tail = packet;
        tail = &packet->pa_next;
    }
    return count;
}


static lsquic_conn_ctx_t *
on_new_conn (void *UNUSED_ctx, lsquic_conn_t *UNUSED_conn)
{
    return NULL;
}


static void
on_conn_closed (lsquic_conn_t *UNUSED_conn)
{
}


static const struct lsquic_stream_if stream_if = {
    .on_new_conn = on_new_conn,
    .on_conn_closed = on_conn_closed,
};


static SSL_CTX *
get_ssl_ctx (void *ctx, const struct sockaddr *UNUSED_local)
{
    return ctx;
}


static SSL_CTX *
lookup_cert (void *ctx, const struct sockaddr *UNUSED_local, const char *hostname)
{
    struct lookup_ctx *lookup = ctx;

    ++lookup->lc_calls;
    if (lookup->lc_hostname)
        assert(hostname && 0 == strcmp(hostname, lookup->lc_hostname));
    else
        assert(!hostname);
    /* Reject deliberately: opting in must still let the application refuse. */
    return NULL;
}


static void
test_client_hello (enum lsquic_version version, unsigned http, int allow_no_sni,
                  const char *hostname)
{
    struct lsquic_engine_settings settings;
    struct lsquic_engine_api api;
    struct sockaddr_in client_addr, server_addr;
    struct lookup_ctx lookup = { hostname, 0 };
    struct packet *packets = NULL, *packet;
    lsquic_engine_t *client, *server;
    SSL_CTX *ssl_ctx;

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    client_addr.sin_port = htons(12345);
    server_addr = client_addr;
    server_addr.sin_port = htons(443);
    ssl_ctx = SSL_CTX_new(TLS_method());
    assert(ssl_ctx);
    assert(SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION));
    assert(SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION));

    memset(&api, 0, sizeof(api));
    api.ea_stream_if = &stream_if;
    api.ea_packets_out = save_packets;
    api.ea_packets_out_ctx = &packets;
    api.ea_alpn = "test";
    client = lsquic_engine_new(http, &api);
    assert(client);

    lsquic_engine_init_settings(&settings, LSENG_SERVER | http);
    settings.es_allow_no_sni = allow_no_sni;
    api.ea_settings = &settings;
    api.ea_get_ssl_ctx = get_ssl_ctx;
    api.ea_lookup_cert = lookup_cert;
    api.ea_cert_lu_ctx = &lookup;
    server = lsquic_engine_new(LSENG_SERVER | http, &api);
    assert(server);
    assert(lsquic_engine_connect(client, version,
        (const struct sockaddr *) &client_addr,
        (const struct sockaddr *) &server_addr, NULL, NULL, hostname,
        0, NULL, 0, NULL, 0));
    lsquic_engine_process_conns(client);
    assert(packets);
    while ((packet = packets))
    {
        packets = packet->pa_next;
        assert(0 == lsquic_engine_packet_in(server, packet->pa_data,
            packet->pa_size, (const struct sockaddr *) &server_addr,
            (const struct sockaddr *) &client_addr, ssl_ctx, 0));
        free(packet);
    }
    assert(lookup.lc_calls == !!(hostname || !http || allow_no_sni));
    lsquic_engine_destroy(client);
    lsquic_engine_destroy(server);
    SSL_CTX_free(ssl_ctx);
}


int
main (void)
{
    const enum lsquic_version versions[] = { LSQVER_I001, LSQVER_I002 };
    unsigned i, http;
    int allow;

    assert(0 == lsquic_global_init(LSQUIC_GLOBAL_CLIENT | LSQUIC_GLOBAL_SERVER));
    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i)
        for (http = 0; http <= LSENG_HTTP; http += LSENG_HTTP)
            for (allow = 0; allow <= 1; ++allow)
            {
                test_client_hello(versions[i], http, allow, NULL);
                test_client_hello(versions[i], http, allow, "example.com");
            }
    lsquic_global_cleanup();
    return 0;
}
