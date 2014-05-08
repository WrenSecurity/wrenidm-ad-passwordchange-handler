/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2014 ForgeRock AS. All rights reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [2014] [ForgeRock AS]"
 **/
#ifndef __NETWORK_H__
#define __NETWORK_H__

#define SECURITY_WIN32
#include <winsock2.h>
#include <security.h>
#include <wincrypt.h>

#define NET_CONNECT_TIMEOUT 4 /*seconds*/

typedef enum {
    NO_AUTH = 0,
    BASIC_AUTH,
    CERT_AUTH,
    IDM_HEADER_AUTH
} AUTH_TYPE;

enum {
    SSLv3 = 1 << 0,
    TLSv1 = 1 << 1,
    TLSv11 = 1 << 2,
    TLSv12 = 1 << 3,
    SSL_VERSION_MASKS = 1 << 4
};

typedef SSIZE_T ssize_t;

typedef struct {
    void *o;
    void (*info)(void *, const char *, ...);
    void (*warning)(void *, const char *, ...);
    void (*error)(void *, const char *, ...);
    void (*debug)(void *, const char *, ...);
} net_log_t;

typedef enum {
    STATE_NONE = 0,
    STATE_HANDSHAKE_READ,
    STATE_HANDSHAKE_READ_COMPLETE,
    STATE_HANDSHAKE_WRITE,
    STATE_HANDSHAKE_WRITE_COMPLETE,
    STATE_VERIFY_CERT,
    STATE_VERIFY_CERT_COMPLETE,
    STATE_COMPLETED_RENEGOTIATION,
    STATE_COMPLETED_HANDSHAKE
} ssl_state_t;

typedef struct {
    SOCKET sock;

    struct url {
        char ssl;
        char *proto;
        char *host;
        char *uri;
        unsigned int port;
    } url;

    struct ssl {
        char on;

        CredHandle creds;
        CtxtHandle ctx;

        ssl_state_t state;
        char *transport_read_buf_;
        char *transport_write_buf_;
        SecPkgContext_StreamSizes stream_sizes_;

        SecBuffer in_buffers_[2];
        SecBuffer send_buffer_;
        SECURITY_STATUS isc_status_;

        char *payload_send_buffer_;
        unsigned int payload_send_buffer_len_;
        unsigned int bytes_sent_;
        char *recv_buffer_;

        unsigned int user_write_buf_len_;
        const char *user_write_buf_;
        unsigned int user_read_buf_len_;
        char *user_read_buf_;

        const char *decrypted_ptr_;
        unsigned int bytes_decrypted_;
        const char *received_ptr_;
        unsigned int bytes_received_;

        BOOL writing_first_token_;
        BOOL ignore_ok_result_;
        BOOL renegotiating_;
        BOOL need_more_data_;

        HCERTSTORE store_;
        char *cfile;
        char *cpass;

        char verifypeer;
        unsigned int version;
    } ssl;

    AUTH_TYPE auth;

    net_log_t log;

    char keepalive;
    char nonblocking;
    unsigned int timeout;
} net_t;

void net_init();
void net_shutdown();

net_t * net_connect_url(const char *url, const char *cfile, const char *cpass, unsigned int timeout, net_log_t *log);
void net_close(net_t *);
ssize_t http_post(net_t *c, const char * uri, const char **hdrs, size_t hdrsz, const char * post, const size_t len, char ** buff);
unsigned int http_status(net_t *c, const char *data);

#endif
