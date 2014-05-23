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
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0502
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#define SECURITY_WIN32
#include <ws2tcpip.h>
#include <schnlsp.h>
#include "network.h"
#include "utils.h"
#include "version.h"

#define URI_HTTP "%5[HTPShtps]"
#define URI_HOST "%255[-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]"
#define URI_PORT "%6d"
#define URI_PATH "%2047[-_.!~*'();/?:@&=+$,%#abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]"
#define HD1 URI_HTTP "://" URI_HOST ":" URI_PORT "/" URI_PATH
#define HD2 URI_HTTP "://" URI_HOST "/" URI_PATH
#define HD3 URI_HTTP "://" URI_HOST ":" URI_PORT
#define HD4 URI_HTTP "://" URI_HOST

#define RECV_BUF_SZ 16453
#define SOCKET_IO_WAIT_TIME 300000 /* msec */
#define net_error_int(c, e) \
   do {LPSTR es = NULL; \
   if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, e, 0, (LPSTR) & es, 0, 0) == 0) { \
        if (c && c->log.error) c->log.error(c->log.o, "net_error(%s:%d) unknown error code (%d/%X)", __FILE__, __LINE__, e, e); } else { \
        char *p = strchr(es, '\r'); \
        if (p != NULL) *p = '\0'; \
        if (c && c->log.error) c->log.error(c->log.o, "net_error(%s:%d) %s (%d/%X)", __FILE__, __LINE__, es, e, e); \
        LocalFree(es);}} while(0)

static int net_ssl_loop(net_t *c, int last_io_result);
static int state_payload_read(net_t *c);
static int state_payload_write_complete(net_t *c, int result);
static ssize_t net_write(net_t *c, const char *data, const size_t sz);

enum {
    NET_OK = 0,
    NET_IO_PENDING = -1,
    NET_FAILED = -2,
    NET_UNEXPECTED = -3,
    NET_SSL_CLIENT_AUTH_CERT_NO_PRIVATE_KEY = -4,
    NET_SSL_VERSION_OR_CIPHER_MISMATCH = -5,
    NET_BAD_SSL_CLIENT_AUTH_CERT = -6,
    NET_SSL_PROTOCOL_ERROR = -7,
    NET_CERT_BEGIN = -8,
    NET_CERT_INVALID = -9,
    NET_CERT_REVOKED = -10,
    NET_CERT_UNABLE_TO_CHECK_REVOCATION = -11,
    NET_CERT_NO_REVOCATION_MECHANISM = -12,
    NET_CERT_DATE_INVALID = -13,
    NET_CERT_AUTHORITY_INVALID = -14,
    NET_CERT_COMMON_NAME_INVALID = -15,
    NET_CERT_END = -16,
    NET_SSL_CLIENT_AUTH_PRIVATE_KEY_ACCESS_DENIED = -17,
    NET_SSL_NO_RENEGOTIATION = -18,
    NET_SSL_CLIENT_AUTH_CERT_NEEDED = -19,
    NET_SSL_RENEGOTIATION_REQUESTED = -20
};

static BOOL net_in_progress(int error) {
    return (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS);
}

static BOOL net_cert_error(int error) {
    return (error <= NET_CERT_BEGIN && error > NET_CERT_END);
}

static int net_error() {
    return WSAGetLastError();
}

static int wait_for_io(net_t *c, int timeout, int for_read) {
    struct timeval tv, *tvptr;
    fd_set fdset;
    int srv, err;
    do {
        FD_ZERO(&fdset);
        FD_SET(c->sock, &fdset);
        if (timeout <= 0) {
            tvptr = NULL;
        } else {
            tv.tv_sec = 0;
            tv.tv_usec = timeout;
            tvptr = &tv;
        }
        srv = select((c->sock) + 1, for_read ? &fdset : NULL,
                for_read ? NULL : &fdset, NULL, tvptr);
        err = net_error();
    } while (srv == SOCKET_ERROR && err == WSAEINTR);
    if (srv == 0) {
        if (err != 0) net_error_int(c, err);
        return -1; /*timeout*/
    } else if (srv == SOCKET_ERROR) {
        net_error_int(c, err);
        return err; /*fatal error ( >0 )*/
    }
    srv = FD_ISSET(c->sock, &fdset);
    return srv ? 0 /*NET_OK*/ : err;
}

static int net_read_ssl_int(net_t *c, char *data, int data_sz) {
    int r = 10/*max retry count*/, l;
    do {
        l = recv(c->sock, data, data_sz, 0);
        if (l >= 0) return l;
        else if (l == SOCKET_ERROR && net_error() == WSAETIMEDOUT) return NET_OK;
        else if (l == SOCKET_ERROR && net_in_progress(net_error())) {
            if (wait_for_io(c, SOCKET_IO_WAIT_TIME, 1) == 0) {
                continue;
            }
            return NET_OK;
        } else break;
    } while (--r > 0);
    return NET_FAILED;
}

static int net_security_error(net_t *c, SECURITY_STATUS err) {
    switch (err) {
        case SEC_E_WRONG_PRINCIPAL:
        case CERT_E_CN_NO_MATCH:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() CERT_COMMON_NAME_INVALID %X", err);
            return NET_CERT_COMMON_NAME_INVALID;
        case SEC_E_UNTRUSTED_ROOT:
        case CERT_E_UNTRUSTEDROOT:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() CERT_AUTHORITY_INVALID %X", err);
            return NET_CERT_AUTHORITY_INVALID;
        case SEC_E_CERT_EXPIRED:
        case CERT_E_EXPIRED:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() CERT_DATE_INVALID %X", err);
            return NET_CERT_DATE_INVALID;
        case CRYPT_E_NO_REVOCATION_CHECK:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() CERT_NO_REVOCATION_MECHANISM %X", err);
            return NET_CERT_NO_REVOCATION_MECHANISM;
        case CRYPT_E_REVOCATION_OFFLINE:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() CERT_UNABLE_TO_CHECK_REVOCATION %X", err);
            return NET_CERT_UNABLE_TO_CHECK_REVOCATION;
        case CRYPT_E_REVOKED:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() CERT_REVOKED %X", err);
            return NET_CERT_REVOKED;
        case SEC_E_CERT_UNKNOWN:
        case CERT_E_ROLE:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() CERT_INVALID %X", err);
            return NET_CERT_INVALID;
        case SEC_E_ILLEGAL_MESSAGE:
        case SEC_E_DECRYPT_FAILURE:
        case SEC_E_MESSAGE_ALTERED:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() SSL_PROTOCOL_ERROR %X", err);
            return NET_SSL_PROTOCOL_ERROR;
        case SEC_E_LOGON_DENIED:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() BAD_SSL_CLIENT_AUTH_CERT %X", err);
            return NET_BAD_SSL_CLIENT_AUTH_CERT;
        case SEC_E_UNSUPPORTED_FUNCTION:
        case SEC_E_ALGORITHM_MISMATCH:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() SSL_VERSION_OR_CIPHER_MISMATCH %X", err);
            return NET_SSL_VERSION_OR_CIPHER_MISMATCH;
        case SEC_E_NO_CREDENTIALS:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() SSL_CLIENT_AUTH_CERT_NO_PRIVATE_KEY %X", err);
            return NET_SSL_CLIENT_AUTH_CERT_NO_PRIVATE_KEY;
        case SEC_E_INVALID_HANDLE:
        case SEC_E_INVALID_TOKEN:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() unexpected error %X", err);
            return NET_UNEXPECTED;
        case SEC_I_INCOMPLETE_CREDENTIALS:
            if (c && c->log.error) c->log.error(c->log.o, "net_security_error() SSL_CLIENT_AUTH_INCOMPLETE_CREDENTIALS %X", err);
            return NET_SSL_CLIENT_AUTH_CERT_NEEDED;
        case SEC_E_OK:
            return NET_OK;
        default:
            if (c && c->log.warning) c->log.warning(c->log.o, "net_security_error() error %X", err);
            return NET_FAILED;
    }
}

void net_init() {
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
}

void net_shutdown() {
    WSACleanup();
}

static int net_close_int(SOCKET sock) {
    shutdown(sock, SD_BOTH);
    return closesocket(sock);
}

static int net_inet_pton(int af, const char *src, void *dst) {
    struct sockaddr_storage ss;
    int size = sizeof (ss);
    char src_copy[INET6_ADDRSTRLEN + 1];
    memset(&(ss), 0, sizeof (ss));
    strncpy(src_copy, src, INET6_ADDRSTRLEN + 1);
    src_copy[INET6_ADDRSTRLEN] = 0;
    if (WSAStringToAddressA(src_copy, af, NULL, (struct sockaddr *) &ss, &size) == 0) {
        switch (af) {
            case AF_INET:
                *(struct in_addr *) dst = ((struct sockaddr_in *) &ss)->sin_addr;
                return 1;
            case AF_INET6:
                *(struct in6_addr *) dst = ((struct sockaddr_in6 *) &ss)->sin6_addr;
                return 1;
        }
    }
    return 0;
}

static const char *net_inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    struct sockaddr_storage ss;
    unsigned long s = size;
    memset(&(ss), 0, sizeof (ss));
    ss.ss_family = af;
    switch (af) {
        case AF_INET:
            ((struct sockaddr_in *) &ss)->sin_addr = *(struct in_addr *) src;
            break;
        case AF_INET6:
            ((struct sockaddr_in6 *) &ss)->sin6_addr = *(struct in6_addr *) src;
            break;
    }
    return (WSAAddressToStringA((struct sockaddr *) &ss, sizeof (ss), NULL, dst, &s) == 0) ? dst : NULL;
}

static void net_connect_int(net_t *net) {
    struct in6_addr serveraddr;
    char service[6];
    struct addrinfo *res, *rp, hints;
    int err = 0, on = 1;
    u_long nonblock = 1;

    _snprintf(service, sizeof (service), "%u", net->url.port);
    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_flags = 0;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    err = net_inet_pton(AF_INET, net->url.host, &serveraddr);
    if (err == 1) {
        hints.ai_family = AF_INET;
        hints.ai_flags |= AI_NUMERICHOST;
    } else {
        err = net_inet_pton(AF_INET6, net->url.host, &serveraddr);
        if (err == 1) {
            hints.ai_family = AF_INET6;
            hints.ai_flags |= AI_NUMERICHOST;
        }
    }

    if ((err = getaddrinfo(net->url.host, service, &hints, &res)) != 0) {
        if (net->log.error) net->log.error(net->log.o, "net_connect_int() cannot resolve address %s", net->url.host);
        net_error_int(net, err);
        net->sock = INVALID_SOCKET;
        return;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family != AF_INET && rp->ai_family != AF_INET6 &&
                rp->ai_socktype != SOCK_STREAM && rp->ai_protocol != IPPROTO_TCP) continue;
        if (net->log.debug) net->log.debug(net->log.o, "net_connect_int() connecting to %s:%d (%s)",
                net->url.host, net->url.port, rp->ai_family == AF_INET ? "IPv4" : "IPv6");
        
        if ((net->sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == INVALID_SOCKET) {
            if (net->log.error) net->log.error(net->log.o,
                    "net_connect_int() cannot create socket while connecting to %s:%d", net->url.host, net->url.port);
            net_error_int(net, net_error());
        } else {
            if (net->timeout > 0) {
                struct timeval tva;
                memset(&tva, 0, sizeof (tva));
                tva.tv_sec = net->timeout;
                tva.tv_usec = 0;
                if (setsockopt(net->sock, SOL_SOCKET, SO_RCVTIMEO, (char *) &tva, sizeof (tva)) < 0) {
                    net_error_int(net, net_error());
                }
                if (setsockopt(net->sock, SOL_SOCKET, SO_SNDTIMEO, (char *) &tva, sizeof (tva)) < 0) {
                    net_error_int(net, net_error());
                }
            }

            if (setsockopt(net->sock, IPPROTO_TCP, TCP_NODELAY, (void *) &on, sizeof (on)) < 0) {
                net_error_int(net, net_error());
            }
            /* turn off bind address checking, and allow port numbers to be reused */
            if (setsockopt(net->sock, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof (on)) < 0) {
                net_error_int(net, net_error());
            }

            ioctlsocket(net->sock, FIONBIO, &nonblock);
            err = connect(net->sock, rp->ai_addr, (DWORD) rp->ai_addrlen);
            if (err == 0) {
                if (net->log.debug) net->log.debug(net->log.o, "net_connect_int() connected to %s:%d (%s)", net->url.host, net->url.port,
                        rp->ai_family == AF_INET ? "IPv4" : "IPv6");
                break;
            } else if (err == SOCKET_ERROR && net_in_progress(net_error())) {
                fd_set fds, eds;
                struct timeval tv;
                memset(&tv, 0, sizeof (tv));
                tv.tv_sec = net->timeout > 0 ? net->timeout : NET_CONNECT_TIMEOUT;
                tv.tv_usec = 0;
                FD_ZERO(&fds);
                FD_ZERO(&eds);
                FD_SET(net->sock, &fds);
                FD_SET(net->sock, &eds);
                err = select(net->sock + 1, NULL, &fds, &eds, &tv);
                if (err == 0) {
                    if (net->log.error) net->log.error(net->log.o, "net_connect_int() timeout connecting to %s:%d (%s)", net->url.host, net->url.port,
                            rp->ai_family == AF_INET ? "IPv4" : "IPv6");
                    net_close_int(net->sock);
                    net->sock = INVALID_SOCKET;
                } else {
                    int ret, rlen = sizeof (ret);
                    if (FD_ISSET(net->sock, &fds)) {
                        if (getsockopt(net->sock, SOL_SOCKET, SO_ERROR, (char *) &ret, &rlen) == 0) {
                            if (net->log.debug) net->log.debug(net->log.o, "net_connect_int() connected to %s:%d (%s)", net->url.host, net->url.port,
                                    rp->ai_family == AF_INET ? "IPv4" : "IPv6");
                            break;
                        } else {
                            if (net->log.error) net->log.error(net->log.o, "net_connect_int() getsockopt error");
                            net_error_int(net, net_error());
                            net_close_int(net->sock);
                            net->sock = INVALID_SOCKET;
                        }
                    } else if (FD_ISSET(net->sock, &eds)) {
                        if (getsockopt(net->sock, SOL_SOCKET, SO_ERROR, (char *) &ret, &rlen) == 0) {
                            if (net_error() == WSAECONNREFUSED) {
                                if (net->log.error) net->log.error(net->log.o, "net_connect_int() connection refused error connecting to %s:%d (%s)",
                                        net->url.host, net->url.port, rp->ai_family == AF_INET ? "IPv4" : "IPv6");
                            } else {
                                if (net->log.error) net->log.error(net->log.o, "net_connect_int() socket error %d/%d", ret, net_error());
                            }
                        } else {
                            if (net->log.error) net->log.error(net->log.o, "net_connect_int() socket/getsockopt error %d", net_error());
                        }
                        if (err == SOCKET_ERROR) {
                            net_error_int(net, net_error());
                        }
                        net_close_int(net->sock);
                        net->sock = INVALID_SOCKET;
                    }
                }
            } else {
                if (net->log.error) net->log.error(net->log.o, "net_connect_int() connect error");
                net_error_int(net, net_error());
                net_close_int(net->sock);
                net->sock = INVALID_SOCKET;
            }
        }
    }
    if (net->sock != INVALID_SOCKET) {
        if (net->nonblocking == 0) {
            nonblock = 0;
            ioctlsocket(net->sock, FIONBIO, &nonblock);
        }
    }
    freeaddrinfo(res);
}

static void net_free_url(net_t *c) {
    if (c != NULL) {
        if (c->url.proto) free(c->url.proto);
        if (c->url.host) free(c->url.host);
        if (c->url.uri) free(c->url.uri);
        c->url.proto = NULL;
        c->url.host = NULL;
        c->url.uri = NULL;
    }
}

unsigned int http_status(net_t *c, const char *data) {
    unsigned int r = 0;
    char ver[4];
    char smsg[32];
    if (ISVALID(data) &&
            sscanf(data,
            "HTTP/%3[.012] %d %31[-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ]\r\n",
            ver, &r, smsg) == 3) {
        if (c->log.debug) c->log.debug(c->log.o, "http_status() HTTP/%s %d %s", ver, r, smsg);
    } else if (c->log.error) c->log.error(c->log.o, "http_status() error parsing status header");
    return r;
}

static int net_url(const char *u, net_t *c) {
    int port = 0;
    if (c != NULL) {
        c->url.proto = (char *) calloc(1, 6);
        c->url.host = (char *) calloc(1, 256);
        c->url.uri = (char *) calloc(1, 2048);
        if (c->url.proto == NULL || c->url.host == NULL || c->url.uri == NULL
                || u == NULL || u[0] == '\0') {
            net_free_url(c);
            return 0;
        }
        while (u) {
            if (sscanf(u, HD1, c->url.proto, c->url.host, &port, c->url.uri) == 4) {
                break;
            } else if (sscanf(u, HD2, c->url.proto, c->url.host, c->url.uri) == 3) {
                break;
            } else if (sscanf(u, HD3, c->url.proto, c->url.host, &port) == 3) {
                break;
            } else if (sscanf(u, HD4, c->url.proto, c->url.host) == 2) {
                break;
            } else {
                if (c->log.error) c->log.error(c->log.o, "net_url() error parsing %s", u);
                net_free_url(c);
                return 0;
            }
        }
        c->url.port = port;
        if (_stricmp(c->url.proto, "https") == 0) {
            c->url.ssl = 1;
        } else {
            c->url.ssl = 0;
        }
        if (_stricmp(c->url.proto, "https") == 0 && (c->url.port == 80 || c->url.port == 0)) {
            c->url.port = 443;
        } else if (_stricmp(c->url.proto, "http") == 0 && c->url.port == 0) {
            c->url.port = 80;
        } else {
            c->url.port = abs(c->url.port);
        }
    }
    return 1;
}

static void state_send_shutdown(net_t *c) {
    SecBufferDesc message;
    SecBuffer buffers[1] = {0};
    DWORD status, dwType = SCHANNEL_SHUTDOWN;
    buffers[0].pvBuffer = &dwType;
    buffers[0].BufferType = SECBUFFER_TOKEN;
    buffers[0].cbBuffer = sizeof (dwType);
    message.cBuffers = 1;
    message.pBuffers = buffers;
    message.ulVersion = SECBUFFER_VERSION;
    status = ApplyControlToken(&c->ssl.ctx, &message);
    if (SUCCEEDED(status)) {
        PBYTE pbMessage;
        TimeStamp tsExpiry;
        DWORD cbMessage, cbData, dwSSPIOutFlags,
                dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
                ASC_REQ_REPLAY_DETECT |
                ASC_REQ_CONFIDENTIALITY |
                ASC_REQ_EXTENDED_ERROR |
                ASC_REQ_ALLOCATE_MEMORY |
                ASC_REQ_STREAM;

        buffers[0].pvBuffer = NULL;
        buffers[0].BufferType = SECBUFFER_TOKEN;
        buffers[0].cbBuffer = 0;
        message.cBuffers = 1;
        message.pBuffers = buffers;
        message.ulVersion = SECBUFFER_VERSION;
        status = AcceptSecurityContext(&c->ssl.creds, &c->ssl.ctx, NULL,
                dwSSPIFlags, SECURITY_NATIVE_DREP, NULL,
                &message, &dwSSPIOutFlags, &tsExpiry);
        if (SUCCEEDED(status)) {
            pbMessage = buffers[0].pvBuffer;
            cbMessage = buffers[0].cbBuffer;
            if (pbMessage && cbMessage) {
                cbData = net_write(c, pbMessage, cbMessage);
                FreeContextBuffer(pbMessage);
            }
        }
    }
    c->ssl.on = 0;
}

void net_close(net_t *c) {
    if (c != NULL) {
        if (c->log.debug && c->url.host) c->log.debug(c->log.o, "net_close() %s:%u disconnecting", c->url.host, c->url.port);
        c->ssl.state = STATE_NONE;
        if (c->ssl.on) state_send_shutdown(c);
        if (c->ssl.recv_buffer_) free(c->ssl.recv_buffer_);
        if (c->ssl.send_buffer_.pvBuffer) {
            FreeContextBuffer(c->ssl.send_buffer_.pvBuffer);
            memset(&c->ssl.send_buffer_, 0, sizeof (c->ssl.send_buffer_));
        }
        if (c->ssl.store_) CertCloseStore(c->ssl.store_, 0);
        if (SecIsValidHandle(&c->ssl.ctx)) {
            DeleteSecurityContext(&c->ssl.ctx);
            SecInvalidateHandle(&c->ssl.ctx);
            FreeCredentialsHandle(&c->ssl.creds);
        }
        c->ssl.bytes_decrypted_ = 0;
        c->ssl.bytes_received_ = 0;
        c->ssl.writing_first_token_ = FALSE;
        c->ssl.renegotiating_ = FALSE;
        c->ssl.need_more_data_ = FALSE;

        if (c->sock != INVALID_SOCKET) {
            net_close_int(c->sock);
            c->sock = INVALID_SOCKET;
        }
        net_free_url(c);
        free(c);
    }
    c = NULL;
}

static int net_ssl_init_creds(net_t *c) {
    TimeStamp expiry;
    HCERTSTORE store = NULL;
    PCCERT_CONTEXT cctx = NULL;
    SECURITY_STATUS status;
    HANDLE hfile = INVALID_HANDLE_VALUE, hsection = NULL;
    void *pfx = NULL;
    SCHANNEL_CRED schannel_cred = {0};
    schannel_cred.dwVersion = SCHANNEL_CRED_VERSION;
    schannel_cred.grbitEnabledProtocols = 0;

    /* SCHANNEL will make its own copy of a certificate */

    if (!ISVALID(c->ssl.cfile) && ISVALID(c->ssl.cpass)) {
        /* look into system store; c->ssl.cpass == cn */
        store = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0, CERT_SYSTEM_STORE_LOCAL_MACHINE, "My");
        if (store) {
            cctx = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0, CERT_FIND_SUBJECT_STR, c->ssl.cpass, NULL);
            if (cctx) {
                char ccname[256];
                if (CertGetNameStringA(cctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, ccname, sizeof (ccname))) {
                    if (c->log.debug && c->url.host) c->log.debug(c->log.o, "net_ssl_init_creds() auth certificate \"%s\"", ccname);
                }
                schannel_cred.cCreds = 1;
                schannel_cred.paCred = &cctx;
            } else {
                if (c->log.warning && c->url.host) c->log.warning(c->log.o,
                        "net_ssl_init_creds() failed to locate certificate in local machine store (error: %X)", GetLastError());
            }
            c->ssl.store_ = store;
        }
    } else if (ISVALID(c->ssl.cfile) && ISVALID(c->ssl.cpass)) {
        CRYPT_DATA_BLOB blob;
        DWORD propId = CERT_KEY_PROV_INFO_PROP_ID;
        hfile = CreateFileA(c->ssl.cfile, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
        if (hfile != INVALID_HANDLE_VALUE) {
            hsection = CreateFileMapping(hfile, 0, PAGE_READONLY, 0, 0, 0);
            if (hsection != NULL) {
                pfx = MapViewOfFile(hsection, FILE_MAP_READ, 0, 0, 0);
                if (pfx != NULL) {
                    blob.cbData = GetFileSize(hfile, 0);
                    blob.pbData = (BYTE*) pfx;
                    if (PFXIsPFXBlob(&blob)) {
                        wchar_t *pass = utf8_decode(c->ssl.cpass, NULL);
                        store = PFXImportCertStore(&blob, pass, CRYPT_MACHINE_KEYSET | CRYPT_EXPORTABLE);
                        if (store) {
                            cctx = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    0, CERT_FIND_PROPERTY, &propId, NULL);
                            if (cctx) {
                                char ccname[256];
                                if (CertGetNameStringA(cctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, ccname, sizeof (ccname))) {
                                    if (c->log.debug && c->url.host) c->log.debug(c->log.o, "net_ssl_init_creds() auth certificate \"%s\"", ccname);
                                }
                                schannel_cred.cCreds = 1;
                                schannel_cred.paCred = &cctx;
                            } else {
                                if (c->log.warning && c->url.host) c->log.warning(c->log.o, "net_ssl_init_creds() failed to locate certificate in pkcs#12 store");
                            }
                            c->ssl.store_ = store;
                        }
                        if (pass) free(pass);
                    }
                }
            }
        }
    }

    if (c->ssl.version & SSLv3)
        schannel_cred.grbitEnabledProtocols |= SP_PROT_SSL3_CLIENT;
    if (c->ssl.version & TLSv1)
        schannel_cred.grbitEnabledProtocols |= SP_PROT_TLS1_CLIENT;
    if (c->ssl.version & TLSv11)
        schannel_cred.grbitEnabledProtocols |= SP_PROT_TLS1_1_CLIENT;
    if (c->ssl.version & TLSv12)
        schannel_cred.grbitEnabledProtocols |= SP_PROT_TLS1_2_CLIENT;

    schannel_cred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS |
            SCH_CRED_MANUAL_CRED_VALIDATION |
            SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

    if (!c->ssl.verifypeer) {
        schannel_cred.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
    }

    status = AcquireCredentialsHandleA(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL, &schannel_cred, NULL, NULL, &c->ssl.creds, &expiry);

    if (!store) {
        if (c->log.warning) c->log.warning(c->log.o, "net_ssl_init_creds() certificate store is not available");
    }
    if (cctx) CertFreeCertificateContext(cctx);
    if (pfx) UnmapViewOfFile(pfx);
    if (hsection) CloseHandle(hsection);
    if (INVALID_HANDLE_VALUE != hfile) CloseHandle(hfile);

    if (status != SEC_E_OK) {
        if (c->log.error) c->log.error(c->log.o, "net_ssl_init_creds() AcquireCredentialsHandle failed %X", status);
        return net_security_error(c, status);
    }
    return NET_OK;
}

static int net_ssl_init_ctx(net_t *c) {
    TimeStamp expiry;
    SECURITY_STATUS status;
    SecBufferDesc buffer_desc;
    DWORD out_flags, flags = ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY |
            ISC_RET_EXTENDED_ERROR |
            ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_STREAM;

    c->ssl.send_buffer_.pvBuffer = NULL;
    c->ssl.send_buffer_.BufferType = SECBUFFER_TOKEN;
    c->ssl.send_buffer_.cbBuffer = 0;

    buffer_desc.cBuffers = 1;
    buffer_desc.pBuffers = &c->ssl.send_buffer_;
    buffer_desc.ulVersion = SECBUFFER_VERSION;

    status = InitializeSecurityContextA(&c->ssl.creds, NULL, c->url.host, flags, 0, 0, NULL, 0, &c->ssl.ctx, &buffer_desc, &out_flags, &expiry);
    if (status != SEC_I_CONTINUE_NEEDED) {
        if (status == SEC_E_INVALID_HANDLE) {
            if (c->log.error) c->log.error(c->log.o, "net_ssl_init_ctx() invalid creds handle");
        }
        return net_security_error(c, status);
    }
    return NET_OK;
}

static int state_handshake_read(net_t *c) {
    int rs;
    int buf_len = RECV_BUF_SZ - c->ssl.bytes_received_;
    if (!c->ssl.recv_buffer_) {
        c->ssl.recv_buffer_ = (char *) malloc(RECV_BUF_SZ);
        if (!c->ssl.recv_buffer_) {
            if (c->log.error) c->log.error(c->log.o, "state_handshake_read() memory allocation error");
            return NET_UNEXPECTED;
        }
    }
    c->ssl.state = STATE_HANDSHAKE_READ_COMPLETE;
    if (buf_len <= 0) {
        if (c->log.error) c->log.error(c->log.o, "state_handshake_read() receive buffer is too small");
        return NET_UNEXPECTED;
    }
    c->ssl.transport_read_buf_ = (char *) malloc(buf_len);
    if (!c->ssl.transport_read_buf_) {
        if (c->log.error) c->log.error(c->log.o, "state_handshake_read() memory allocation error");
        return NET_UNEXPECTED;
    }
    rs = net_read_ssl_int(c, c->ssl.transport_read_buf_, buf_len);
    return rs;
}

static void state_complete_reneg(net_t *c) {
    c->ssl.renegotiating_ = FALSE;
    c->ssl.state = STATE_COMPLETED_RENEGOTIATION;
}

static void net_display_cert_chain(net_t *c, PCCERT_CONTEXT pServerCert, BOOL fLocal) {
    char szName[1024];
    PCCERT_CONTEXT pCurrentCert;
    PCCERT_CONTEXT pIssuerCert;
    DWORD dwVerificationFlags;

    if (!CertNameToStr(pServerCert->dwCertEncodingType,
            &pServerCert->pCertInfo->Subject,
            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
            szName, sizeof (szName))) {
        if (c->log.error) c->log.error(c->log.o, "net_display_cert_chain() error 0x%x building subject name", GetLastError());
    }
    if (fLocal) {
        if (c->log.debug) c->log.debug(c->log.o, "net_display_cert_chain() client cert subject: \"%s\"", szName);
    } else {
        if (c->log.debug) c->log.debug(c->log.o, "net_display_cert_chain() server cert subject: \"%s\"", szName);
    }
    if (!CertNameToStr(pServerCert->dwCertEncodingType,
            &pServerCert->pCertInfo->Issuer,
            CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
            szName, sizeof (szName))) {
        if (c->log.error) c->log.error(c->log.o, "net_display_cert_chain() error 0x%x building issuer name", GetLastError());
    }
    if (fLocal) {
        if (c->log.debug) c->log.debug(c->log.o, "net_display_cert_chain() client cert issuer: \"%s\"", szName);
    } else {
        if (c->log.debug) c->log.debug(c->log.o, "net_display_cert_chain() server cert issuer: \"%s\"", szName);
    }

    pCurrentCert = pServerCert;
    while (pCurrentCert != NULL) {
        dwVerificationFlags = 0;
        pIssuerCert = CertGetIssuerCertificateFromStore(pServerCert->hCertStore,
                pCurrentCert,
                NULL,
                &dwVerificationFlags);
        if (pIssuerCert == NULL) {
            if (pCurrentCert != pServerCert) {
                CertFreeCertificateContext(pCurrentCert);
            }
            break;
        }

        if (!CertNameToStr(pIssuerCert->dwCertEncodingType,
                &pIssuerCert->pCertInfo->Subject,
                CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                szName, sizeof (szName))) {
            if (c->log.error) c->log.error(c->log.o, "net_display_cert_chain() error 0x%x building subject name", GetLastError());
        }
        if (c->log.debug) c->log.debug(c->log.o, "net_display_cert_chain() CA subject: \"%s\"", szName);
        if (!CertNameToStr(pIssuerCert->dwCertEncodingType,
                &pIssuerCert->pCertInfo->Issuer,
                CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                szName, sizeof (szName))) {
            if (c->log.error) c->log.error(c->log.o, "net_display_cert_chain() error 0x%x building issuer name", GetLastError());
        }
        if (c->log.debug) c->log.debug(c->log.o, "net_display_cert_chain() CA issuer: \"%s\"", szName);

        if (pCurrentCert != pServerCert) {
            CertFreeCertificateContext(pCurrentCert);
        }
        pCurrentCert = pIssuerCert;
        pIssuerCert = NULL;
    }
}

static DWORD verify_server_certificate(net_t *c, PCCERT_CONTEXT server_cert_handle, DWORD dwCertFlags) {
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA httpsPolicy;
    CERT_CHAIN_POLICY_PARA policyPara;
    CERT_CHAIN_POLICY_STATUS policyStatus;
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT chainContext = NULL;
    LPSTR rgszUsages[] = {szOID_PKIX_KP_SERVER_AUTH,
        szOID_SERVER_GATED_CRYPTO, szOID_SGC_NETSCAPE};
    DWORD status = SEC_E_OK,
            cUsages = sizeof (rgszUsages) / sizeof (LPSTR);

    memset(&chainPara, 0x00, sizeof (chainPara));
    chainPara.cbSize = sizeof (chainPara);
    chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chainPara.RequestedUsage.Usage.cUsageIdentifier = cUsages;
    chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

    memset(&httpsPolicy, 0x00, sizeof (httpsPolicy));
    httpsPolicy.cbStruct = sizeof (httpsPolicy);
    httpsPolicy.dwAuthType = AUTHTYPE_SERVER;
    httpsPolicy.fdwChecks = dwCertFlags;

    memset(&policyStatus, 0x00, sizeof (policyStatus));
    policyStatus.cbSize = sizeof (policyStatus);

    if (server_cert_handle != NULL && ISVALID(c->url.host)) {
        if (CertGetCertificateChain(NULL, server_cert_handle, NULL, c->ssl.store_,
                &chainPara, 0, NULL, &chainContext)) {
            httpsPolicy.pwszServerName = utf8_decode(c->url.host, NULL);
            memset(&policyPara, 0x00, sizeof (policyPara));
            policyPara.cbSize = sizeof (policyPara);
            policyPara.pvExtraPolicyPara = &httpsPolicy;
            if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chainContext,
                    &policyPara, &policyStatus)) {
                status = GetLastError();
                if (c->log.error) c->log.error(c->log.o, "verify_server_certificate() CertVerifyCertificateChainPolicy failed %X", status);
            }

            if (policyStatus.dwError) {
                status = policyStatus.dwError;
                if (c->log.error) c->log.error(c->log.o, "verify_server_certificate() CertVerifyCertificateChainPolicy error %X", status);
            }

            if (httpsPolicy.pwszServerName) free(httpsPolicy.pwszServerName);
        } else {
            status = GetLastError();
            if (c->log.error) c->log.error(c->log.o, "verify_server_certificate() CertGetCertificateChain failed %X", status);
        }
    } else {
        status = SEC_E_WRONG_PRINCIPAL;
    }
    if (chainContext) CertFreeCertificateChain(chainContext);
    return status;
}

static int state_handshake_complete(net_t *c) {
    DWORD dwCertFlags = 0;
    PCCERT_CONTEXT server_cert_handle = NULL;
    SECURITY_STATUS status = QueryContextAttributesA(&c->ssl.ctx, SECPKG_ATTR_STREAM_SIZES, (VOID*) & c->ssl.stream_sizes_);
    if (status != SEC_E_OK) {
        if (c->log.error) c->log.error(c->log.o, "state_handshake_complete() QueryContextAttributes (stream sizes) failed %d", status);
        return net_security_error(c, status);
    }

    status = QueryContextAttributesA(&c->ssl.ctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (VOID*) & server_cert_handle);
    if (status != SEC_E_OK) {
        if (c->log.error) c->log.error(c->log.o, "state_handshake_complete() QueryContextAttributes (remote cert) failed %d", status);
        return net_security_error(c, status);
    }

    net_display_cert_chain(c, server_cert_handle, FALSE);

    if (c->ssl.verifypeer == 1) {
        status = verify_server_certificate(c, server_cert_handle, dwCertFlags);
        if (status != SEC_E_OK) {
            return net_security_error(c, status);
        }
    }

    state_complete_reneg(c);
    CertFreeCertificateContext(server_cert_handle);
    return NET_OK;
}

static int state_call_init_sctx(net_t *c) {

    if (c->log.debug) c->log.debug(c->log.o, "state_call_init_sctx() status %X", c->ssl.isc_status_);

    if (c->ssl.isc_status_ == SEC_E_INCOMPLETE_MESSAGE) {
        c->ssl.state = STATE_HANDSHAKE_READ;
        return NET_OK;
    }

    if (c->ssl.isc_status_ == SEC_E_OK) {
        if (c->ssl.in_buffers_[1].BufferType == SECBUFFER_EXTRA) {
            memmove(c->ssl.recv_buffer_, c->ssl.recv_buffer_ + (c->ssl.bytes_received_ - c->ssl.in_buffers_[1].cbBuffer),
                    c->ssl.in_buffers_[1].cbBuffer);
            c->ssl.bytes_received_ = c->ssl.in_buffers_[1].cbBuffer;
        } else {
            c->ssl.bytes_received_ = 0;
        }
        return state_handshake_complete(c);
    }

    if (FAILED(c->ssl.isc_status_)) {
        int result;
        if (c->log.error) c->log.error(c->log.o, "state_call_init_sctx() failed %X", c->ssl.isc_status_);
        if (c->ssl.isc_status_ == SEC_E_INTERNAL_ERROR) {
            return NET_SSL_CLIENT_AUTH_PRIVATE_KEY_ACCESS_DENIED;
        }
        result = net_security_error(c, c->ssl.isc_status_);
        if (net_cert_error(result)) {
            return NET_BAD_SSL_CLIENT_AUTH_CERT;
        }
        return result;
    }

    if (c->ssl.isc_status_ == SEC_I_INCOMPLETE_CREDENTIALS) {
        if (c->log.error) c->log.error(c->log.o, "state_call_init_sctx() failed. server requires authentication");
        return NET_SSL_CLIENT_AUTH_CERT_NEEDED;
    }

    if (c->ssl.isc_status_ == SEC_I_NO_RENEGOTIATION) {
        return NET_SSL_NO_RENEGOTIATION;
    }

    if (c->ssl.in_buffers_[1].BufferType == SECBUFFER_EXTRA) {
        memmove(c->ssl.recv_buffer_,
                c->ssl.recv_buffer_ + (c->ssl.bytes_received_ - c->ssl.in_buffers_[1].cbBuffer),
                c->ssl.in_buffers_[1].cbBuffer);
        c->ssl.bytes_received_ = c->ssl.in_buffers_[1].cbBuffer;
        c->ssl.state = STATE_HANDSHAKE_READ_COMPLETE;
        c->ssl.ignore_ok_result_ = TRUE;
        return NET_OK;
    }
    c->ssl.bytes_received_ = 0;
    c->ssl.state = STATE_HANDSHAKE_READ;
    return NET_OK;
}

static int state_handshake_read_complete(net_t *c, int result) {
    TimeStamp expiry;
    DWORD out_flags;
    DWORD flags;
    SecBufferDesc in_buffer_desc, out_buffer_desc;

    if (result < 0) {
        if (c->ssl.transport_read_buf_) free(c->ssl.transport_read_buf_);
        c->ssl.transport_read_buf_ = NULL;
        return result;
    }

    if (c->ssl.transport_read_buf_) {
        char* buf = c->ssl.recv_buffer_ + c->ssl.bytes_received_;
        memcpy(buf, c->ssl.transport_read_buf_, result);
        if (c->ssl.transport_read_buf_) free(c->ssl.transport_read_buf_);
        c->ssl.transport_read_buf_ = NULL;
    }

    if (result == 0 && !c->ssl.ignore_ok_result_)
        return NET_SSL_PROTOCOL_ERROR;

    c->ssl.ignore_ok_result_ = FALSE;
    c->ssl.bytes_received_ += result;

    flags = ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY |
            ISC_RET_EXTENDED_ERROR |
            ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_STREAM |
            ISC_REQ_USE_SUPPLIED_CREDS;

    in_buffer_desc.cBuffers = 2;
    in_buffer_desc.pBuffers = c->ssl.in_buffers_;
    in_buffer_desc.ulVersion = SECBUFFER_VERSION;

    c->ssl.in_buffers_[0].pvBuffer = c->ssl.recv_buffer_;
    c->ssl.in_buffers_[0].cbBuffer = c->ssl.bytes_received_;
    c->ssl.in_buffers_[0].BufferType = SECBUFFER_TOKEN;

    c->ssl.in_buffers_[1].pvBuffer = NULL;
    c->ssl.in_buffers_[1].cbBuffer = 0;
    c->ssl.in_buffers_[1].BufferType = SECBUFFER_EMPTY;

    out_buffer_desc.cBuffers = 1;
    out_buffer_desc.pBuffers = &c->ssl.send_buffer_;
    out_buffer_desc.ulVersion = SECBUFFER_VERSION;

    c->ssl.send_buffer_.pvBuffer = NULL;
    c->ssl.send_buffer_.BufferType = SECBUFFER_TOKEN;
    c->ssl.send_buffer_.cbBuffer = 0;

    c->ssl.isc_status_ = InitializeSecurityContextA(&c->ssl.creds, &c->ssl.ctx, NULL, flags, 0, 0, &in_buffer_desc, 0,
            NULL, &out_buffer_desc, &out_flags, &expiry);
    if (c->ssl.isc_status_ == SEC_E_INVALID_TOKEN) {
        if (c->log.error) c->log.error(c->log.o, "state_handshake_read_complete() InitializeSecurityContext failed %X", c->ssl.isc_status_);
        return NET_SSL_PROTOCOL_ERROR;
    }

    if (c->ssl.send_buffer_.cbBuffer != 0 &&
            (c->ssl.isc_status_ == SEC_E_OK ||
            c->ssl.isc_status_ == SEC_I_CONTINUE_NEEDED ||
            (FAILED(c->ssl.isc_status_) && (out_flags & ISC_RET_EXTENDED_ERROR)))) {
        c->ssl.state = STATE_HANDSHAKE_WRITE;
        return NET_OK;
    }
    return state_call_init_sctx(c);
}

static int state_handshake_write(net_t *c) {
    ssize_t rv = 0;
    const char* buf = (char *) (c->ssl.send_buffer_.pvBuffer) + c->ssl.bytes_sent_;
    int buf_len = c->ssl.send_buffer_.cbBuffer - c->ssl.bytes_sent_;
    c->ssl.transport_write_buf_ = (char *) malloc(buf_len);
    if (!c->ssl.transport_write_buf_) {
        if (c->log.error) c->log.error(c->log.o, "state_handshake_write() memory allocation error");
        return NET_UNEXPECTED;
    }
    memcpy(c->ssl.transport_write_buf_, buf, buf_len);
    c->ssl.state = STATE_HANDSHAKE_WRITE_COMPLETE;
    rv = net_write(c, c->ssl.transport_write_buf_, buf_len);
    return rv;
}

static int state_handshake_write_complete(net_t *c, int result) {
    if (c->ssl.transport_write_buf_) free(c->ssl.transport_write_buf_);
    c->ssl.transport_write_buf_ = NULL;
    if (result < 0)
        return result;

    c->ssl.bytes_sent_ += result;

    if (c->ssl.bytes_sent_ >= c->ssl.send_buffer_.cbBuffer) {
        BOOL overflow = (c->ssl.bytes_sent_ > c->ssl.send_buffer_.cbBuffer);
        FreeContextBuffer(c->ssl.send_buffer_.pvBuffer);
        memset(&c->ssl.send_buffer_, 0, sizeof (c->ssl.send_buffer_));
        c->ssl.bytes_sent_ = 0;
        if (overflow) {
            if (c->log.error) c->log.error(c->log.o, "state_handshake_write_complete() overflow");
            return NET_UNEXPECTED;
        }
        if (c->ssl.writing_first_token_) {
            c->ssl.writing_first_token_ = FALSE;
            c->ssl.state = STATE_HANDSHAKE_READ;
            return NET_OK;
        }
        return state_call_init_sctx(c);
    }
    c->ssl.state = STATE_HANDSHAKE_WRITE;
    return NET_OK;
}

static int state_verify_cert(net_t *c) {
    c->ssl.state = STATE_VERIFY_CERT_COMPLETE;
    return NET_OK;
}

static int state_verify_cert_complete(net_t *c, int result) {
    if (c->ssl.renegotiating_) {
        state_complete_reneg(c);
        return result;
    }
    c->ssl.state = STATE_COMPLETED_HANDSHAKE;
    return result;
}

static int state_payload_read_complete(net_t *c, int result) {
    if (result == NET_IO_PENDING)
        return result;
    c->ssl.need_more_data_ = FALSE;
    if (result <= 0) {
        if (c->ssl.transport_read_buf_) free(c->ssl.transport_read_buf_);
        c->ssl.transport_read_buf_ = NULL;
        if (result == 0 && c->ssl.bytes_received_ != 0) {
            return NET_SSL_PROTOCOL_ERROR;
        }
        return result;
    }
    if (c->ssl.transport_read_buf_) {
        char* buf = c->ssl.recv_buffer_ + c->ssl.bytes_received_;
        memcpy(buf, c->ssl.transport_read_buf_, result);
        free(c->ssl.transport_read_buf_);
        c->ssl.transport_read_buf_ = NULL;
    }
    c->ssl.bytes_received_ += result;
    return result;
}

static int state_payload_decrypt(net_t *c) {
    int i, len = 0;
    while (c->ssl.bytes_received_) {
        SecBuffer buffers[4];
        SecBufferDesc buffer_desc;
        SECURITY_STATUS status;

        buffers[0].pvBuffer = c->ssl.recv_buffer_;
        buffers[0].cbBuffer = c->ssl.bytes_received_;
        buffers[0].BufferType = SECBUFFER_DATA;

        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;

        buffer_desc.cBuffers = 4;
        buffer_desc.pBuffers = buffers;
        buffer_desc.ulVersion = SECBUFFER_VERSION;

        status = DecryptMessage(&c->ssl.ctx, &buffer_desc, 0, NULL);
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            c->ssl.need_more_data_ = TRUE;
            return state_payload_read(c);
        }
        if (status == SEC_I_CONTEXT_EXPIRED) {
            c->ssl.bytes_received_ = 0;
            return NET_OK;
        }
        if (status != SEC_E_OK && status != SEC_I_RENEGOTIATE) {
            return net_security_error(c, status);
        }

        c->ssl.decrypted_ptr_ = NULL;
        c->ssl.bytes_decrypted_ = 0;
        c->ssl.received_ptr_ = NULL;
        c->ssl.bytes_received_ = 0;
        for (i = 1; i < 4; i++) {
            switch (buffers[i].BufferType) {
                case SECBUFFER_DATA:
                    c->ssl.decrypted_ptr_ = (char*) (buffers[i].pvBuffer);
                    c->ssl.bytes_decrypted_ = buffers[i].cbBuffer;
                    break;
                case SECBUFFER_EXTRA:
                    c->ssl.received_ptr_ = (char*) (buffers[i].pvBuffer);
                    c->ssl.bytes_received_ = buffers[i].cbBuffer;
                    break;
                default:
                    break;
            }
        }

        if (c->ssl.bytes_decrypted_ != 0) {
            len = c->ssl.bytes_decrypted_;
            c->ssl.user_read_buf_ = realloc(c->ssl.user_read_buf_, c->ssl.user_read_buf_len_ + len + 1);
            if (!c->ssl.user_read_buf_) {
                if (c->log.error) c->log.error(c->log.o, "state_payload_decrypt() memory allocation error");
                return NET_UNEXPECTED;
            }
            memcpy(c->ssl.user_read_buf_ + c->ssl.user_read_buf_len_, c->ssl.decrypted_ptr_, len);
            c->ssl.user_read_buf_len_ += len;
            c->ssl.decrypted_ptr_ += len;
            c->ssl.bytes_decrypted_ -= len;
        }
        if (c->ssl.bytes_decrypted_ == 0) {
            c->ssl.decrypted_ptr_ = NULL;
            if (c->ssl.bytes_received_ != 0) {
                memmove(c->ssl.recv_buffer_, c->ssl.received_ptr_, c->ssl.bytes_received_);
                c->ssl.received_ptr_ = c->ssl.recv_buffer_;
            }
        }

        if (status == SEC_I_RENEGOTIATE) {
            if (c->ssl.bytes_received_ != 0) {
                return NET_SSL_RENEGOTIATION_REQUESTED;
            }
            if (len != 0) {
                return NET_SSL_RENEGOTIATION_REQUESTED;
            }
            c->ssl.renegotiating_ = TRUE;
            c->ssl.ignore_ok_result_ = TRUE;
            c->ssl.state = STATE_HANDSHAKE_READ_COMPLETE;
            return net_ssl_loop(c, NET_OK);
        }

        if (len) {
            return state_payload_read(c);
        }
    }

    if (len == 0)
        return state_payload_read(c);

    return len;
}

static int state_payload_read(net_t *c) {
    int rv;
    int buf_len = RECV_BUF_SZ - c->ssl.bytes_received_;
    if (buf_len <= 0) {
        return NET_FAILED;
    }
    if (!c->ssl.bytes_received_ || c->ssl.need_more_data_) {
        c->ssl.transport_read_buf_ = (char *) malloc(buf_len);
        if (!c->ssl.transport_read_buf_) {
            if (c->log.error) c->log.error(c->log.o, "state_payload_read() memory allocation error");
            return NET_UNEXPECTED;
        }
        rv = net_read_ssl_int(c, c->ssl.transport_read_buf_, buf_len);
        if (rv != NET_IO_PENDING)
            rv = state_payload_read_complete(c, rv);
        if (rv <= 0)
            return rv;
    }
    return state_payload_decrypt(c);
}

static int state_reneg_complete(net_t *c, int result) {
    c->ssl.state = STATE_COMPLETED_HANDSHAKE;
    if (result != NET_OK)
        return result;
    return state_payload_read(c);
}

static int state_payload_encrypt(net_t *c) {
    SecBuffer buffers[4];
    SecBufferDesc buffer_desc;
    SECURITY_STATUS status;
    ULONG message_len = min(
            c->ssl.stream_sizes_.cbMaximumMessage, (ULONG) c->ssl.user_write_buf_len_);
    ULONG alloc_len =
            message_len + c->ssl.stream_sizes_.cbHeader + c->ssl.stream_sizes_.cbTrailer;
    c->ssl.user_write_buf_len_ = message_len;

    c->ssl.payload_send_buffer_ = malloc(alloc_len);
    if (!c->ssl.payload_send_buffer_) {
        if (c->log.error) c->log.error(c->log.o, "state_payload_encrypt() memory allocation error");
        return NET_UNEXPECTED;
    }

    memcpy(&c->ssl.payload_send_buffer_[c->ssl.stream_sizes_.cbHeader],
            c->ssl.user_write_buf_, message_len);

    buffers[0].pvBuffer = c->ssl.payload_send_buffer_;
    buffers[0].cbBuffer = c->ssl.stream_sizes_.cbHeader;
    buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    buffers[1].pvBuffer = &c->ssl.payload_send_buffer_[c->ssl.stream_sizes_.cbHeader];
    buffers[1].cbBuffer = message_len;
    buffers[1].BufferType = SECBUFFER_DATA;

    buffers[2].pvBuffer = &c->ssl.payload_send_buffer_[c->ssl.stream_sizes_.cbHeader +
            message_len];
    buffers[2].cbBuffer = c->ssl.stream_sizes_.cbTrailer;
    buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    buffers[3].BufferType = SECBUFFER_EMPTY;

    buffer_desc.cBuffers = 4;
    buffer_desc.pBuffers = buffers;
    buffer_desc.ulVersion = SECBUFFER_VERSION;

    status = EncryptMessage(&c->ssl.ctx, 0, &buffer_desc, 0);
    if (FAILED(status)) {
        if (c->log.debug) c->log.debug(c->log.o, "state_payload_encrypt() EncryptMessage failed %X", status);
        return net_security_error(c, status);
    }

    c->ssl.payload_send_buffer_len_ = buffers[0].cbBuffer +
            buffers[1].cbBuffer + buffers[2].cbBuffer;
    return NET_OK;
}

static int state_payload_write(net_t *c) {
    const char* buf = c->ssl.payload_send_buffer_ + c->ssl.bytes_sent_;
    int rv, buf_len = c->ssl.payload_send_buffer_len_ - c->ssl.bytes_sent_;
    c->ssl.transport_write_buf_ = (char *) malloc(buf_len);
    if (!c->ssl.transport_write_buf_) {
        if (c->log.error) c->log.error(c->log.o, "state_payload_write() memory allocation error");
        return NET_UNEXPECTED;
    }
    memcpy(c->ssl.transport_write_buf_, buf, buf_len);
    rv = net_write(c, c->ssl.transport_write_buf_, buf_len);
    if (rv != NET_IO_PENDING)
        rv = state_payload_write_complete(c, rv);
    return rv;
}

static int state_payload_write_complete(net_t *c, int result) {
    if (c->ssl.transport_write_buf_) free(c->ssl.transport_write_buf_);
    c->ssl.transport_write_buf_ = NULL;
    if (result < 0)
        return result;
    c->ssl.bytes_sent_ += result;
    if (c->ssl.bytes_sent_ >= c->ssl.payload_send_buffer_len_) {
        BOOL overflow = (c->ssl.bytes_sent_ > c->ssl.payload_send_buffer_len_);
        if (c->ssl.payload_send_buffer_) free(c->ssl.payload_send_buffer_);
        c->ssl.payload_send_buffer_len_ = 0;
        c->ssl.bytes_sent_ = 0;
        if (overflow) {
            return NET_UNEXPECTED;
        }
        return c->ssl.user_write_buf_len_;
    }
    return state_payload_write(c);
}

static int net_ssl_loop(net_t *c, int last_io_result) {
    int rv = last_io_result;
    do {
        ssl_state_t state = c->ssl.state;
        if (c->log.debug) c->log.debug(c->log.o, "net_ssl_loop() state %d (%d)", state, rv);
        c->ssl.state = STATE_NONE;
        switch (state) {
            case STATE_HANDSHAKE_READ:
                rv = state_handshake_read(c);
                break;
            case STATE_HANDSHAKE_READ_COMPLETE:
                rv = state_handshake_read_complete(c, rv);
                break;
            case STATE_HANDSHAKE_WRITE:
                rv = state_handshake_write(c);
                break;
            case STATE_HANDSHAKE_WRITE_COMPLETE:
                rv = state_handshake_write_complete(c, rv);
                break;
            case STATE_VERIFY_CERT:
                rv = state_verify_cert(c);
                break;
            case STATE_VERIFY_CERT_COMPLETE:
                rv = state_verify_cert_complete(c, rv);
                break;
            case STATE_COMPLETED_RENEGOTIATION:
                rv = state_reneg_complete(c, rv);
                break;
            case STATE_COMPLETED_HANDSHAKE:
                c->ssl.state = STATE_COMPLETED_HANDSHAKE;
                return rv;
            default:
                rv = NET_UNEXPECTED;
                if (c->log.error) c->log.error(c->log.o, "net_ssl_loop() unexpected state %d", state);
                break;
        }
    } while (rv != NET_IO_PENDING && c->ssl.state != STATE_NONE);

    return rv;
}

static int net_ssl_connect(net_t *c) {
    int rv;
    c->ssl.user_read_buf_len_ = 0;
    c->ssl.user_write_buf_len_ = 0;
    c->ssl.state = STATE_NONE;
    c->ssl.recv_buffer_ = NULL;
    c->ssl.isc_status_ = SEC_E_OK;
    c->ssl.payload_send_buffer_len_ = 0;
    c->ssl.bytes_sent_ = 0;
    c->ssl.decrypted_ptr_ = NULL;
    c->ssl.bytes_decrypted_ = 0;
    c->ssl.received_ptr_ = NULL;
    c->ssl.bytes_received_ = 0;
    c->ssl.writing_first_token_ = FALSE;
    c->ssl.ignore_ok_result_ = FALSE;
    c->ssl.renegotiating_ = FALSE;
    c->ssl.need_more_data_ = FALSE;
    c->ssl.transport_read_buf_ = NULL;
    rv = net_ssl_init_creds(c);
    if (rv == NET_OK) {
        rv = net_ssl_init_ctx(c);
        if (rv == NET_OK) {
            c->ssl.writing_first_token_ = TRUE;
            c->ssl.state = STATE_HANDSHAKE_WRITE;
            rv = net_ssl_loop(c, NET_OK);
        }
    }
    return rv;
}

net_t * net_connect_url(const char *url, const char *cfile, const char *cpass, unsigned int timeout, net_log_t *log) {
    net_t *n = NULL;
    if (ISVALID(url)) {
        n = (net_t *) calloc(1, sizeof (net_t));
        if (n != NULL) {
            n->sock = INVALID_SOCKET;
            n->keepalive = 0;
            n->nonblocking = 0;
            n->timeout = timeout;
            if (log != NULL) {
                n->log.o = log->o;
                n->log.info = log->info;
                n->log.warning = log->warning;
                n->log.error = log->error;
                n->log.debug = log->debug;
            }
            if (net_url(url, n)) {
                if (n->log.debug) n->log.debug(n->log.o, "net_connect_url() connecting to %s:%d", n->url.host, n->url.port);
                net_connect_int(n);
                if (n->sock != INVALID_SOCKET) {
                    if (n->url.ssl) {
                        n->ssl.version = SSLv3 | TLSv1;
                        n->ssl.verifypeer = 0;
                        /* CertGetCertificateChain could be slow when this is set to 1.
                         *  Edit the “Certificate Path Validation Settings” in the group policy editor: 
                         *  Computer Configuration → Windows Settings → Public Key Policies → Certificate Path Validation Settings
                         *  Change the timeout values to 5 seconds each like this: Default URL retrieval timeout (in seconds) = 5 
                         *  Default path validation cumulative retrieval timeout (in seconds) = 5 
                         */
                        n->ssl.cfile = (char *) cfile;
                        n->ssl.cpass = (char *) cpass;
                        n->ssl.on = net_ssl_connect(n) == NET_OK ? 1 : 0;
                    }
                    return n;
                }
            }
        }
    }
    net_free_url(n);
    net_close(n);
    return NULL;
}

static ssize_t net_read(net_t *c, char **data) {
    ssize_t out_len = 0, len = 0;
    u_long n = 0;
#define READ_BUFFER_SIZE 8192
    char *tmp = NULL;
    if ((tmp = malloc(READ_BUFFER_SIZE)) != NULL) {
        do {
            n = 0;
            memset(&tmp[0], 0x00, READ_BUFFER_SIZE);
            len = recv(c->sock, tmp, READ_BUFFER_SIZE, 0);
            if (len == 0) {
                if (net_error() != 0) net_error_int(c, net_error());
                break; /* connection has been gracefully closed */
            } else if (len > 0) {
                *data = (char *) realloc(*data, out_len + len + 1);
                if (*data == NULL) {
                    if (c->log.error) c->log.error(c->log.o, "net_read() memory allocation error");
                    break;
                }
                memcpy((*data) + out_len, tmp, len);
                out_len += len;
                if (ioctlsocket(c->sock, FIONREAD, &n) == SOCKET_ERROR) {
                    net_error_int(c, net_error());
                    break;
                }
                if (n > 0) {
                    if (c->log.debug) c->log.debug(c->log.o, "net_read() more data available (%d), continue reading", n);
                }
            } else if (len == SOCKET_ERROR && net_in_progress(net_error())) {
                if (wait_for_io(c, SOCKET_IO_WAIT_TIME, 1) == 0) {
                    len = 1;
                }
            } else {
                if (net_error() == WSAETIMEDOUT) {
                    break;
                }
                net_error_int(c, net_error());
                break;
            }
        } while (len > 0);
        free(tmp);
    } else {
        if (c->log.error) c->log.error(c->log.o, "net_read() memory allocation error");
    }
    if (*data != NULL) {
        (*data)[out_len] = 0;
    } else out_len = 0;
    if (c->log.debug) c->log.debug(c->log.o, "net_read() read %ld byte(s) from %s:%d", out_len, c->url.host, c->url.port);
    return out_len;
}

static ssize_t net_write(net_t *c, const char *data, const size_t sz) {
    ssize_t wrtlen, ttllen = 0, reqlen;
    if (c->log.debug) c->log.debug(c->log.o, "net_write() sending %ld byte(s) to %s:%d", sz, c->url.host, c->url.port);
    for (ttllen = 0, reqlen = sz; reqlen > 0;) {
        wrtlen = send(c->sock, data + ttllen, reqlen, 0);
        if (wrtlen == SOCKET_ERROR &&
                net_in_progress(net_error())) {
            if (wait_for_io(c, SOCKET_IO_WAIT_TIME, 0) == 0) {
                continue;
            }
        } else if (wrtlen == SOCKET_ERROR) return 0;
        if (c->log.debug) c->log.debug(c->log.o, "net_write() sent %ld byte(s)", wrtlen);
        ttllen += wrtlen;
        reqlen -= wrtlen;
    }
    return ttllen;
}

static ssize_t net_read_ssl(net_t *c, char **data) {
    int rv;
    if (c->ssl.bytes_decrypted_ != 0) {
        int len = c->ssl.bytes_decrypted_;
        *data = malloc(len + 1);
        if (!(*data)) {
            if (c->log.error) c->log.error(c->log.o, "net_read_ssl() memory allocation error");
            return 0;
        }
        memcpy(*data, c->ssl.decrypted_ptr_, len);
        *data[len] = 0;
        c->ssl.decrypted_ptr_ += len;
        c->ssl.bytes_decrypted_ -= len;
        if (c->ssl.bytes_decrypted_ == 0) {
            c->ssl.decrypted_ptr_ = NULL;
            if (c->ssl.bytes_received_ != 0) {
                memmove(c->ssl.recv_buffer_, c->ssl.received_ptr_, c->ssl.bytes_received_);
                c->ssl.received_ptr_ = c->ssl.recv_buffer_;
            }
        }
        return len;
    }
    c->ssl.user_read_buf_ = NULL;
    c->ssl.user_read_buf_len_ = 0;
    rv = state_payload_read(c);
    if (c->ssl.user_read_buf_) {
        c->ssl.user_read_buf_[c->ssl.user_read_buf_len_] = 0;
        *data = c->ssl.user_read_buf_;
    }
    return c->ssl.user_read_buf_len_;
}

static ssize_t net_write_ssl(net_t *c, const char *buf, const size_t buf_len) {
    int rv;
    c->ssl.user_write_buf_ = buf;
    c->ssl.user_write_buf_len_ = (unsigned int) buf_len;
    rv = state_payload_encrypt(c);
    if (rv != NET_OK)
        return rv;
    rv = state_payload_write(c);
    return rv;
}

ssize_t http_post(net_t *c, const char * uri, const char **hdrs, size_t hdrsz, const char * post, const size_t len, char ** buff) {
    char *data = NULL;
    size_t i;
    ssize_t rlen = 0;
    if (c != NULL && c->sock != INVALID_SOCKET) {
        int size = asprintf(&data, "POST /%s HTTP/1.0\r\n"
                "Host: %s:%d\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "X-Requested-With: ADPlugin\r\n"
                "Connection: close\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                "Content-Length: %ld\r\n",
                (ISVALID(uri) ? uri : ISVALID(c->url.uri) ? c->url.uri : "/"), c->url.host, c->url.port, USERAGENT, len);
        if (data == NULL) return -1;
        /*add request headers*/
        for (i = 0; i < hdrsz; i++) {
            asprintf(&data, "%s%s", data, hdrs[i]);
        }
        size = asprintf(&data, "%s\r\n", data);
        if (size > 0) {
            data = (char *) realloc(data, size + len + 1);
            if (data != NULL) {
                if (len > 0) {
                    if (!memcpy(data + size, post, len)) {
                        if (c->log.error) c->log.error(c->log.o, "http_post() memory copy error");
                        free(data);
                        return -1;
                    }
                }
                if (c->log.debug) c->log.debug(c->log.o, "http_post() request size: %d byte(s)", size + len);
                rlen = c->ssl.on ? net_write_ssl(c, data, size + len) : net_write(c, data, size + len);
                if (rlen > 0) {
                    rlen = c->ssl.on ? net_read_ssl(c, buff) : net_read(c, buff);
                    if (rlen > 0 && c->log.debug) c->log.debug(c->log.o, "http_post() response:\n%s", LOGEMPTY(*buff));
                    if (rlen <= 0 && c->log.debug) c->log.debug(c->log.o, "http_post() empty response");
                }
                free(data);
            } else {
                if (c->log.error) c->log.error(c->log.o, "http_post() memory allocation error");
            }
        }
    }
    return rlen;
}
