/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2012 ForgeRock Inc. All rights reserved.
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
 * "Portions Copyrighted [2012] [Forgerock Inc]"
 **/

#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

#define TIMEOUT 4000//4 sec

typedef enum {
    IDM_MEMORY_ERROR = 1000,
    IDM_SET_TIMEOUT_ERROR,
    IDM_NET_TIMEOUT,
    IDM_NET_REQUEST_OPEN_ERROR,
    IDM_NET_REQUEST_CB_ERROR,
    IDM_NET_REQUEST_SEND_ERROR,
    IDM_FILE_OPEN_ERROR,
    IDM_MMAP_CREATE_ERROR,
    IDM_MMAP_ERROR,
    IDM_PFX_OPEN_ERROR,
    IDM_CERT_ENUM_ERROR
} IDM_ERROR;

typedef enum {
    NO_AUTH = 0,
    BASIC_AUTH,
    CERT_AUTH,
    IDM_HEADER_AUTH
} AUTH_TYPE;

typedef struct {
    DWORD id;
    HINTERNET hRequest;
    DWORD dwSize;
    DWORD dwTotalSize;
    LPSTR lpBuffer;
    DWORD dwTid;
    DWORD dwErrorFlag;
    DWORD dwErrorCode;
    DWORD dwStatusCode;
} REQUEST_CONTEXT_INT;

typedef struct {
    HINTERNET hSession;
    HINTERNET hConnect;
    LPWSTR lpUrlPath;
    DWORD dwTid;
    DWORD dwErrorFlag;
    DWORD dwErrorCode;
    DWORD dwReqFlag;
    DWORD dwSecFlag;
    DWORD dwReqCount;
    REQUEST_CONTEXT_INT **lpRequest;
    AUTH_TYPE tokenType;
    LPWSTR idToken0;
    LPWSTR idToken1;
    PCCERT_CONTEXT pCertContext;
    HCERTSTORE pfxStore;
} REQUEST_CONTEXT;

REQUEST_CONTEXT * http_connect(LPWSTR url, int timeout_msec);

BOOL send_get_request(REQUEST_CONTEXT *context, LPWSTR urlpath);

BOOL send_post_request(REQUEST_CONTEXT *context, LPWSTR urlpath, LPWSTR post, DWORD len);

void http_close(REQUEST_CONTEXT *context);

void set_basic_auth(REQUEST_CONTEXT *context, LPWSTR username, LPWSTR userpassword);

void set_cert_auth(REQUEST_CONTEXT *context, LPWSTR pkcs12filepath, LPWSTR pkcs12passwd);

void set_idmheader_auth(REQUEST_CONTEXT *context, LPWSTR username, LPWSTR userpassword);

#endif
