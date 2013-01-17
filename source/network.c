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

#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <stdio.h> 
#include "network.h"
#include "log.h"

typedef enum {
    GET = 0,
    POST
} REQUEST_TYPE;

void http_close(REQUEST_CONTEXT *context) {
    DWORD i = 0;
    if (context != NULL) {
        if (context->lpRequest != NULL) {
            for (i = 0; i < context->dwReqCount; i++) {
                REQUEST_CONTEXT_INT *r = context->lpRequest[i];
                if (r != NULL) {
                    if (r->hRequest != NULL) {
                        WinHttpSetStatusCallback(r->hRequest, NULL, 0, (DWORD_PTR) NULL);
                        WinHttpCloseHandle(r->hRequest);
                        r->hRequest = NULL;
                    }
                    if (r->lpBuffer != NULL) {
                        free(r->lpBuffer);
                        r->lpBuffer = NULL;
                    }
                    free(r);
                    r = NULL;
                }
            }
            free(context->lpRequest);
            context->lpRequest = NULL;
        }
        if (context->hConnect != NULL) {
            WinHttpCloseHandle(context->hConnect);
            context->hConnect = NULL;
        }
        if (context->hSession != NULL) {
            WinHttpCloseHandle(context->hSession);
            context->hSession = NULL;
        }
        if (context->lpUrlPath != NULL) {
            free(context->lpUrlPath);
            context->lpUrlPath = NULL;
        }
        if (context->pCertContext != NULL) {
            CertFreeCertificateContext(context->pCertContext);
            context->pCertContext = NULL;
        }
        if (context->pfxStore != NULL) {
            CertCloseStore(context->pfxStore, CERT_CLOSE_STORE_FORCE_FLAG);
            context->pfxStore = NULL;
        }
        free(context);
        context = NULL;
    }
}

static LPVOID query_header(REQUEST_CONTEXT_INT *cpContext, ULONG header) {
    DWORD dwSize = 0;
    LPVOID lpOutBuffer = NULL;
    WinHttpQueryHeaders(cpContext->hRequest,
            header, NULL, (LPVOID) NULL, &dwSize, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        lpOutBuffer = malloc((dwSize + 1) * sizeof (wchar_t));
        if (lpOutBuffer == NULL) return FALSE;
        if (WinHttpQueryHeaders(cpContext->hRequest,
                header, NULL, lpOutBuffer, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
            return lpOutBuffer;
        }
        free(lpOutBuffer);
    }
    return NULL;
}

REQUEST_CONTEXT * http_connect(LPWSTR url, int timeout_msec) {
    WCHAR szHost[256];
    REQUEST_CONTEXT *ctx = NULL;
    URL_COMPONENTS urlComp;
    if (url != NULL && (ctx = (REQUEST_CONTEXT *) malloc(sizeof (REQUEST_CONTEXT))) != NULL) {
        ZeroMemory(ctx, sizeof (REQUEST_CONTEXT));
        ctx->dwTid = GetCurrentThreadId();
        ctx->tokenType = NO_AUTH;
        if (ctx->hSession = WinHttpOpen(L"OpenIDM AD Sync/2.1",
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC)) {
            if (!WinHttpSetTimeouts(ctx->hSession, timeout_msec, timeout_msec, timeout_msec, timeout_msec)) {
                ctx->dwErrorFlag = IDM_SET_TIMEOUT_ERROR;
                ctx->dwErrorCode = GetLastError();
            }
            ZeroMemory(&urlComp, sizeof (urlComp));
            urlComp.dwStructSize = sizeof (urlComp);
            urlComp.lpszHostName = szHost;
            urlComp.dwHostNameLength = sizeof (szHost) / sizeof (szHost[0]);
            urlComp.dwUrlPathLength = -1;
            urlComp.dwSchemeLength = -1;
            urlComp.dwExtraInfoLength = -1;
            if (WinHttpCrackUrl(url, 0, 0, &urlComp)) {
                if ((ctx->hConnect = WinHttpConnect(ctx->hSession, szHost, urlComp.nPort, 0))) {
                    ctx->lpUrlPath = (LPWSTR) malloc((urlComp.dwUrlPathLength + urlComp.dwExtraInfoLength + 1) * sizeof (WCHAR));
                    memcpy(ctx->lpUrlPath, urlComp.lpszUrlPath, (urlComp.dwUrlPathLength + urlComp.dwExtraInfoLength) * sizeof (WCHAR));
                    ctx->lpUrlPath[urlComp.dwUrlPathLength + urlComp.dwExtraInfoLength] = 0;
                    ctx->dwReqFlag = (INTERNET_SCHEME_HTTPS == urlComp.nScheme) ? WINHTTP_FLAG_SECURE : 0;
                    ctx->dwSecFlag = (INTERNET_SCHEME_HTTPS == urlComp.nScheme) ?
                            SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                            | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE : 0;
                    return ctx;
                }
            }
        }
    }
    http_close(ctx);
    return NULL;
}

void set_cert_auth(REQUEST_CONTEXT *context, LPWSTR pkcs12filepath, LPWSTR pkcs12passwd) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hSection = 0;
    LPVOID pFileView = 0;
    CRYPT_DATA_BLOB blob;
    if (context != NULL && context->pCertContext == NULL && context->pfxStore == NULL) {
        context->tokenType = NO_AUTH;
        context->idToken0 = pkcs12filepath;
        context->idToken1 = pkcs12passwd;
        if (context->idToken0 != NULL && (hFile = CreateFile(context->idToken0, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) != INVALID_HANDLE_VALUE) {
            if ((hSection = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0))) {
                if ((pFileView = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0))) {
                    blob.cbData = GetFileSize(hFile, 0);
                    blob.pbData = (BYTE*) pFileView;
                    if (PFXIsPFXBlob(&blob)
                            && (context->pfxStore = PFXImportCertStore(&blob, context->idToken1 != NULL ? context->idToken1 : L"",
                            CRYPT_MACHINE_KEYSET | CRYPT_EXPORTABLE))) {
                        if ((context->pCertContext = CertEnumCertificatesInStore(context->pfxStore, context->pCertContext))) {
                            context->tokenType = CERT_AUTH;
                        } else {
                            context->dwErrorFlag = IDM_CERT_ENUM_ERROR;
                            context->dwErrorCode = GetLastError();
                            CertCloseStore(context->pfxStore, CERT_CLOSE_STORE_FORCE_FLAG);
                            context->pfxStore = NULL;
                        }
                    } else {
                        context->dwErrorFlag = IDM_PFX_OPEN_ERROR;
                        context->dwErrorCode = GetLastError();
                    }
                    UnmapViewOfFile(pFileView);
                } else {
                    context->dwErrorFlag = IDM_MMAP_ERROR;
                    context->dwErrorCode = GetLastError();
                }
                CloseHandle(hSection);
            } else {
                context->dwErrorFlag = IDM_MMAP_CREATE_ERROR;
                context->dwErrorCode = GetLastError();
            }
            CloseHandle(hFile);
        } else {
            context->dwErrorFlag = IDM_FILE_OPEN_ERROR;
            context->dwErrorCode = GetLastError();
        }
    }
}

void set_basic_auth(REQUEST_CONTEXT *context, LPWSTR username, LPWSTR userpassword) {
    if (context != NULL) {
        context->tokenType = BASIC_AUTH;
        context->idToken0 = username;
        context->idToken1 = userpassword;
    }
}

void set_idmheader_auth(REQUEST_CONTEXT *context, LPWSTR username, LPWSTR userpassword) {
    if (context != NULL) {
        context->tokenType = IDM_HEADER_AUTH;
        context->idToken0 = username;
        context->idToken1 = userpassword;
    }
}

static BOOL read_sync_response(REQUEST_CONTEXT_INT *ctx) {
    LPSTR lpBuffer = NULL;
    LPVOID statusCode = NULL;
    DWORD contLen = 0, readCount = 0;
    BOOL readStatus;
    if (WinHttpReceiveResponse(ctx->hRequest, NULL) == TRUE) {
        if ((statusCode = query_header(ctx, WINHTTP_QUERY_STATUS_CODE)) != NULL) {
            ctx->dwStatusCode = wcstol(statusCode, NULL, 10);
            free(statusCode);
        }
        if ((statusCode = query_header(ctx, WINHTTP_QUERY_CONTENT_LENGTH)) != NULL) {
            contLen = wcstol(statusCode, NULL, 10);
            free(statusCode);
        }
        LOG(LOG_DEBUG, L"read_sync_response(): status code: %d, content length: %d", ctx->dwStatusCode, contLen);
        while (WinHttpQueryDataAvailable(ctx->hRequest, &ctx->dwSize)) {
            if (ctx->dwSize) {
                lpBuffer = malloc(ctx->dwSize + 1);
                if (!lpBuffer) return FALSE;
                readStatus = WinHttpReadData(ctx->hRequest, lpBuffer, ctx->dwSize, &readCount);
                if (readStatus == FALSE) {
                    free(lpBuffer);
                    ctx->dwErrorCode = GetLastError();
                    return FALSE;
                }
                ctx->lpBuffer = realloc(ctx->lpBuffer, ctx->dwTotalSize + readCount + 1);
                if (!ctx->lpBuffer) {
                    free(lpBuffer);
                    return FALSE;
                }
                memcpy((ctx->lpBuffer) + ctx->dwTotalSize, lpBuffer, readCount);
                ctx->dwTotalSize += readCount;
                free(lpBuffer);
            } else break;
        }
        if (ctx->lpBuffer != NULL) {
            ctx->lpBuffer[ctx->dwTotalSize] = 0;
            return TRUE;
        } else {
            ctx->dwTotalSize = 0;
            if (contLen == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOL send_sync_request(REQUEST_CONTEXT *context, REQUEST_TYPE type, LPWSTR urlpath, LPWSTR post, DWORD len) {
    REQUEST_CONTEXT_INT *ctxi = NULL;
    LPWSTR contentType = L"Content-Type: application/json; charset=utf-8\r\n";
    if (context != NULL && (ctxi = (REQUEST_CONTEXT_INT *) malloc(sizeof (REQUEST_CONTEXT_INT))) != NULL) {
        ZeroMemory(ctxi, sizeof (REQUEST_CONTEXT_INT));
        ctxi->id = context->dwReqCount;
        context->lpRequest = (REQUEST_CONTEXT_INT **) realloc(context->lpRequest, (context->dwReqCount + 1) * sizeof (REQUEST_CONTEXT_INT *));
        context->lpRequest[context->dwReqCount] = ctxi;
        context->dwReqCount++;
        ctxi->hRequest = WinHttpOpenRequest(context->hConnect, type == GET ? L"GET" : L"POST",
                (urlpath == NULL ? context->lpUrlPath : urlpath),
                NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, context->dwReqFlag);
        if (ctxi->hRequest != NULL) {
            WinHttpAddRequestHeaders(ctxi->hRequest, L"X-Requested-With: ADPlugin", (DWORD) - 1,
                    WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
            switch (context->tokenType) {
                case BASIC_AUTH:
                    WinHttpSetCredentials(ctxi->hRequest, WINHTTP_AUTH_TARGET_SERVER, WINHTTP_AUTH_SCHEME_BASIC,
                            context->idToken0 != NULL ? context->idToken0 : L"",
                            context->idToken1 != NULL ? context->idToken1 : L"",
                            NULL);
                    break;
                case CERT_AUTH:
                    WinHttpSetOption(ctxi->hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                            (LPVOID) context->pCertContext, sizeof (CERT_CONTEXT));
                    break;
                case IDM_HEADER_AUTH:
                {
                    wchar_t *uhdr = NULL, *phdr = NULL;
                    if (idm_printf(&uhdr, L"X-OpenIDM-Username: %s", context->idToken0 != NULL ? context->idToken0 : L"")) {
                        WinHttpAddRequestHeaders(ctxi->hRequest, uhdr, (DWORD) - 1,
                                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
                    } else {
                        ctxi->dwErrorFlag = IDM_MEMORY_ERROR;
                        ctxi->dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
                    }
                    if (idm_printf(&phdr, L"X-OpenIDM-Password: %s", context->idToken1 != NULL ? context->idToken1 : L"")) {
                        WinHttpAddRequestHeaders(ctxi->hRequest, phdr, (DWORD) - 1,
                                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
                    } else {
                        ctxi->dwErrorFlag = IDM_MEMORY_ERROR;
                        ctxi->dwErrorCode = ERROR_NOT_ENOUGH_MEMORY;
                    }
                    if (uhdr) free(uhdr);
                    if (phdr) free(phdr);
                }
                    break;
            }
            switch (type) {
                case GET:
                    if (context->dwSecFlag > 0)
                        WinHttpSetOption(ctxi->hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &(context->dwSecFlag), sizeof (DWORD));
                    if (WinHttpSendRequest(ctxi->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, (DWORD_PTR) 0)) {
                        return read_sync_response(ctxi);
                    } else {
                        ctxi->dwErrorFlag = IDM_NET_REQUEST_SEND_ERROR;
                        ctxi->dwErrorCode = GetLastError();
                    }
                    break;
                case POST:
                    if (context->dwSecFlag > 0)
                        WinHttpSetOption(ctxi->hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &(context->dwSecFlag), sizeof (DWORD));
                    if (WinHttpSendRequest(ctxi->hRequest, contentType, -1,
                            (LPVOID) post, len, len, (DWORD_PTR) 0)) {
                        return read_sync_response(ctxi);
                    } else {
                        ctxi->dwErrorFlag = IDM_NET_REQUEST_SEND_ERROR;
                        ctxi->dwErrorCode = GetLastError();
                    }
                    break;
            }
            context->dwErrorFlag = ctxi->dwErrorFlag;
            context->dwErrorCode = ctxi->dwErrorCode;
        } else {
            context->dwErrorFlag = IDM_NET_REQUEST_OPEN_ERROR;
            context->dwErrorCode = GetLastError();
        }
    } else {
        context->dwErrorFlag = IDM_MEMORY_ERROR;
        context->dwErrorCode = GetLastError();
    }
    return FALSE;
}

BOOL send_get_request(REQUEST_CONTEXT *context, LPWSTR urlpath) {
    return send_sync_request(context, GET, urlpath, NULL, 0);
}

BOOL send_post_request(REQUEST_CONTEXT *context, LPWSTR urlpath, LPWSTR post, DWORD len) {
    if (log_level == LOG_DEBUG) {
        LOG(LOG_DEBUG, L"send_post_request(): request uri:\n%s",
                (context == NULL || context->lpUrlPath == NULL ? L"(null)" : context->lpUrlPath));
        LOG(LOG_DEBUG, L"send_post_request(): post size: %d, data:\n%s", len, (post == NULL ? L"(null)" : post));
    }
    return send_sync_request(context, POST, urlpath, post, len);
}
